/* $NetBSD: if_pppoe.c,v 1.187 2026/03/05 09:59:17 riastradh Exp $ */

/*-
 * Copyright (c) 2002, 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Martin Husemann <martin@NetBSD.org>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Discovery FSM seam of the split if_pppoe(4) module.
 *
 * Everything that speaks 0x8863 on the wire lives here: building and sending
 * PADI/PADR/PADT, the retransmit timeout, and pppoe_disc_input(), the receive
 * half of the discovery state machine.  The RX hook that hands this seam its
 * frames, the softc-list/session-table family and the per-vnet counters stay
 * in if_pppoe.c; the cross-file surface is if_pppoe_var.h.
 *
 * Moved verbatim from if_pppoe.c (same NetBSD lineage); the only deltas are
 * the dropped `static` on symbols the core calls and the include list.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/counter.h>
#include <sys/endian.h>
#include <sys/epoch.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/taskqueue.h>
#include <sys/time.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <net/vnet.h>
#include <net/if_pppoe.h>
#include <net/if_pppoe_var.h>

/*
 * Discovery output.
 *
 * A discovery frame is built into a fresh mbuf with ETHER_HDR_LEN of leading
 * space reserved, then handed to pppoe_output_frame(), which is the single
 * place any of them reaches the wire.  It goes out via ether_output_frame()
 * so the parent's VLAN PCP tagging and the outbound Ethernet pfil hooks both
 * apply (spec section 7; a deliberate decision).
 *
 * Verified against the 25.7 source before use:
 * ether_output_frame(struct ifnet *, struct mbuf *) is declared in
 * sys/net/ethernet.h:448 and defined at sys/net/if_ethersubr.c:474; its
 * comment states it assumes the 14-byte Ethernet header is present and
 * contiguous in the first mbuf, it does not look at m_pkthdr.rcvif, and it
 * ends in (*ifp->if_transmit)(ifp, m) at :516.  It reads V_link_pfil_head
 * (:479), so every caller must have curvnet set -- see pppoe_timeout().
 */
static struct mbuf *
pppoe_get_mbuf(size_t len)
{
	struct mbuf *m;

	/*
	 * Bound the request explicitly rather than leaning on the callers.
	 * Until RFC 4638 every discovery frame was short by construction
	 * (names <= PPPOE_MAX_NAMELEN, cookie/relay <= 256), but the largest
	 * buffer this can hand back is one cluster, so anything that does not
	 * fit has to be refused here instead of overrunning it below.
	 */
	if (len + ETHER_HDR_LEN > MCLBYTES)
		return (NULL);
	m = m_gethdr(M_NOWAIT, MT_DATA);
	if (m == NULL) {
		counter_u64_add(V_pppoe_stats.nomem, 1);
		return (NULL);
	}
	if (len + ETHER_HDR_LEN > MHLEN) {
		if (!(MCLGET(m, M_NOWAIT))) {
			m_freem(m);
			counter_u64_add(V_pppoe_stats.nomem, 1);
			return (NULL);
		}
	}
	m->m_data += ETHER_HDR_LEN;
	m->m_len = len;
	m->m_pkthdr.len = len;
	return (m);
}

/*
 * Prepend the Ethernet header and hand the frame to the parent.
 * Caller must NOT hold sc_mtx: ether_output_frame() calls into the parent's
 * if_transmit (spec section 9: no lock held across transmit).
 */
static int
pppoe_output_frame1(if_t parent, const struct ether_addr *dst,
    uint16_t etype, struct mbuf *m, bool departing)
{
	struct ether_header *eh;
	int error;

	/* Dropped, not queued: discovery retries from sc_timeout. */
	if (!pppoe_parent_can_tx(parent, departing)) {
		m_freem(m);
		counter_u64_add(V_pppoe_stats.tx_parent_down, 1);
		counter_u64_add(V_pppoe_stats.tx_errors, 1);
		return (ENETDOWN);
	}
	M_PREPEND(m, ETHER_HDR_LEN, M_NOWAIT);
	if (m == NULL) {
		counter_u64_add(V_pppoe_stats.nomem, 1);
		counter_u64_add(V_pppoe_stats.tx_errors, 1);
		return (ENOBUFS);
	}
	eh = mtod(m, struct ether_header *);
	memcpy(eh->ether_dhost, dst, ETHER_ADDR_LEN);
	/*
	 * Not if_getlladdr(): a departing parent can have lost its link
	 * address by the time a PADT for it gets here (pppoe_lladdr_copy()).
	 */
	if (!pppoe_lladdr_copy(parent, eh->ether_shost)) {
		m_freem(m);
		counter_u64_add(V_pppoe_stats.tx_errors, 1);
		return (ENXIO);
	}
	eh->ether_type = htons(etype);
	/*
	 * tx_frames and tx_errors are disjoint: count the frame only once
	 * ether_output_frame() has taken it.  Bumping tx_frames first -- as
	 * this did until Task 11 -- makes a parent that rejects every frame
	 * report an unbroken run of successes.  ether_output_frame() returns
	 * EACCES for a PFIL_DROPPED frame and whatever the parent's
	 * if_transmit returns otherwise (sys/net/if_ethersubr.c:479-484,
	 * :516); in every non-zero case the mbuf has already been freed by
	 * the layer that refused it.
	 */
	error = ether_output_frame(parent, m);
	if (error != 0) {
		counter_u64_add(V_pppoe_stats.tx_errors, 1);
		return (error);
	}
	counter_u64_add(V_pppoe_stats.tx_frames, 1);
	return (0);
}

int
pppoe_output_frame(if_t parent, const struct ether_addr *dst, uint16_t etype,
    struct mbuf *m)
{

	return (pppoe_output_frame1(parent, dst, etype, m, false));
}

void
pppoe_add_16(uint8_t **p, uint16_t v)
{

	*(*p)++ = v >> 8;
	*(*p)++ = v & 0xff;
}

static void
pppoe_add_tag(uint8_t **p, uint16_t tag, const void *val, uint16_t len)
{

	pppoe_add_16(p, tag);
	pppoe_add_16(p, len);
	if (len != 0)
		memcpy(*p, val, len);
	*p += len;
}

/*
 * pppoe_send_padi() and pppoe_send_padr() are called with sc_mtx held and
 * return with it held, but they DROP it around the transmit.  Callers must
 * therefore re-validate sc_detaching and sc_state before touching the softc
 * or re-arming sc_timeout: a PADO/PADS, an ioctl, or pppoe_clone_destroy()
 * can all have run while the lock was down.
 */
int
pppoe_send_padi(struct pppoe_softc *sc)
{
	if_t parent;
	struct mbuf *m;
	struct epoch_tracker et;
	uint8_t *p;
	size_t svc_len, ac_len, len;
	uint64_t hu;
	struct ether_addr bcast;
	int error;

	PPPOE_SC_ASSERT(sc);
	parent = sc->sc_parent;
	if (parent == NULL)
		return (ENXIO);

	/*
	 * A PADI opens a fresh negotiation, so re-offer what the administrator
	 * asked for rather than whatever the last AC left behind.  Both the
	 * PADO clamp and the PADS write-back overwrite sc_max_payload, and
	 * nothing else restores it: without this, one session clamped to 1492
	 * -- or one whose PADS dropped the tag -- would switch RFC 4638 off
	 * for the life of the interface, and a single AC that granted 1400
	 * would hold every later session at 1400.  RFC 4638 negotiation is per
	 * session, not per interface lifetime.  Seeding here rather than in
	 * pppoe_connect() also covers the pppoe_timeout() retransmit path,
	 * which re-enters this function without passing through connect.
	 */
	sc->sc_max_payload = sc->sc_max_payload_req;

	svc_len = (sc->sc_service_name != NULL) ?
	    strlen(sc->sc_service_name) : 0;
	ac_len = (sc->sc_ac_name != NULL) ? strlen(sc->sc_ac_name) : 0;

	len = PPPOE_HEADERLEN;
	len += 4 + svc_len;			/* Service-Name */
	len += 4 + sizeof(hu);			/* Host-Uniq */
	if (ac_len != 0)
		len += 4 + ac_len;		/* AC-Name */
	if (sc->sc_max_payload != 0)
		len += 4 + 2;			/* PPP-Max-Payload, Task 9 */

	m = pppoe_get_mbuf(len);
	if (m == NULL)
		return (ENOBUFS);
	p = mtod(m, uint8_t *);
	*p++ = PPPOE_VERTYPE;
	*p++ = PPPOE_CODE_PADI;
	pppoe_add_16(&p, 0);				/* session id */
	pppoe_add_16(&p, len - PPPOE_HEADERLEN);	/* payload length */
	pppoe_add_tag(&p, PPPOE_TAG_SNAME, sc->sc_service_name, svc_len);
	hu = htobe64(sc->sc_hunique);
	pppoe_add_tag(&p, PPPOE_TAG_HUNIQUE, &hu, sizeof(hu));
	if (ac_len != 0)
		pppoe_add_tag(&p, PPPOE_TAG_ACNAME, sc->sc_ac_name, ac_len);
	if (sc->sc_max_payload != 0) {
		uint8_t mp[2];

		mp[0] = sc->sc_max_payload >> 8;
		mp[1] = sc->sc_max_payload & 0xff;
		pppoe_add_tag(&p, PPPOE_TAG_MAX_PAYLOAD, mp, sizeof(mp));
	}

	memset(&bcast, 0xff, sizeof(bcast));
	/*
	 * The parent's last if_rele() frees it from a NET_EPOCH_CALL()
	 * (sys/net/if.c:713-716), so the pointer is only guaranteed for the
	 * duration of a net-epoch section.  pppoe_disc_input() is already in
	 * one; pppoe_timeout() runs in softclock with no epoch at all, so
	 * bracket the transmit here -- nesting on the RX path is harmless.
	 *
	 * Enter the section BEFORE dropping sc_mtx, not after.  epoch_call()
	 * (sys/kern/subr_epoch.c:778, ck_epoch_call() at :797) only defers a
	 * callback past sections that were already active when it was queued,
	 * and pppoe_ioctl_setparms() cannot reach its if_rele(old) without
	 * first taking sc_mtx -- which we still hold here.  Entering under the
	 * mutex is safe: _epoch_enter_preempt() is critical_enter()/
	 * sched_pin()/critical_exit() plus THREAD_NO_SLEEPING(), and the
	 * mtx_unlock() below does not sleep.
	 */
	NET_EPOCH_ENTER(et);
	PPPOE_SC_UNLOCK(sc);
	error = pppoe_output_frame(parent, &bcast, ETHERTYPE_PPPOEDISC, m);
	NET_EPOCH_EXIT(et);
	PPPOE_SC_LOCK(sc);
	return (error);
}

int
pppoe_send_padr(struct pppoe_softc *sc)
{
	if_t parent;
	struct ether_addr dest;
	struct mbuf *m;
	struct epoch_tracker et;
	uint8_t *p;
	size_t svc_len, len;
	uint64_t hu;

	PPPOE_SC_ASSERT(sc);
	parent = sc->sc_parent;
	if (parent == NULL)
		return (ENXIO);

	svc_len = (sc->sc_service_name != NULL) ?
	    strlen(sc->sc_service_name) : 0;
	len = PPPOE_HEADERLEN;
	len += 4 + svc_len;
	len += 4 + sizeof(hu);
	if (sc->sc_ac_cookie_len != 0)
		len += 4 + sc->sc_ac_cookie_len;
	if (sc->sc_relay_sid_len != 0)
		len += 4 + sc->sc_relay_sid_len;
	if (sc->sc_max_payload != 0)
		len += 4 + 2;

	m = pppoe_get_mbuf(len);
	if (m == NULL)
		return (ENOBUFS);
	p = mtod(m, uint8_t *);
	*p++ = PPPOE_VERTYPE;
	*p++ = PPPOE_CODE_PADR;
	pppoe_add_16(&p, 0);
	pppoe_add_16(&p, len - PPPOE_HEADERLEN);
	pppoe_add_tag(&p, PPPOE_TAG_SNAME, sc->sc_service_name, svc_len);
	hu = htobe64(sc->sc_hunique);
	pppoe_add_tag(&p, PPPOE_TAG_HUNIQUE, &hu, sizeof(hu));
	if (sc->sc_ac_cookie_len != 0)
		pppoe_add_tag(&p, PPPOE_TAG_ACCOOKIE, sc->sc_ac_cookie,
		    sc->sc_ac_cookie_len);
	if (sc->sc_relay_sid_len != 0)
		pppoe_add_tag(&p, PPPOE_TAG_RELAYSID, sc->sc_relay_sid,
		    sc->sc_relay_sid_len);
	if (sc->sc_max_payload != 0) {
		uint8_t mp[2];

		mp[0] = sc->sc_max_payload >> 8;
		mp[1] = sc->sc_max_payload & 0xff;
		pppoe_add_tag(&p, PPPOE_TAG_MAX_PAYLOAD, mp, sizeof(mp));
	}

	dest = sc->sc_dest;
	/*
	 * Net epoch around the transmit, entered before the unlock so a
	 * concurrent setparms release cannot precede it: see pppoe_send_padi().
	 */
	NET_EPOCH_ENTER(et);
	PPPOE_SC_UNLOCK(sc);
	(void)pppoe_output_frame(parent, &dest, ETHERTYPE_PPPOEDISC, m);
	NET_EPOCH_EXIT(et);
	PPPOE_SC_LOCK(sc);
	return (0);
}

/*
 * Unlike pppoe_send_padi/padr this takes no softc and asserts no lock: the
 * parent, session id and peer are passed explicitly so a PADT can also be sent
 * for a session that is not (or is no longer) in a softc -- an unknown
 * incoming session (spec section 6.3) and the Task 13 unload path.  Callers
 * must hold neither sc_mtx (ether_output_frame() reaches the parent's
 * if_transmit) nor a stale parent reference (be inside the net epoch), and
 * must have curvnet set: V_pppoe_stats and ether_output_frame()'s
 * V_link_pfil_head are both per-vnet.
 */
static int
pppoe_send_padt1(if_t parent, uint16_t session, const struct ether_addr *peer,
    bool departing)
{
	struct mbuf *m;
	uint8_t *p;
	int error;

	if (parent == NULL || session == 0)
		return (EINVAL);
	m = pppoe_get_mbuf(PPPOE_HEADERLEN);
	if (m == NULL)
		return (ENOBUFS);
	p = mtod(m, uint8_t *);
	*p++ = PPPOE_VERTYPE;
	*p++ = PPPOE_CODE_PADT;
	pppoe_add_16(&p, session);
	pppoe_add_16(&p, 0);			/* no tags */
	error = pppoe_output_frame1(parent, peer, ETHERTYPE_PPPOEDISC, m,
	    departing);
	/* Counted once the parent took it, like tx_frames. */
	if (error == 0)
		counter_u64_add(V_pppoe_stats.padt_tx, 1);
	return (error);
}

int
pppoe_send_padt(if_t parent, uint16_t session, const struct ether_addr *peer)
{

	return (pppoe_send_padt1(parent, session, peer, false));
}

/* For pppoe_parent_departed() only: the parent has been if_down()'d. */
int
pppoe_send_padt_departing(if_t parent, uint16_t session,
    const struct ether_addr *peer)
{

	return (pppoe_send_padt1(parent, session, peer, true));
}

/*
 * Back off 5s, 10s, 20s, 40s, then settle on one PADI a minute, forever:
 * NetBSD stops retrying unless the link carries LINK1, but a router's WAN has
 * nothing else to do and an AC that comes back must find us still dialling.
 */
static int
pppoe_padi_backoff(const struct pppoe_softc *sc)
{

	if (sc->sc_padi_retried >= PPPOE_DISC_MAXPADI)
		return (PPPOE_SLOW_RETRY);
	return (PPPOE_DISC_TIMEOUT * (1 << MIN(sc->sc_padi_retried, 3)));
}

/*
 * One PADI retry: count it only if it reached the wire.  A PADI dropped for
 * a parent that is down or not running (pppoe_output_frame1()'s ENETDOWN,
 * counted in tx_parent_down) restarts the schedule instead, so the parent is
 * polled every PPPOE_DISC_TIMEOUT while it is down and the first PADI after
 * it returns goes out within 5s rather than up to PPPOE_SLOW_RETRY late.
 * No event hook needed: IFF_DRV_RUNNING changes post none.
 */
static void
pppoe_padi_retry(struct pppoe_softc *sc)
{

	sc->sc_padi_retried++;
	if (pppoe_send_padi(sc) == ENETDOWN)
		sc->sc_padi_retried = 0;
}

void
pppoe_timeout(void *arg)
{
	struct pppoe_softc *sc = arg;

	/*
	 * curvnet is NULL in softclock context on this VIMAGE kernel
	 * (an earlier spike panicked on exactly this), and everything below
	 * reaches V_ state: pppoe_output_frame() bumps V_pppoe_stats and
	 * ether_output_frame() dereferences V_link_pfil_head
	 * (sys/net/if_ethersubr.c:479).  Set it for the whole body.
	 */
	CURVNET_SET(if_getvnet(sc->sc_ifp));
	PPPOE_SC_ASSERT(sc);
	if (sc->sc_detaching)
		goto out;
	switch (sc->sc_state) {
	case PPPOE_STATE_PADI_SENT:
		pppoe_padi_retry(sc);
		/* sc_mtx was dropped around the transmit -- re-validate. */
		if (!sc->sc_detaching &&
		    sc->sc_state == PPPOE_STATE_PADI_SENT)
			callout_reset(&sc->sc_timeout, pppoe_padi_backoff(sc),
			    pppoe_timeout, sc);
		break;
	case PPPOE_STATE_PADR_SENT:
		sc->sc_padr_retried++;
		if (sc->sc_padr_retried >= PPPOE_DISC_MAXPADR) {
			/*
			 * Back to PADI, keeping the backoff: an AC that PADOs
			 * but never PADSes would otherwise get a PADI every 5s.
			 */
			sc->sc_state = PPPOE_STATE_PADI_SENT;
			memset(&sc->sc_dest, 0xff, sizeof(sc->sc_dest));
			pppoe_padi_retry(sc);
		} else {
			(void)pppoe_send_padr(sc);
		}
		/* Same here: the send above dropped and re-took sc_mtx. */
		if (sc->sc_detaching)
			break;
		if (sc->sc_state == PPPOE_STATE_PADI_SENT)
			callout_reset(&sc->sc_timeout, pppoe_padi_backoff(sc),
			    pppoe_timeout, sc);
		else if (sc->sc_state == PPPOE_STATE_PADR_SENT)
			callout_reset(&sc->sc_timeout, PPPOE_DISC_TIMEOUT,
			    pppoe_timeout, sc);
		break;
	default:
		break;
	}
out:
	CURVNET_RESTORE();
}

/*
 * Does the tag area, already bounds-checked by pppoe_disc_input()'s walk,
 * carry a tag of this type whose value is exactly want?
 */
static bool
pppoe_tag_has(const uint8_t *tags, size_t taglen, uint16_t type,
    const char *want, size_t wantlen)
{
	size_t off;
	uint16_t tag, tlen;

	for (off = 0; off + 4 <= taglen; off += 4 + tlen) {
		tag = (tags[off] << 8) | tags[off + 1];
		tlen = (tags[off + 2] << 8) | tags[off + 3];
		if (tag == PPPOE_TAG_EOL || off + 4 + tlen > taglen)
			break;
		if (tag == type && tlen == wantlen &&
		    memcmp(&tags[off + 4], want, wantlen) == 0)
			return (true);
	}
	return (false);
}

/*
 * A configured AC-Name or Service-Name picks the AC: a PADO that does not
 * offer it is ignored.  An AC may list several Service-Names; one will do.
 */
static bool
pppoe_pado_wanted(struct pppoe_softc *sc, const uint8_t *tags,
    size_t taglen)
{
	size_t len;

	PPPOE_SC_ASSERT(sc);
	len = sc->sc_ac_name != NULL ? strlen(sc->sc_ac_name) : 0;
	if (len != 0 && !pppoe_tag_has(tags, taglen, PPPOE_TAG_ACNAME,
	    sc->sc_ac_name, len))
		return (false);
	len = sc->sc_service_name != NULL ? strlen(sc->sc_service_name) : 0;
	if (len != 0 && !pppoe_tag_has(tags, taglen, PPPOE_TAG_SNAME,
	    sc->sc_service_name, len))
		return (false);
	return (true);
}

/*
 * Log an AC-triggered discovery refusal, at most once a second per softc,
 * with the error tag's text: printable ASCII only, so an AC cannot forge
 * log lines.
 */
static void
pppoe_disc_log(struct pppoe_softc *sc, const char *what, const uint8_t *text,
    size_t len)
{
	char buf[65];
	size_t i;

	PPPOE_SC_ASSERT(sc);
	if (!ppsratecheck(&sc->sc_disclog_last, &sc->sc_disclog_pps, 1))
		return;
	len = MIN(len, sizeof(buf) - 1);
	for (i = 0; i < len; i++)
		buf[i] = (text[i] >= 0x20 && text[i] < 0x7f) ? text[i] : '?';
	buf[len] = '\0';
	log(LOG_INFO, "%s: %s%s%s\n", if_name(sc->sc_ifp), what,
	    len != 0 ? ": " : "", buf);
}

/*
 * The discovery FSM's receive half: PADO in PADI_SENT -> send PADR, PADS in
 * PADR_SENT -> session up.  Runs in the RX hook, inside the net epoch, with
 * the Ethernet header still on the mbuf.
 *
 * Tag parsing is a bounded walk.  The advertised PPPoE payload length is
 * bounded by both the frame in hand and ETHERMTU first, the tag area is then
 * m_copydata()'d into a private buffer, and every TLV length is validated
 * against the remaining tag area before the value is touched, so a malformed
 * PADO/PADS from the wire can never read past the frame.
 *
 * The tag area is copied, not m_pullup()'d: m_pullup() (sys/kern/uipc_mbuf.c)
 * takes its `else` arm whenever the first mbuf carries an external cluster,
 * and that arm is `if (len > MHLEN) goto bad;` -- with MHLEN ~184 on amd64
 * (MSIZE 256, sys/sys/param.h:195) that would silently drop every chained
 * discovery frame whose payload runs past ~164 bytes.
 *
 * Only frames that name a softc of ours on this parent are consumed: a
 * Host-Uniq match, or a PADT matching one of our live sessions (parent,
 * session id, peer MAC).  Everything else -- another client's PADI/PADO/
 * PADS, a PADT for someone else's session, a frame too malformed to
 * attribute -- is returned FOREIGN with the mbuf intact so the hook can
 * PFIL_PASS it on to ether_demux() and, past it, ng_ether's orphans hook
 * (a same-NIC mpd5).  The frame-level counters still count it.
 */
enum pppoe_disc_verdict
pppoe_disc_input(if_t ifp, struct mbuf **mp)
{
	struct mbuf *m = *mp;
	struct pppoe_softc *sc = NULL;
	struct pppoe_tx_snap *ts;
	const struct ether_header *eh;
	const struct pppoehdr *ph;
	struct ether_addr peer;
	uint8_t *buf = NULL;
	const uint8_t *tags, *ac_cookie = NULL, *relay = NULL, *hunique = NULL;
	const uint8_t *err_text = NULL;
	size_t taglen, off, ac_cookie_len = 0, relay_len = 0, hunique_len = 0;
	size_t err_len = 0;
	int avail;
	uint16_t plen, code, session, tag, tlen, max_payload = 0;
	bool error_tag = false, ours = false;

	NET_EPOCH_ASSERT();

	if (m->m_pkthdr.len < ETHER_HDR_LEN + (int)PPPOE_HEADERLEN)
		goto malformed;
	if (m->m_len < ETHER_HDR_LEN + (int)PPPOE_HEADERLEN) {
		/* m_pullup() frees the chain on failure. */
		m = m_pullup(m, ETHER_HDR_LEN + PPPOE_HEADERLEN);
		*mp = m;
		if (m == NULL) {
			counter_u64_add(V_pppoe_stats.nomem, 1);
			return (PPPOE_DISC_FREED);
		}
	}
	eh = mtod(m, const struct ether_header *);
	memcpy(&peer, eh->ether_shost, ETHER_ADDR_LEN);
	ph = (const struct pppoehdr *)(mtod(m, const uint8_t *) +
	    ETHER_HDR_LEN);
	if (ph->vertype != PPPOE_VERTYPE)
		goto malformed;
	code = ph->code;
	session = ntohs(ph->session);
	plen = ntohs(ph->plen);
	/*
	 * Bound the advertised payload length by the frame actually in hand
	 * and by the largest a PPPoE payload can legitimately be on Ethernet,
	 * so the m_copydata() below can never walk off the chain (m_copydata()
	 * has no return value -- sys/sys/mbuf.h:829 -- and only KASSERTs the
	 * overrun, which this kernel has no INVARIANTS to catch).
	 */
	avail = m->m_pkthdr.len - ETHER_HDR_LEN - (int)PPPOE_HEADERLEN;
	if (plen > avail || plen > ETHERMTU - (int)PPPOE_HEADERLEN)
		goto malformed;
	if (plen != 0) {
		/*
		 * M_NOWAIT: this is the RX hook, under the net epoch, where
		 * nothing may sleep.  Heap, not stack: plen runs to 1494 and
		 * this frame arrives on an already deep ether_demux() stack.
		 */
		buf = malloc(plen, M_PPPOE, M_NOWAIT);
		if (buf == NULL) {
			/* Cannot attribute it without the tags: pass it on. */
			counter_u64_add(V_pppoe_stats.nomem, 1);
			goto foreign;
		}
		m_copydata(m, ETHER_HDR_LEN + PPPOE_HEADERLEN, plen,
		    (caddr_t)buf);
	}
	tags = buf;
	taglen = plen;

	for (off = 0; off + 4 <= taglen; off += 4 + tlen) {
		tag = (tags[off] << 8) | tags[off + 1];
		tlen = (tags[off + 2] << 8) | tags[off + 3];
		if (off + 4 + tlen > taglen)
			goto malformed;		/* truncated tag */
		switch (tag) {
		case PPPOE_TAG_EOL:
			off = taglen;
			break;
		case PPPOE_TAG_HUNIQUE:
			hunique = &tags[off + 4];
			hunique_len = tlen;
			break;
		case PPPOE_TAG_ACCOOKIE:
			ac_cookie = &tags[off + 4];
			ac_cookie_len = tlen;
			break;
		case PPPOE_TAG_RELAYSID:
			relay = &tags[off + 4];
			relay_len = tlen;
			break;
		case PPPOE_TAG_MAX_PAYLOAD:
			if (tlen == 2)
				max_payload = (tags[off + 4] << 8) |
				    tags[off + 5];
			break;
		case PPPOE_TAG_SNAME_ERR:
		case PPPOE_TAG_ACSYS_ERR:
		case PPPOE_TAG_GENERIC_ERR:
			if (!error_tag) {
				err_text = &tags[off + 4];
				err_len = tlen;
			}
			error_tag = true;
			break;
		default:
			break;
		}
	}

	/*
	 * Frame-level accounting: once per well-formed frame, never per tag,
	 * and before the softc lookup, so these answer "what arrived on the
	 * segment" like the rest of the net.pppoe.* family rather than "what we
	 * acted on".  A frame naming no softc of ours is exactly the one the
	 * operator needs -- an AC answering with errors, or PADTing a session
	 * we had already torn down.
	 */
	if (error_tag)
		counter_u64_add(V_pppoe_stats.disc_err_tag, 1);
	if (code == PPPOE_CODE_PADT)
		counter_u64_add(V_pppoe_stats.padt_rx, 1);

	if (hunique != NULL)
		sc = pppoe_find_by_hunique(hunique, hunique_len);
	if (sc == NULL && code == PPPOE_CODE_PADT)
		sc = pppoe_find_by_session(ifp, session, &peer);
	if (sc == NULL)
		goto foreign;

	PPPOE_SC_LOCK(sc);
	/*
	 * sc_parent and sc_detaching are only stable under sc_mtx, so both
	 * checks belong here rather than on the lock-free lookup path above.
	 */
	if (sc->sc_detaching || sc->sc_parent != ifp) {
		PPPOE_SC_UNLOCK(sc);
		goto foreign;
	}
	ours = true;
	switch (code) {
	case PPPOE_CODE_PADO:
		if (sc->sc_state != PPPOE_STATE_PADI_SENT)
			break;			/* ignore extra PADOs */
		if (error_tag) {
			pppoe_disc_log(sc, "PADO carried an error tag",
			    err_text, err_len);
			break;
		}
		if (!pppoe_pado_wanted(sc, tags, taglen))
			break;
		sc->sc_dest = peer;
		free(sc->sc_ac_cookie, M_PPPOE);
		sc->sc_ac_cookie = NULL;
		sc->sc_ac_cookie_len = 0;
		if (ac_cookie_len != 0 && ac_cookie_len <= 256) {
			sc->sc_ac_cookie = malloc(ac_cookie_len, M_PPPOE,
			    M_NOWAIT);
			if (sc->sc_ac_cookie != NULL) {
				memcpy(sc->sc_ac_cookie, ac_cookie,
				    ac_cookie_len);
				sc->sc_ac_cookie_len = ac_cookie_len;
			} else
				counter_u64_add(V_pppoe_stats.nomem, 1);
		}
		free(sc->sc_relay_sid, M_PPPOE);
		sc->sc_relay_sid = NULL;
		sc->sc_relay_sid_len = 0;
		if (relay_len != 0 && relay_len <= 256) {
			sc->sc_relay_sid = malloc(relay_len, M_PPPOE,
			    M_NOWAIT);
			if (sc->sc_relay_sid != NULL) {
				memcpy(sc->sc_relay_sid, relay, relay_len);
				sc->sc_relay_sid_len = relay_len;
			} else
				counter_u64_add(V_pppoe_stats.nomem, 1);
		}
		if (max_payload != 0 && sc->sc_max_payload != 0)
			sc->sc_max_payload = MIN(sc->sc_max_payload,
			    max_payload);
		sc->sc_state = PPPOE_STATE_PADR_SENT;
		sc->sc_padr_retried = 0;
		(void)pppoe_send_padr(sc);
		/*
		 * pppoe_send_padr() dropped sc_mtx around the transmit, so
		 * re-validate before re-arming: a PADS may already have taken
		 * the FSM to SESSION, or clone_destroy may have claimed the
		 * softc, while we were unlocked.
		 */
		if (!sc->sc_detaching &&
		    sc->sc_state == PPPOE_STATE_PADR_SENT)
			callout_reset(&sc->sc_timeout, PPPOE_DISC_TIMEOUT,
			    pppoe_timeout, sc);
		break;
	case PPPOE_CODE_PADS:
		if (sc->sc_state != PPPOE_STATE_PADR_SENT)
			break;
		/* Only the AC whose PADO we answered may grant the session. */
		if (memcmp(&sc->sc_dest, &peer, sizeof(sc->sc_dest)) != 0)
			break;
		/* RFC 2516 section 4: 0xffff is reserved, 0 is no session. */
		if (error_tag || session == 0 || session == 0xffff) {
			pppoe_disc_log(sc, "PADS refused the session",
			    err_text, err_len);
			break;
		}
		/*
		 * The transmit snapshot (T2), allocated before anything is
		 * committed: on failure the PADR retransmit timer is still
		 * armed, and the next PADS gets another try.  Cache-line
		 * aligned: the struct is __aligned(CACHE_LINE_SIZE), and
		 * plain malloc(9) promises only max_align_t.
		 */
		ts = malloc_aligned(sizeof(*ts), CACHE_LINE_SIZE, M_PPPOE,
		    M_NOWAIT | M_ZERO);
		if (ts == NULL) {
			counter_u64_add(V_pppoe_stats.nomem, 1);
			log(LOG_WARNING, "%s: no memory for the session, "
			    "PADS ignored\n", if_name(sc->sc_ifp));
			break;
		}
		callout_stop(&sc->sc_timeout);
		sc->sc_session = session;
		sc->sc_state = PPPOE_STATE_SESSION;
		/*
		 * The AC reissued the id we last closed: it is live again, not
		 * stale, and its first frames can reach the RX hook before
		 * pppoe_session_task() publishes it (term_unknown must not
		 * PADT them).  See pppoe_stale_session_is_ours().
		 */
		if (sc->sc_last_session == session)
			sc->sc_last_session = 0;
		/*
		 * RFC 4638 section 5.1, verbatim: a bigger payload is in force
		 * only "If (PPP-Max-Payload-Tag) AND (PPP-Max-Payload-Tag >
		 * 1492)", and then it is min(what we asked, what was granted);
		 * with the tag absent -- or at or below 1492 on either side --
		 * "the existing MRU constraint of 1492 octets MUST stay
		 * applicable".  Taking the else arm only when both values
		 * exceed PPPOE_MAXMTU is also what bounds the MTU set here:
		 * max_payload comes straight off the wire above with no range
		 * check, so a PADS (or an earlier PADO, via the clamp) naming
		 * 1 would otherwise set this interface's MTU to 1 -- under
		 * IF_MINMTU, under IPv4's 68, under IPv6's 1280.
		 *
		 * The outer test keeps this gated on having asked, so an
		 * unsolicited tag cannot move the MTU of an interface that
		 * never offered one.
		 *
		 * The write goes through pppoe_mtu_set_link(), the one if_mtu
		 * writer (if_pppoe.c), which caps it by the peer's MRU while LCP
		 * is up.  if_setmtu() is a plain if_mtu assignment
		 * (sys/net/if.c:4457-4461), so it is safe under sc_mtx.
		 *
		 * ifhwioctl() follows every MTU change with rt_ifmsg() and
		 * if_notifymtu() (sys/net/if.c:2754, :2762-2763); the writer
		 * defers both to sc_mtu_task rather than calling them from
		 * here, because doing it inline is not safe: if_notifymtu()
		 * (:4463-4470) reaches rt_updatemtu() (sys/net/route.c:509-530)
		 * -> nhops_update_ifmtu() (sys/net/route/nhop_ctl.c:1054-1076),
		 * which takes rw_wlock() (sys/net/route/nhop_var.h:63) across a
		 * full next-hop walk for every address family in every fib, and
		 * rt_ifmsg() (sys/net/route.c:698-703) reaches nl_send_group()
		 * (sys/netlink/netlink_domain.c:193) under rm_rlock (:66) --
		 * all of it inside the pfil RX path's net epoch, where
		 * epoch(9) forbids sleeping: a blocking call there --
		 * rw_wlock() across the next-hop walk, or nl_send_group() --
		 * would sleep in the epoch section.  The stack's own answer to
		 * this on the RX side is to defer: if_link_state_change()
		 * (:2116-2126) only stores the state and enqueues
		 * ifp->if_linktask.  There is no such deferral for the MTU,
		 * hence the task of ours.
		 */
		if (sc->sc_max_payload != 0) {
			if (max_payload <= PPPOE_MAXMTU ||
			    sc->sc_max_payload <= PPPOE_MAXMTU) {
				sc->sc_max_payload = 0;
				pppoe_mtu_set_link(sc, PPPOE_MAXMTU);
			} else {
				sc->sc_max_payload = MIN(sc->sc_max_payload,
				    max_payload);
				pppoe_mtu_set_link(sc, sc->sc_max_payload);
			}
		}
		/* Session id, peer, parent and payload bound are final now. */
		pppoe_tx_snap_publish(sc, ts);
		taskqueue_enqueue(pppoe_taskq, &sc->sc_session_task);
		/*
		 * Tell the PPP layer the link is up (pp_up -> LCP Up event).
		 * Latched under sc_mtx and delivered by pppoe_session_task(),
		 * which runs outside sc_mtx: pp_up() enqueues on sppp's
		 * taskqueue and may take the sppp lock (plan-2 Task 3 Step 4).
		 * The interface link state is NOT set here: it goes UP when an
		 * NCP opens, written only by sppp_ncp_link() (p3-events).
		 */
		sc->sc_want_up = true;
		break;
	case PPPOE_CODE_PADT:
		/*
		 * pppoe_find_by_session() matched without the lock, and a
		 * Host-Uniq match did not check the session at all.  Re-check
		 * the whole key here: a PADT naming another session, or coming
		 * from a MAC that is not our AC, must not tear us down.
		 */
		if (sc->sc_state != PPPOE_STATE_SESSION ||
		    sc->sc_session != session ||
		    memcmp(&sc->sc_dest, &peer, sizeof(sc->sc_dest)) != 0) {
			ours = false;	/* not our session: pass it on */
			break;
		}
		taskqueue_enqueue(pppoe_taskq, &sc->sc_session_task);
		pppoe_clear_softc(sc, "received PADT");
		/*
		 * Re-dial after a short delay rather than sitting idle: this
		 * is the ISP-side behaviour called out in spec section 11
		 * ("no PADT on shutdown -> ISP refuses re-connect").
		 */
		sc->sc_state = PPPOE_STATE_PADI_SENT;
		sc->sc_padi_retried = 0;
		callout_reset(&sc->sc_timeout, PPPOE_RECON_PADTRCVD,
		    pppoe_timeout, sc);
		break;
	default:
		break;
	}
	PPPOE_SC_UNLOCK(sc);
	if (!ours)
		goto foreign;
	free(buf, M_PPPOE);
	m_freem(m);
	*mp = NULL;
	return (PPPOE_DISC_OURS);
malformed:
	counter_u64_add(V_pppoe_stats.disc_malformed, 1);
foreign:
	free(buf, M_PPPOE);
	*mp = m;
	return (PPPOE_DISC_FOREIGN);
}
