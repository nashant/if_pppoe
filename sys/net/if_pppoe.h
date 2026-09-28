/* $NetBSD: if_pppoe.h,v 1.15 2017/10/12 09:50:55 knakahara Exp $ */

/*-
 * Copyright (c) 2002 The NetBSD Foundation, Inc.
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
 * FreeBSD port notice
 * -------------------
 * Ported to FreeBSD 14.3 (OPNsense 25.7, kernel SMP) for the OPNsense
 * if_pppoe project.  Source: NetBSD/src commit
 * 5ee7eb6e8db7128264453921994932a2c2a5af70, sys/net/if_pppoe.h.
 * The ioctl numbers and the userland-visible structs below are unchanged so
 * that NetBSD's pppoectl(8) works against this driver unmodified. Group
 * 'i' is kept (required so these ioctls actually reach ifioctl() -- see
 * sys/net/if_sppp.h and docs/PORTING-sppp.md); numbers 110-112 do not
 * collide with any generic FreeBSD 'i'-group ioctl.
 * The NetBSD locking notes at the end of the original header do not apply:
 * this port uses an epoch-protected session table (see sys/net/if_pppoe.c).
 */

#ifndef _NET_IF_PPPOE_H_
#define _NET_IF_PPPOE_H_

#include <sys/ioccom.h>

struct pppoediscparms {
	char	ifname[IFNAMSIZ];	/* pppoe interface name */
	char	eth_ifname[IFNAMSIZ];	/* external ethernet interface name */
	const char *ac_name;		/* access concentrator name (or NULL) */
	size_t	ac_name_len;		/* on write: length of buffer for ac_name */
	const char *service_name;	/* service name (or NULL) */
	size_t	service_name_len;	/* on write: length of buffer for service name */
};

#define	PPPOESETPARMS	_IOW('i', 110, struct pppoediscparms)
#define	PPPOEGETPARMS	_IOWR('i', 111, struct pppoediscparms)

#define PPPOE_STATE_INITIAL	0
#define PPPOE_STATE_PADI_SENT	1
#define	PPPOE_STATE_PADR_SENT	2
#define	PPPOE_STATE_SESSION	3
#define	PPPOE_STATE_CLOSING	4

struct pppoeconnectionstate {
	char	ifname[IFNAMSIZ];	/* pppoe interface name */
	u_int	state;			/* one of the PPPOE_STATE_ states above */
	u_int	session_id;		/* if state == PPPOE_STATE_SESSION */
	u_int	padi_retry_no;		/* number of retries already sent */
	u_int	padr_retry_no;
};

#define PPPOEGETSESSION	_IOWR('i', 112, struct pppoeconnectionstate)

/*
 * TCP MSS clamp (not in NetBSD; kern.features.if_pppoe_mssfix), on by
 * default like mpd5's tcpmssfix.  enable is 0 or 1; anything else is EINVAL.
 */
struct pppoemssfixparms {
	char	ifname[IFNAMSIZ];	/* pppoe interface name */
	u_int	enable;
};

#define	PPPOESETMSSFIX	_IOW('i', 113, struct pppoemssfixparms)
#define	PPPOEGETMSSFIX	_IOWR('i', 114, struct pppoemssfixparms)

#ifdef _KERNEL

MALLOC_DECLARE(M_PPPOE);

struct pppoehdr {
	uint8_t vertype;
	uint8_t code;
	uint16_t session;
	uint16_t plen;
} __packed;

struct pppoetag {
	uint16_t tag;
	uint16_t len;
} __packed;

#define	PPPOE_HEADERLEN		sizeof(struct pppoehdr)		/* 6 */
#define	PPPOE_OVERHEAD		(PPPOE_HEADERLEN + 2)		/* + PPP proto */
#define	PPPOE_VERTYPE		0x11	/* VER=1, TYPE=1 */
#define	PPPOE_MAXMTU		(ETHERMTU - PPPOE_OVERHEAD)	/* 1492 */

/*
 * Bytes the RX hook strips before handing the mbuf to sppp: the Ethernet
 * header is still on the mbuf at the ether_demux() pfil hook
 * (sys/net/if_ethersubr.c:959 strips it only after the hook), so it is
 * 14 + 6 = 20, leaving the 2-byte PPP protocol field at the front for
 * sppp_input() to read.  Spec section 6 step 3.
 */
#define	PPPOE_RX_STRIP		(ETHER_HDR_LEN + PPPOE_HEADERLEN)

#define	PPPOE_TAG_EOL		0x0000
#define	PPPOE_TAG_SNAME		0x0101
#define	PPPOE_TAG_ACNAME	0x0102
#define	PPPOE_TAG_HUNIQUE	0x0103
#define	PPPOE_TAG_ACCOOKIE	0x0104
#define	PPPOE_TAG_VENDOR	0x0105
#define	PPPOE_TAG_RELAYSID	0x0110
#define	PPPOE_TAG_MAX_PAYLOAD	0x0120
#define	PPPOE_TAG_SNAME_ERR	0x0201
#define	PPPOE_TAG_ACSYS_ERR	0x0202
#define	PPPOE_TAG_GENERIC_ERR	0x0203

#define	PPPOE_CODE_PADI		0x09
#define	PPPOE_CODE_PADO		0x07
#define	PPPOE_CODE_PADR		0x19
#define	PPPOE_CODE_PADS		0x65
#define	PPPOE_CODE_PADT		0xA7

#define	PPPOE_DISC_TIMEOUT	(hz * 5)
#define	PPPOE_SLOW_RETRY	(hz * 60)
#define	PPPOE_RECON_FAST	(hz * 15)
#define	PPPOE_RECON_IMMEDIATE	(hz / 10)
#define	PPPOE_RECON_PADTRCVD	(hz * 5)
#define	PPPOE_DISC_MAXPADI	4
#define	PPPOE_DISC_MAXPADR	2

/*
 * Private netisr protocol for decapsulated session frames.  netisr protocol
 * numbers must be 0 < proto < NETISR_MAXPROT (16)
 * (sys/net/netisr_internal.h:70).  1,2,3,4,5,6,9,10 are taken by the base
 * system (sys/net/netisr.h:52-59); 11 and 12 are free.  Verify with
 * `netstat -Q` before loading on a new kernel.
 */
#define	NETISR_PPPOE_DATA	11
#define	NETISR_PPPOE_DISC	12	/* reserved, not registered in Phase 1 */

#endif /* _KERNEL */
#endif /* !_NET_IF_PPPOE_H_ */
