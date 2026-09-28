/* PPPoE frame builders shared by the pppoe/disc tests and the fuzzers. */
#ifndef _T_FRAMES_H_
#define _T_FRAMES_H_

struct fr {
	uint8_t	b[2048];
	size_t	len;
};

/* Ethernet (dst, src, type) + PPPoE header with plen = 0 for now. */
static inline void
fr_start(struct fr *f, const uint8_t dst[6], const uint8_t src[6],
    uint16_t etype, uint8_t code, uint16_t session)
{
	memcpy(f->b, dst, 6);
	memcpy(f->b + 6, src, 6);
	f->b[12] = etype >> 8;
	f->b[13] = etype & 0xff;
	f->b[14] = 0x11;
	f->b[15] = code;
	f->b[16] = session >> 8;
	f->b[17] = session & 0xff;
	f->b[18] = f->b[19] = 0;
	f->len = 20;
}

static inline void
fr_bytes(struct fr *f, const void *p, size_t n)
{
	memcpy(f->b + f->len, p, n);
	f->len += n;
}

static inline void
fr_tag(struct fr *f, uint16_t tag, const void *val, uint16_t len)
{
	uint8_t h[4] = { tag >> 8, tag & 0xff, len >> 8, len & 0xff };

	fr_bytes(f, h, 4);
	if (len != 0)
		fr_bytes(f, val, len);
}

/* Set the PPPoE length field to everything after the PPPoE header. */
static inline void
fr_finish(struct fr *f)
{
	size_t plen = f->len - 20;

	f->b[18] = (uint8_t)(plen >> 8);
	f->b[19] = (uint8_t)plen;
}

static inline void
fr_set_plen(struct fr *f, uint16_t plen)
{
	f->b[18] = plen >> 8;
	f->b[19] = plen & 0xff;
}

#endif
