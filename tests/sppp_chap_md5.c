/*
 * sppp_chap_md5.c - unit-level CHAP-MD5 verification for M002 S02/T3.
 *
 * The if_pppoe module's CHAP-MD5 lives in the vendored NetBSD sppp
 * (sys/net/if_spppsubr.c @ pin 5ee7eb6e8db7) and implements RFC 1994:
 *
 *     Response = MD5(Identifier || Secret || Challenge)
 *
 * each side computing it from ITS copy of the secret:
 *   - peer (client)      arm: sppp_chap_input CHAP_CHALLENGE,
 *     "Compute reply value.":  MD5Init; MD5Update(&h->ident,1);
 *     MD5Update(sp->myauth.secret, myauth.secret_len);
 *     MD5Update(value, value_len) [the challenge]; MD5Final -> digest
 *   - authenticator arm:      sppp_chap_input CHAP_RESPONSE: same triple
 *     over sp->hisauth.secret and sp->chap.challenge, compared against the
 *     value the packet carried (mismatch = RCR- / CHAP failure)
 *
 * That code is kernel-only (locks, mbufs, workqueue), so - exactly like the
 * S02/T1 LCP loopback harness - this harness transcribes the two MD5 calls
 * verbatim from the vendored source and drives them with known CHAP-MD5
 * challenge/response vectors:
 *
 *   Vector A (canonical):  id=0x01, secret="secret",
 *     challenge="1234567890123456789012345678901234567890"  ->
 *     3357a363bb9ab37fb15610eb2b21eda9
 *   Vector B (real capture): id=0x03, secret="freesurf",
 *     challenge=bf2b15282cf4f6672f1b809a251bd731 ->
 *     69cd88a27098f6c3e961f49f0cec74fb
 *     (captured live from a ppp <-> mpd exchange; documented at
 *     networkengineering.stackexchange.com/questions/54285)
 *
 * Both reference digests were re-derived independently with OpenSSL's MD5
 * (python hashlib) on the build host at S02/T3 time - see the run log.
 *
 * MD5 is provided one of two ways (both are validated against the RFC 1321
 * known-answer digests below, and both implement the exact
 * MD5Init/MD5Update/MD5Final API from sys/sys/md5.h that the kernel module
 * compiles against):
 *   - default: the embedded RFC 1321 reference implementation below
 *     (the same algorithm lineage as FreeBSD's kernel sys/crypto/md5)
 *   - -DSPPP_CHAP_USE_LIBMD: FreeBSD base libmd via <md5.h> (the libmd
 *     and kernel md5.c share that reference implementation), so the
 *     harness also runs against the exact MD5 the deployed
 *     /tmp/if_pppoe.ko was linked against.
 *
 * Build and run (no privileges, no network, no interfaces):
 *   cc -Wall -Wextra -O2 -o sppp_chap_md5 sppp_chap_md5.c
 *   ./sppp_chap_md5
 * or, on FreeBSD:  cc -O2 -Wall -Wextra -DSPPP_CHAP_USE_LIBMD \
 *                      -o sppp_chap_md5 sppp_chap_md5.c -lmd && ./sppp_chap_md5
 *
 * Every failure exits non-zero and names the exact check.  R011: the
 * harness prints identifiers, lengths and digests only - never a secret
 * (the runner additionally greps this binary's output for the live
 * secret before failing the run).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef SPPP_CHAP_USE_LIBMD
#include <sys/types.h>	/* u_int32_t, required by FreeBSD /usr/include/md5.h */
#include <md5.h>
#else

/*
 * Embedded MD5 - RFC 1321 reference implementation, transcribed with the
 * FreeBSD sys/sys/md5.h API (MD5_CTX / MD5Init / MD5Update / MD5Final;
 * see /usr/src/sys/sys/md5.h and /usr/src/sys/crypto/md5/md5.c).  The
 * transform constants (F..I, S, T) come verbatim from RFC 1321.
 */
typedef struct MD5Context {
	uint32_t state[4];
	uint32_t count[2];
	unsigned char buffer[64];
} MD5_CTX;

static void
MD5Init(MD5_CTX *ctx)
{
	ctx->count[0] = ctx->count[1] = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define STEP(f, a, b, c, d, x, t, s)					\
	(a) += f((b), (c), (d)) + (x) + (uint32_t)(t);			\
	(a) = ROTL((a), (s));						\
	(a) += (b);

static void
MD5Transform(uint32_t *state, const unsigned char *block)
{
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
	uint32_t x[16];
	int i;

	for (i = 0; i < 16; i++)
		x[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1]<<8) |
		    ((uint32_t)block[i*4+2]<<16) | ((uint32_t)block[i*4+3]<<24);

	/* Round 1 */
	STEP(F, a, b, c, d, x[ 0], 0xd76aa478, 7);
	STEP(F, d, a, b, c, x[ 1], 0xe8c7b756, 12);
	STEP(F, c, d, a, b, x[ 2], 0x242070db, 17);
	STEP(F, b, c, d, a, x[ 3], 0xc1bdceee, 22);
	STEP(F, a, b, c, d, x[ 4], 0xf57c0faf, 7);
	STEP(F, d, a, b, c, x[ 5], 0x4787c62a, 12);
	STEP(F, c, d, a, b, x[ 6], 0xa8304613, 17);
	STEP(F, b, c, d, a, x[ 7], 0xfd469501, 22);
	STEP(F, a, b, c, d, x[ 8], 0x698098d8, 7);
	STEP(F, d, a, b, c, x[ 9], 0x8b44f7af, 12);
	STEP(F, c, d, a, b, x[10], 0xffff5bb1, 17);
	STEP(F, b, c, d, a, x[11], 0x895cd7be, 22);
	STEP(F, a, b, c, d, x[12], 0x6b901122, 7);
	STEP(F, d, a, b, c, x[13], 0xfd987193, 12);
	STEP(F, c, d, a, b, x[14], 0xa679438e, 17);
	STEP(F, b, c, d, a, x[15], 0x49b40821, 22);
	/* Round 2 */
	STEP(G, a, b, c, d, x[ 1], 0xf61e2562, 5);
	STEP(G, d, a, b, c, x[ 6], 0xc040b340, 9);
	STEP(G, c, d, a, b, x[11], 0x265e5a51, 14);
	STEP(G, b, c, d, a, x[ 0], 0xe9b6c7aa, 20);
	STEP(G, a, b, c, d, x[ 5], 0xd62f105d, 5);
	STEP(G, d, a, b, c, x[10], 0x02441453, 9);
	STEP(G, c, d, a, b, x[15], 0xd8a1e681, 14);
	STEP(G, b, c, d, a, x[ 4], 0xe7d3fbc8, 20);
	STEP(G, a, b, c, d, x[ 9], 0x21e1cde6, 5);
	STEP(G, d, a, b, c, x[14], 0xc33707d6, 9);
	STEP(G, c, d, a, b, x[ 3], 0xf4d50d87, 14);
	STEP(G, b, c, d, a, x[ 8], 0x455a14ed, 20);
	STEP(G, a, b, c, d, x[13], 0xa9e3e905, 5);
	STEP(G, d, a, b, c, x[ 2], 0xfcefa3f8, 9);
	STEP(G, c, d, a, b, x[ 7], 0x676f02d9, 14);
	STEP(G, b, c, d, a, x[12], 0x8d2a4c8a, 20);
	/* Round 3 */
	STEP(H, a, b, c, d, x[ 5], 0xfffa3942, 4);
	STEP(H, d, a, b, c, x[ 8], 0x8771f681, 11);
	STEP(H, c, d, a, b, x[11], 0x6d9d6122, 16);
	STEP(H, b, c, d, a, x[14], 0xfde5380c, 23);
	STEP(H, a, b, c, d, x[ 1], 0xa4beea44, 4);
	STEP(H, d, a, b, c, x[ 4], 0x4bdecfa9, 11);
	STEP(H, c, d, a, b, x[ 7], 0xf6bb4b60, 16);
	STEP(H, b, c, d, a, x[10], 0xbebfbc70, 23);
	STEP(H, a, b, c, d, x[13], 0x289b7ec6, 4);
	STEP(H, d, a, b, c, x[ 0], 0xeaa127fa, 11);
	STEP(H, c, d, a, b, x[ 3], 0xd4ef3085, 16);
	STEP(H, b, c, d, a, x[ 6], 0x04881d05, 23);
	STEP(H, a, b, c, d, x[ 9], 0xd9d4d039, 4);
	STEP(H, d, a, b, c, x[12], 0xe6db99e5, 11);
	STEP(H, c, d, a, b, x[15], 0x1fa27cf8, 16);
	STEP(H, b, c, d, a, x[ 2], 0xc4ac5665, 23);
	/* Round 4 */
	STEP(I, a, b, c, d, x[ 0], 0xf4292244, 6);
	STEP(I, d, a, b, c, x[ 7], 0x432aff97, 10);
	STEP(I, c, d, a, b, x[14], 0xab9423a7, 15);
	STEP(I, b, c, d, a, x[ 5], 0xfc93a039, 21);
	STEP(I, a, b, c, d, x[12], 0x655b59c3, 6);
	STEP(I, d, a, b, c, x[ 3], 0x8f0ccc92, 10);
	STEP(I, c, d, a, b, x[10], 0xffeff47d, 15);
	STEP(I, b, c, d, a, x[ 1], 0x85845dd1, 21);
	STEP(I, a, b, c, d, x[ 8], 0x6fa87e4f, 6);
	STEP(I, d, a, b, c, x[15], 0xfe2ce6e0, 10);
	STEP(I, c, d, a, b, x[ 6], 0xa3014314, 15);
	STEP(I, b, c, d, a, x[13], 0x4e0811a1, 21);
	STEP(I, a, b, c, d, x[ 4], 0xf7537e82, 6);
	STEP(I, d, a, b, c, x[11], 0xbd3af235, 10);
	STEP(I, c, d, a, b, x[ 2], 0x2ad7d2bb, 15);
	STEP(I, b, c, d, a, x[ 9], 0xeb86d391, 21);

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void
MD5Update(MD5_CTX *ctx, const unsigned char *input, unsigned int inlen)
{
	uint32_t i, idx, part;

	idx = (ctx->count[0] >> 3) & 0x3f;
	if ((ctx->count[0] += ((uint32_t)inlen << 3)) <
	    ((uint32_t)inlen << 3))
		ctx->count[1]++;
	ctx->count[1] += ((uint32_t)inlen >> 29);

	part = 64 - idx;
	if (inlen >= part) {
		memcpy(ctx->buffer + idx, input, part);
		MD5Transform(ctx->state, ctx->buffer);
		for (i = part; i + 63 < inlen; i += 64)
			MD5Transform(ctx->state, input + i);
		idx = 0;
	} else {
		i = 0;
	}
	memcpy(ctx->buffer + idx, input + i, inlen - i);
}

static void
MD5Final(unsigned char digest[16], MD5_CTX *ctx)
{
	static const unsigned char pad[64] = {
		0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	unsigned char c[8];
	uint32_t i;

	c[0] = (unsigned char)(ctx->count[0] >> 0);
	c[1] = (unsigned char)(ctx->count[0] >> 8);
	c[2] = (unsigned char)(ctx->count[0] >> 16);
	c[3] = (unsigned char)(ctx->count[0] >> 24);
	c[4] = (unsigned char)(ctx->count[1] >> 0);
	c[5] = (unsigned char)(ctx->count[1] >> 8);
	c[6] = (unsigned char)(ctx->count[1] >> 16);
	c[7] = (unsigned char)(ctx->count[1] >> 24);

	i = (ctx->count[0] >> 3) & 0x3f;
	MD5Update(ctx, pad, (i < 56) ? 56 - i : 120 - i);
	MD5Update(ctx, c, 8);
	for (i = 0; i < 4; i++) {
		digest[i]      = (unsigned char)(ctx->state[0] >> (i*8));
		digest[i + 4]  = (unsigned char)(ctx->state[1] >> (i*8));
		digest[i + 8]  = (unsigned char)(ctx->state[2] >> (i*8));
		digest[i + 12] = (unsigned char)(ctx->state[3] >> (i*8));
	}
}
#endif /* !SPPP_CHAP_USE_LIBMD */

/*
 * The two MD5 arms from the vendored if_spppsubr.c, transcribed verbatim.
 * sppp_chap_response() is the peer arm (CHAP_CHALLENGE handler: "Compute
 * reply value") and sppp_chap_verify() is the authenticator arm
 * (CHAP_RESPONSE handler: recompute and compare).  Both follow RFC 1994.
 */
static void
sppp_chap_response(unsigned char ident, const unsigned char *secret,
    size_t secret_len, const unsigned char *challenge, size_t challenge_len,
    unsigned char digest[16])
{
	MD5_CTX ctx;

	MD5Init(&ctx);
	MD5Update(&ctx, &ident, 1);
	MD5Update(&ctx, secret, secret_len);
	MD5Update(&ctx, challenge, challenge_len);
	MD5Final(digest, &ctx);
}

static int
sppp_chap_verify(unsigned char ident, const unsigned char *secret,
    size_t secret_len, const unsigned char *challenge, size_t challenge_len,
    const unsigned char *value)
{
	unsigned char digest[16];

	sppp_chap_response(ident, secret, secret_len, challenge,
	    challenge_len, digest);
	return memcmp(digest, value, 16) == 0;
}

#define MD5_DIGEST_LEN	16

static int fails;
static int total;

static void
check(const char *what, int ok)
{
	total++;
	printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
	if (!ok)
		fails++;
}

static const char *
hex(const unsigned char *p, size_t n, char *buf, size_t buflen)
{
	static const char *digits = "0123456789abcdef";
	size_t i;

	if (buflen < n * 2 + 1)
		return "(buf too small)";
	for (i = 0; i < n; i++) {
		buf[i*2] = digits[p[i] >> 4];
		buf[i*2+1] = digits[p[i] & 0xf];
	}
	buf[n*2] = 0;
	return buf;
}

int
main(void)
{
	char hbuf[64];
	unsigned char digest[MD5_DIGEST_LEN];
	unsigned char frame[128], *p;
	size_t flen;
	int i, j;

	printf("== sppp_chap_md5: unit CHAP-MD5 vector verification ==\n");
#ifdef SPPP_CHAP_USE_LIBMD
	printf("MD5 provider: FreeBSD base libmd (-DSPPP_CHAP_USE_LIBMD)\n");
#else
	printf("MD5 provider: embedded RFC 1321 reference implementation\n");
#endif

	/* ---- (1) RFC 1321 known-answer digests for the MD5 provider ---- */
	printf("\n[1] RFC 1321 MD5 known-answer digests\n");
	{
		struct kat { const char *s; const char *digest; } kats[] = {
			{ "", "d41d8cd98f00b204e9800998ecf8427e" },
			{ "a", "0cc175b9c0f1b6a831c399e269772661" },
			{ "abc", "900150983cd24fb0d6963f7d28e17f72" },
			{ "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
			{ "abcdefghijklmnopqrstuvwxyz",
			  "c3fcd3d76192e4007dfb496cca67e13b" },
			{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			  "d174ab98d277d9f5a5611c2c9f419d9f" },
			{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
			  "57edf4a22be3c955ac49da2e2107b67a" },
		};
		for (i = 0; i < 7; i++) {
			MD5_CTX ctx;

			MD5Init(&ctx);
			MD5Update(&ctx,
			    (const unsigned char *)kats[i].s, strlen(kats[i].s));
			MD5Final(digest, &ctx);
			check("RFC 1321 KAT", hex(digest, MD5_DIGEST_LEN, hbuf,
			    sizeof(hbuf)) != NULL &&
			    strcmp(hbuf, kats[i].digest) == 0);
		}
	}

	/* ---- (2) the known CHAP-MD5 challenge/response vectors ---- */
	printf("\n[2] known CHAP-MD5 vectors (MD5(ident || secret || challenge))\n");
	{
		static const unsigned char chalA[] =
		    "1234567890123456789012345678901234567890";
		static const unsigned char chalB[16] = {
		    0xbf, 0x2b, 0x15, 0x28, 0x2c, 0xf4, 0xf6, 0x67,
		    0x2f, 0x1b, 0x80, 0x9a, 0x25, 0x1b, 0xd7, 0x31 };

		/* Vector A: canonical (id=1, secret="secret") */
		sppp_chap_response(0x01, (const unsigned char *)"secret", 6,
		    chalA, sizeof(chalA) - 1, digest);
		check("vector A 3357a363bb9ab37fb15610eb2b21eda9",
		    strcmp(hex(digest, MD5_DIGEST_LEN, hbuf, sizeof(hbuf)),
		    "3357a363bb9ab37fb15610eb2b21eda9") == 0);

		/* Vector B: real captured exchange ("freesurf") */
		sppp_chap_response(0x03, (const unsigned char *)"freesurf", 8,
		    chalB, sizeof(chalB), digest);
		check("vector B 69cd88a27098f6c3e961f49f0cec74fb",
		    strcmp(hex(digest, MD5_DIGEST_LEN, hbuf, sizeof(hbuf)),
		    "69cd88a27098f6c3e961f49f0cec74fb") == 0);
	}

	/* ---- (3) full round trip: challenge -> response -> verify ---- */
	printf("\n[3] complete exchange round trip (peer secret == server secret)\n");
	{
		unsigned char challenge[16];
		unsigned char response[MD5_DIGEST_LEN];

		for (j = 0; j < 16; j++)
			challenge[j] = (unsigned char)(0xa0 + j);

		/* peer: on CHAP_CHALLENGE, compute reply value */
		sppp_chap_response(0x2a, (const unsigned char *)"labpass", 7,
		    challenge, sizeof(challenge), response);

		/* build the CHAP_RESPONSE packet: value_size(1) value(16)
		 * name_len(1) name(..) - exactly the layout
		 * sppp_chap_scr() ships via sppp_auth_send() */
		p = frame;
		*p++ = MD5_DIGEST_LEN;
		memcpy(p, response, MD5_DIGEST_LEN);
		p += MD5_DIGEST_LEN;
		*p++ = 3;
		memcpy(p, "lab", 3);
		p += 3;
		flen = (size_t)(p - frame);

		/* authenticator: recompute from ITS secret and compare */
		check("authenticator verifies correct secret",
		    sppp_chap_verify(0x2a, (const unsigned char *)"labpass", 7,
		    challenge, sizeof(challenge), response));

		/* wire properties: frame carries the digest bytes ... */
		printf("  response digest on the wire: %s\n",
		    hex(response, MD5_DIGEST_LEN, hbuf, sizeof(hbuf)));
		/* ... and never the secret material itself */
		{
			static const unsigned char secretenc[] =
			    "labpass";
			int found = 0;
			for (j = 0; j <= (int)flen - (int)sizeof(secretenc) + 1; j++)
				if (memcmp(frame + j, secretenc,
				    sizeof(secretenc) - 1) == 0)
					found = 1;
			check("response frame contains no plaintext secret", !found);
		}
	}

	/* ---- (4) negative: a wrong secret must FAIL verification ---- */
	printf("\n[4] negative: wrong secret is rejected (authenticator RCR- path)\n");
	{
		unsigned char challenge[16];
		unsigned char response[MD5_DIGEST_LEN];

		for (j = 0; j < 16; j++)
			challenge[j] = (unsigned char)(0x40 + j);
		sppp_chap_response(0x7, (const unsigned char *)"correct", 7,
		    challenge, sizeof(challenge), response);
		check("wrong secret => verify mismatch",
		    !sppp_chap_verify(0x7, (const unsigned char *)"wrong!", 6,
		    challenge, sizeof(challenge), response));
		check("empty secret cannot match a non-empty response",
		    !sppp_chap_verify(0x7, (const unsigned char *)"", 0,
		    challenge, sizeof(challenge), response));
	}

	/* ---- (5) R011: this binary's output never contains a secret ---- */
	/* (the runner additionally greps the captured output for the LIVE
	 * secret; here we only print a digest for the lab fixture to show
	 * digests, never secrets, appear) */
	printf("\n[5] R011 self-check (secrets only ever appear hashed)\n");
	{
		sppp_chap_response(0x01, (const unsigned char *)"labpass", 7,
		    (const unsigned char *)"0123456789abcdef", 16, digest);
		printf("  digest for a lab-fixture secret: %s\n",
		    hex(digest, MD5_DIGEST_LEN, hbuf, sizeof(hbuf)));
	}

	printf("\n== result: %d/%d checks passed ==\n", total - fails, total);
	return fails == 0 ? 0 : 1;
}