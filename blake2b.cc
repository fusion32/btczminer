#include "common.hh"

static const u64 blake2b_iv[8] = {
	0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
	0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
	0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
	0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

static const u8 blake2b_sigma[12][16] = {
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

#if ARCH_BIG_ENDIAN
static INLINE
u64 load64(u8 *src){
	u64 result =
		((u64)src[0] << 0)
		| ((u64)src[1] << 8)
		| ((u64)src[2] << 16)
		| ((u64)src[3] << 24)
		| ((u64)src[4] << 32)
		| ((u64)src[5] << 40)
		| ((u64)src[6] << 48)
		| ((u64)src[7] << 56);
	return result;
}
static INLINE
void store64(u8 *dst, u64 val){
	dst[0] = (u8)(val >> 0);
	dst[1] = (u8)(val >> 8);
	dst[2] = (u8)(val >> 16);
	dst[3] = (u8)(val >> 24);
	dst[4] = (u8)(val >> 32);
	dst[5] = (u8)(val >> 40);
	dst[6] = (u8)(val >> 48);
	dst[7] = (u8)(val >> 56);
}
#else // ARCH_BIG_ENDIAN
static INLINE
u64 load64(u8 *src){
	u64 result;
	memcpy(&result, src, 8);
	return result;
}
void store64(u8 *dst, u64 val){
	memcpy(dst, &val, 8);
}
#endif // ARCH_BIG_ENDIAN

static INLINE
u64 rotr64(u64 val, u8 n){
	DEBUG_ASSERT(n > 0 && n <= 63);
	u64 result = (val >> n) | (val << (64 - n));
	return result;
}

void blake2b_init(blake2b_state *S, u8 outlen){
	const u8 BTCZ_BLAKE2B_PARAMS[64] = {
		outlen,						// digest_length
		0x00,						// key_length
		0x01,						// fanout
		0x01,						// depth
		0x00, 0x00, 0x00, 0x00,		// leaf_length
		0x00, 0x00, 0x00, 0x00,		// node_offset
		0x00, 0x00, 0x00, 0x00,		// xof_length
		0x00,						// node_depth
		0x00,						// inner_length

		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,					// reserved

		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,		// salt

		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,		// personal
	};

	memset(S, 0, sizeof(blake2b_state));
	for(i32 i = 0; i < 8; i += 1)
		S->h[i] = blake2b_iv[i] ^ load64((u8*)BTCZ_BLAKE2B_PARAMS + i * 8);
	S->outlen = outlen;
}

void blake2b_init_btcz(blake2b_state *S){
	const u8 BTCZ_BLAKE2B_PARAMS[64] = {
		BTCZ_BLAKE_OUTLEN,			// digest_length
		0x00,						// key_length
		0x01,						// fanout
		0x01,						// depth
		0x00, 0x00, 0x00, 0x00,		// leaf_length
		0x00, 0x00, 0x00, 0x00,		// node_offset
		0x00, 0x00, 0x00, 0x00,		// xof_length
		0x00,						// node_depth
		0x00,						// inner_length

		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,					// reserved

		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,		// salt

		//"BitcoinZ\x90\x00\x00\x00\x05\x00\x00\x00"
		0x42, 0x69, 0x74, 0x63,
		0x6F, 0x69, 0x6E, 0x5A,
		0x90, 0x00, 0x00, 0x00,
		0x05, 0x00, 0x00, 0x00,		// personal
	};

	memset(S, 0, sizeof(blake2b_state));
	for(i32 i = 0; i < 8; i += 1)
		S->h[i] = blake2b_iv[i] ^ load64((u8*)BTCZ_BLAKE2B_PARAMS + i * 8);
	S->outlen = BTCZ_BLAKE_OUTLEN;
}

static
void blake2b_increment_counter(blake2b_state *S, u64 inc){
	S->t[0] += inc;
	S->t[1] += (S->t[0] < inc);
}

static
bool blake2b_is_lastblock(blake2b_state *S){
	return S->f[0] != 0;
}

static
void blake2b_set_lastblock(blake2b_state *S){
	S->f[0] = 0xFFFFFFFFFFFFFFFF;
}

#define G(r, i, a, b, c, d)							\
	do{												\
		a = a + b + m[blake2b_sigma[r][2 * i + 0]];	\
		d = rotr64(d ^ a, 32);						\
		c = c + d;									\
		b = rotr64(b ^ c, 24);						\
		a = a + b + m[blake2b_sigma[r][2 * i + 1]];	\
		d = rotr64(d ^ a, 16);						\
		c = c + d;									\
		b = rotr64(b ^ c, 63);						\
	}while(0)

#define ROUND(r)									\
	do{												\
		G(r, 0, v[0], v[4], v[8], v[12]);			\
		G(r, 1, v[1], v[5], v[9], v[13]);			\
		G(r, 2, v[2], v[6], v[10], v[14]);			\
		G(r, 3, v[3], v[7], v[11], v[15]);			\
		G(r, 4, v[0], v[5], v[10], v[15]);			\
		G(r, 5, v[1], v[6], v[11], v[12]);			\
		G(r, 6, v[2], v[7], v[8], v[13]);			\
		G(r, 7, v[3], v[4], v[9], v[14]);			\
	}while(0)

static
void blake2b_compress(blake2b_state *S, u8 *block){
	u64 m[16];
	u64 v[16];

	for(i32 i = 0; i < 16; i += 1)
		m[i] = load64(block + i * 8);

	for(i32 i = 0; i < 8; i += 1)
		v[i] = S->h[i];

	v[ 8] = blake2b_iv[0];
	v[ 9] = blake2b_iv[1];
	v[10] = blake2b_iv[2];
	v[11] = blake2b_iv[3];
	v[12] = blake2b_iv[4] ^ S->t[0];
	v[13] = blake2b_iv[5] ^ S->t[1];
	v[14] = blake2b_iv[6] ^ S->f[0];
	v[15] = blake2b_iv[7] ^ S->f[1];

	ROUND( 0); ROUND( 1); ROUND( 2); ROUND( 3);
	ROUND( 4); ROUND( 5); ROUND( 6); ROUND( 7);
	ROUND( 8); ROUND( 9); ROUND(10); ROUND(11);

	for(i32 i = 0; i < 8; i += 1)
		S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
}

#undef G
#undef ROUND

void blake2b_update(blake2b_state *S, u8 *in, u64 inlen){
	if(inlen == 0)
		return;

	u64 buflen = S->buflen;
	u64 bytes_to_fill = BLAKE2B_BLOCKBYTES - buflen;
	if(inlen >= bytes_to_fill){
		S->buflen = 0;
		memcpy(S->buf + buflen, in, bytes_to_fill);
		blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
		blake2b_compress(S, S->buf);
		in += bytes_to_fill;
		inlen -= bytes_to_fill;
		while(inlen >= BLAKE2B_BLOCKBYTES){
			blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
			blake2b_compress(S, in);
			in += BLAKE2B_BLOCKBYTES;
			inlen -= BLAKE2B_BLOCKBYTES;
		}
		memcpy(S->buf, in, inlen);
		S->buflen = inlen;
	}else{
		memcpy(S->buf + buflen, in, inlen);
		S->buflen += inlen;
	}
}

void blake2b_final(blake2b_state *S, u8 *out, u64 outlen){
	// NOTE: Even when S->buf is empty, we'll add an entire
	// block of padding. Not sure this is correct but we'll
	// see with the test vectors.

	DEBUG_ASSERT(out != NULL && outlen == S->outlen);
	DEBUG_ASSERT(!blake2b_is_lastblock(S));

	u64 buflen = S->buflen;
	memset(S->buf + buflen, 0, BLAKE2B_BLOCKBYTES - buflen);
	blake2b_set_lastblock(S);
	blake2b_increment_counter(S, buflen);
	blake2b_compress(S, S->buf);

	u8 tmp[BLAKE2B_OUTBYTES];
	for(i32 i = 0; i < 8; i += 1)
		store64(tmp + i * 8, S->h[i]);
	memcpy(out, tmp, S->outlen);
}
