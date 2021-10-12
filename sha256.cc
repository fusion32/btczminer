#include "common.hh"
#include "buffer_util.hh"

u32 sha256_iv[8] = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

u32 sha256_k[64] = {
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

static INLINE
u32 rotr32(u32 val, u8 n){
	DEBUG_ASSERT(n > 0 && n <= 31);
	u32 result = (val >> n) | (val << (32 - n));
	return result;
}

static
void sha256_compress(u32 *h, u8 *block){
	u32 w[64];

	for(i32 i = 0; i < 16; i += 1)
		w[i] = decode_u32_be(&block[i * 4]);

	for(i32 i = 16; i < 64; i += 1){
		u32 s0 = rotr32(w[i - 15],  7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>  3);
		u32 s1 = rotr32(w[i -  2], 17) ^ rotr32(w[i -  2], 19) ^ (w[i -  2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	u32 aux[8];
	memcpy(aux, h, sizeof(aux));
	for(i32 i = 0; i < 64; i += 1){
		u32 s1 = rotr32(aux[4], 6) ^ rotr32(aux[4], 11) ^ rotr32(aux[4], 25);
		u32 ch = (aux[4] & aux[5]) ^ (~aux[4] & aux[6]);
		u32 tmp1 = aux[7] + s1 + ch + sha256_k[i] + w[i];

		u32 s0 = rotr32(aux[0], 2) ^ rotr32(aux[0], 13) ^ rotr32(aux[0], 22);
		u32 maj = (aux[0] & aux[1]) ^ (aux[0] & aux[2]) ^ (aux[1] & aux[2]);
		u32 tmp2 = s0 + maj;

		aux[7] = aux[6];
		aux[6] = aux[5];
		aux[5] = aux[4];
		aux[4] = aux[3] + tmp1;
		aux[3] = aux[2];
		aux[2] = aux[1];
		aux[1] = aux[0];
		aux[0] = tmp1 + tmp2;
	}

	h[0] += aux[0];
	h[1] += aux[1];
	h[2] += aux[2];
	h[3] += aux[3];
	h[4] += aux[4];
	h[5] += aux[5];
	h[6] += aux[6];
	h[7] += aux[7];
}

u256 sha256(u8 *in, i32 inlen){
	u32 h[8];
	memcpy(h, sha256_iv, sizeof(sha256_iv));

	u8 *ptr = in;
	i32 len = inlen;
	while(len >= 64){
		sha256_compress(h, ptr);
		ptr += 64;
		len -= 64;
	}

	//
	// NOTE: At the end of the input data, we need to
	// append a 0x80 byte followed by `num_zeros` 0x00
	// bytes and the inlen encoded as a big-endian 64-bits
	// number such that:
	//	(inlen + 1 + num_zeros + 8) % 64 == 0
	//
	// Regardless, we'll always append 9 bytes at the end,
	// so if the last 'block' of our input has 55 (64 - 9)
	// or less bytes, we'll need to compress only one extra
	// block. In the other hand if it has more than 55 bytes
	// we'll need to compress two extra blocks.
	//

	if(len <= 55){
		i32 num_zeros = 55 - len;
		DEBUG_ASSERT(num_zeros >= 0);

		u8 block[64];
		memcpy(&block[0], ptr, len);
		encode_u8(&block[len], 0x80);
		memset(&block[len + 1], 0x00, num_zeros);
		encode_u64_be(&block[56], (u64)inlen * 8);
		sha256_compress(h, block);
	}else{
		DEBUG_ASSERT(len < 64);
		i32 num_zeros = 63 - len;
		DEBUG_ASSERT(num_zeros >= 0);

		u8 block[64];

		// 1st block
		memcpy(&block[0], ptr, len);
		encode_u8(&block[len], 0x80);
		memset(&block[len + 1], 0x00, num_zeros);
		sha256_compress(h, block);

		// 2nd block
		memset(&block[0], 0, 56);
		encode_u64_be(&block[56], inlen);
		sha256_compress(h, block);
	}

	u256 result;
	encode_u32_be(&result.data[ 0], h[0]);
	encode_u32_be(&result.data[ 4], h[1]);
	encode_u32_be(&result.data[ 8], h[2]);
	encode_u32_be(&result.data[12], h[3]);
	encode_u32_be(&result.data[16], h[4]);
	encode_u32_be(&result.data[20], h[5]);
	encode_u32_be(&result.data[24], h[6]);
	encode_u32_be(&result.data[28], h[7]);
	return result;
}

#if 0
#include <stdio.h>
int main(int argc, char **argv){
	i32 num;
	scanf("%d", &num);

	if(num <= 0 || num > 64)
		return -1;

	u32 *output = (u32*)malloc(sizeof(u32) * num);
	for(i32 i = 0; i < num; i += 1)
		scanf("%x", &output[i]);

	printf("\noutput:\n");
	for(i32 i = 0; i < num; i += 1){
		if((i & 3) == 3)
			printf("0x%08X,\n", output[i]);
		else
			printf("0x%08X, ", output[i]);
	}
	printf("\n");
	return 0;
}
#else
int main(int argc, char **argv){
	//const char *test1 = "";
	//const char *test1_result = "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
	//u256 tmp = sha256((u8*)test1, (i32)strlen(test1));
	u256 tmp = sha256(NULL, 0);
	for(i32 i = 0; i < 32; i += 1)
		printf("%02X ", tmp.data[i]);

	//const char *test2 = "";
	//const char *test2_result = "";
	//sha256((u8*)test2, strlen(test2));
}
#endif
