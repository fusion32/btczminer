#include "common.hh"

#define BITS_TO_BYTES(x) (((x) + 7) / 8)
#define BYTES_TO_BITS(x) (8 * (x))



void expand_indices(
		u8 *in, i32 inlen,
		u8 *out, i32 outlen,
		i32 index_bits, i32 padding){

	// NOTE: This seems to be a restriction on equihash
	// but also on having a 32-bits bitbuffer.
	DEBUG_ASSERT(index_bits >= 8 && index_bits <= 25);

	i32 index_bytes = BITS_TO_BYTES(index_bits);
	i32 expanded_bytes = padding + index_bytes;

	// NOTE: We can't always make sure the assertion below
	// won't trigger because if index_bits isn't a multiple
	// of eight, only some values of `inlen` can be used.
	//DEBUG_ASSERT((BYTES_TO_BITS(inlen) % index_bits) == 0);

	// NOTE: Make sure `out` has enough room to receive the
	// expanded data.
	i32 num_indices = BYTES_TO_BITS(inlen) / index_bits;
	DEBUG_ASSERT(outlen == (num_indices * expanded_bytes));

	u32 index_mask = (1 << index_bits) - 1;
#if 0
	// TODO: This should be a small optimization to avoid shifting the
	// index_mask `index_bytes` times every time we encode an index into
	// `out`. Nevertheless, it may be more expensive to index into this
	// array than to do a simple shift. (CHECK THIS)
	u8 index_mask_array[4] = {
		index_mask >>  0,
		index_mask >>  8,
		index_mask >> 16,
		index_mask >> 24,
	};
#endif

	u32 bitbuffer = 0;
	i32 bitcount = 0;
	for(i32 i = 0; i < inlen; i += 1){
		bitbuffer = (bitbuffer << 8) | in[i];
		bitcount += 8;
		if(bitcount >= index_bits){
			bitcount -= index_bits;
			DEBUG_ASSERT(bitcount < 8);

			// add padding
			for(i32 j = 0; j < padding; j += 1)
				out[j] = 0;
			out += padding;
	
			// encode index bits in big endian order
			for(i32 j = 0; j < index_bytes; j += 1){
				i32 last_byte_index = index_bytes - 1;
				i32 shift = 8 * (last_byte_index - j);
				u8 cur_byte = (u8)(bitbuffer >> (bitcount + shift));
				u8 cur_byte_mask = (u8)(index_mask >> shift);
				out[j] = cur_byte & cur_byte_mask;
			}
			out += index_bytes;
		}
	}
}
#if 0
void compress_indices(
		u8 *in, i32 inlen,
		u8 *out, i32 outlen,
		i32 index_bits, i32 padding){

	// NOTE: This seems to be a restriction on equihash
	// but also on having a 32-bits bitbuffer.
	DEBUG_ASSERT(index_bits >= 8 && index_bits <= 25);

	i32 index_bytes = BITS_TO_BYTES(index_bits);
	i32 expanded_bytes = padding + index_bytes;

	// NOTE: Make sure `in` contains an exact number of
	// expanded indices. This is not a huge deal but will
	// help us catch possible bugs.
	DEBUG_ASSERT((inlen % expanded_bytes) == 0);

	// NOTE: Make sure `out` has enough room to receive the
	// compressed data.
	i32 num_indices = inlen / expanded_bytes;
	DEBUG_ASSERT(outlen == BITS_TO_BYTES(num_indices * index_bits));

	u32 index_mask = (1 << index_bits) - 1;
	u32 bitbuffer = 0;
	i32 bitcount = 0;
	for(i32 i = 0; i < outlen; i += 1){
		if(bitcount < 8){
			// read an entire index into the bitbuffer
			bitbuffer <<= index_bits;
			bitcount += index_bits;
			in += padding; // skip padding
			for(i32 j = 0; j < index_bytes; j += 1){
				i32 shift = 8 * j;
				u8 cur_byte = in[j];
				bitbuffer |= ((u32)cur_byte << shift) & index_mask;
			}
			in += index_bytes;
		}

		bitcount -= 8;
		out[i] = (u8)(bitbuffer >> bitcount);
	}
}

void expand_indices_to_u32(
		u8 *in, i32 inlen,
		u32 *out, i32 outlen,
		i32 index_bits){

	DEBUG_ASSERT(index_bits >= 8 && index_bits <= 25);
	i32 index_bytes = BITS_TO_BYTES(index_bits);
	i32 num_indices = BYTES_TO_BITS(inlen) / index_bits;
	DEBUG_ASSERT(outlen == (num_indices * 4));
	u32 index_mask = (1 << index_bits) - 1;
	u32 bitbuffer = 0;
	i32 bitcount = 0;
	for(i32 i = 0; i < inlen; i += 1){
		bitbuffer = (bitbuffer << 8) | in[i];
		bitcount += 8;
		if(bitcount >= index_bits){
			bitcount -= index_bits;
			DEBUG_ASSERT(bitcount < 8);
			u32 index = (bitbuffer >> bitcount) & index_mask;
			*out = index;
			out += 1;
		}
	}
}

static INLINE
u16 swap_u16(u16 value){
	u16 result =
		  ((value << 8) & 0xFF00)
		| ((value >> 8) & 0x00FF);
	return result;
}

int main(int argc, char **argv){
#define TEST_INDEX_BITS 11
	u16 indices[] = {
		 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
		11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		21, 22, 23, 24, 25, 1337
	};
	u8 compressed[BITS_TO_BYTES(TEST_INDEX_BITS * NARRAY(indices))];
	compress_indices(
		(u8*)indices, sizeof(indices),
		compressed, sizeof(compressed),
		TEST_INDEX_BITS, 0);
	
#if 1
	u32 indices32[NARRAY(indices)];
	expand_indices_to_u32(
		compressed, sizeof(compressed),
		indices32, sizeof(indices32),
		TEST_INDEX_BITS);
	for(i32 i = 0; i < NARRAY(indices32); i += 1)
		LOG("%d = %u\n", i, indices32[i]);
#else
	expand_indices(compressed, sizeof(compressed),
		(u8*)indices, sizeof(indices),
		TEST_INDEX_BITS, 0);
	for(i32 i = 0; i < NARRAY(indices); i += 1){
		LOG("%d: BE = %u, LE = %u\n", i,
			indices[i], swap_u16(indices[i]));
	}
#endif
}

#else

void expand_indices_to_u32(
		u8 *in, i32 inlen,
		u32 *out, i32 outlen,
		i32 index_bits){

	// NOTE: This seems to be a restriction on equihash
	// but also on having a 32-bits bitbuffer.
	DEBUG_ASSERT(index_bits >= 8 && index_bits <= 25);

	i32 index_bytes = BITS_TO_BYTES(index_bits);

	// NOTE: Make sure `out` has enough room to receive the
	// expanded data.
	i32 num_indices = BYTES_TO_BITS(inlen) / index_bits;
	DEBUG_ASSERT(outlen == (num_indices * 4));

	u32 index_mask = (1 << index_bits) - 1;
#if 0
	// TODO: This should be a small optimization to avoid shifting the
	// index_mask `index_bytes` times every time we encode an index into
	// `out`. Nevertheless, it may be more expensive to index into this
	// array than to do a simple shift. (CHECK THIS)
	u8 index_mask_array[4] = {
		index_mask >>  0,
		index_mask >>  8,
		index_mask >> 16,
		index_mask >> 24,
	};
#endif

	u32 bitbuffer = 0;
	i32 bitcount = 0;
	for(i32 i = 0; i < inlen; i += 1){
		bitbuffer = (bitbuffer << 8) | in[i];
		bitcount += 8;
		if(bitcount >= index_bits){
			bitcount -= index_bits;
			DEBUG_ASSERT(bitcount < 8);
			u32 index = (bitbuffer >> bitcount) & index_mask;
			*out = index;
			out += 1;
		}
	}
}

struct u256{
	// NOTE: `data` should be always in little endian format
	u8 data[32];
};

bool operator>(const u256 &a, const u256 &b){
	for(i32 i = 31; i >= 0; i -= 1){
		if(a.data[i] > b.data[i])
			return true;
		if(a.data[i] < b.data[i])
			return false;
	}
	return false;
}

bool operator==(const u256 &a, const u256 &b){
	for(i32 i = 0; i < 32; i += 1){
		if(a.data[i] != b.data[i])
			return false;
	}
	return true;
}

struct u144{
	u8 data[18];
};

#if 0
u144 make_u144(u32 low32){
	u144 result = {};
	result.data[0] = (u8)(low32 >>  0);
	result.data[1] = (u8)(low32 >>  8);
	result.data[2] = (u8)(low32 >> 16);
	result.data[3] = (u8)(low32 >> 24);
	return result;
}
#endif

bool operator>(const u144 &a, const u144 &b){
	for(i32 i = 17; i >= 0; i -= 1){
		if(a.data[i] > b.data[i])
			return true;
		if(a.data[i] < b.data[i])
			return false;
	}
	return false;
}

bool operator==(const u144 &a, const u144 &b){
	for(i32 i = 0; i < 18; i += 1){
		if(a.data[i] != b.data[i])
			return false;
	}
	return true;
}

void operator^=(u144 &a, const u144 &b){
	for(i32 i = 0 ; i < 18; i += 1)
		a.data[i] ^= b.data[i];
}

u144 operator^(const u144 &a, const u144 &b){
	u144 result = a;
	result ^= b;
	return result;
}

struct BlockHeader{
	i32 version;
	u256 hash_prev_block;
	u256 hash_merkle_root;
	u256 hash_final_sapling_root;
	u32 time;
	u32 bits;
	u256 nonce;
};

static INLINE
void serialize_u32(u8 *buffer, u32 value){
	buffer[0] = (value >> 0);
	buffer[1] = (value >> 8);
	buffer[2] = (value >> 16);
	buffer[3] = (value >> 24);
}

static INLINE
void serialize_u256(u8 *buffer, u256 value){
	memcpy(buffer, value.data, 32);
}

static
void print_buf(const char *debug_name, u8 *buf, i32 buflen){
	printf("buf (%s, len = %d):\n", debug_name, buflen);
	for(i32 i = 0; i < buflen; i += 1){
		if((i & 15) == 15)
			printf("%02X\n", buf[i]);
		else
			printf("%02X ", buf[i]);
	}
	printf("\n");
}

static
void init_state(blake2b_state *state, BlockHeader *header){
	// TODO: Init state without the nonce then add the nonce
	// after. This way we'll save the work of re-initializing
	// the whole BLAKE2B state.

	DEBUG_ASSERT(sizeof(BlockHeader) == 140);
	u8 buf[140];
	serialize_u32(buf + 0x00, header->version);
	serialize_u256(buf + 0x04, header->hash_prev_block);
	serialize_u256(buf + 0x24, header->hash_merkle_root);
	serialize_u256(buf + 0x44, header->hash_final_sapling_root);
	serialize_u32(buf + 0x64, header->time);
	serialize_u32(buf + 0x68, header->bits);
	serialize_u256(buf + 0x6C, header->nonce);

	print_buf("block_header", buf, 140);

	blake2b_init_btcz(state);
	blake2b_update(state, buf, 140);
}

void generate_hash(blake2b_state *base_state, u32 index, u8 *out, i32 outlen){
	blake2b_state state = *base_state;
	u32 le_index = index; // host_to_le_32(index);
	blake2b_update(&state, (u8*)&le_index, 4);
	blake2b_final(&state, out, outlen);
}

static
i32 hexdigit(u8 c){
	// TODO: turn into a look up table
	if(c >= '0' && c <= '9'){
		return c - '0';
	}else if(c >= 'A' && c <= 'F'){
		return 0x0A + c - 'A';
	}else if(c >= 'a' && c <= 'f'){
		return 0x0A + c - 'a';
	}else{
		return -1;
	}
}

static
void hex_to_buffer_le(const char *hex, u8 *buf, i32 buflen){
	if(hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
		hex += 2;

	// now, to load `buf` in little endian order we need
	// to start from the end of the hex string
	const char *ptr = hex;
	while(hexdigit(*ptr) != -1)
		ptr += 1;
	ptr -= 1;

	memset(buf, 0, buflen);
	i32 i = 0;
	while(ptr >= hex && i < buflen){
		i32 c0 = hexdigit(*ptr--);
		i32 c1 = 0;
		if(ptr >= hex)
			c1 = hexdigit(*ptr--);
		DEBUG_ASSERT(c0 != -1 && c1 != -1);
		buf[i++] = (u8)(c1 << 4) | (u8)c0;
	}
}

static
void hex_to_buffer(const char *hex, u8 *buf, i32 buflen){
	if(hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
		hex += 2;

	memset(buf, 0, buflen);
	const char *ptr = hex;
	i32 i = 0;
	while(*ptr && i < buflen){
		i32 c0 = hexdigit(*ptr++);
		i32 c1 = 0;
		if(*ptr){
			c1 = c0;
			c0 = hexdigit(*ptr++);
		}
		DEBUG_ASSERT(c0 != -1 && c1 != -1);
		buf[i++] = (u8)(c1 << 4) | (u8)c0;
	}
}

static
i32 count_hex_digits(const char *hex){
	if(hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
		hex += 2;
	i32 result = 0;
	while(hexdigit(*hex++) != -1)
		result += 1;
	return result;
}

int main(int argc, char **argv){
	// block = 818128
	i32 version = 4;
	char *hash_prev_block_hex = "0000007b753e415f80614ba8130aa4668ca4731b0539d9919c2074b43a46b9e8";
	char *hash_merkle_root_hex = "6b2198b49e2055535c403830a3c124a8c235004b4662901010bc0927c43979ec";
	char *hash_final_sapling_root_hex = "189df3ceb26643f3b90ec7059316c7ccb26aeaf1e96559c63b8c6d52f04e79b5";
	u32 time = 1632007626;
	u32 bits = 0x1e009cb8;
	char *nonce_hex = "81b601c200000000000000006dcdf558dd65a0dd9e68012952b8df1003cefade";
	char *solution_hex = "02969d2baea1d4f46df3ddfc40b270b99edba12611cdc547990c8225d18f09ab96da59fd028558e4ab5f6e6e7e1469c2723a089789e121944d2ee7a89f0f92187d821ddd9694eff1579ec92d52e3fd4ee4d0bb522f560c7378bbef28efa9fd39ff112128";

	DEBUG_ASSERT(count_hex_digits(hash_prev_block_hex) == 64);
	DEBUG_ASSERT(count_hex_digits(hash_merkle_root_hex) == 64);
	DEBUG_ASSERT(count_hex_digits(hash_final_sapling_root_hex) == 64);
	DEBUG_ASSERT(count_hex_digits(nonce_hex) == 64);
	DEBUG_ASSERT(count_hex_digits(solution_hex) == 200);

	blake2b_state base_state;
	BlockHeader block_header;
	block_header.version = version;
	hex_to_buffer_le(hash_prev_block_hex, block_header.hash_prev_block.data, 32);
	hex_to_buffer_le(hash_merkle_root_hex, block_header.hash_merkle_root.data, 32);
	hex_to_buffer_le(hash_final_sapling_root_hex, block_header.hash_final_sapling_root.data, 32);
	block_header.time = time;
	block_header.bits = bits;
	hex_to_buffer_le(nonce_hex, block_header.nonce.data, 32);
	init_state(&base_state, &block_header);

	u8 solution[100];
	u32 indices[32];
	u144 hashes[32];

	// NOTE: Why? The solution seems to be stored in big endian order.
	// But why? It took me days of reading the mess that is the BitcoinZ's
	// codebase. But now looking at it, it should be obvious. Solution is
	// an std::vector instead of a u256 in the block header. Because u256 is
	// stored in little endian I thought for some reason that the solution
	// would be stored in the same fashion. The codebase has so many levels
	// of abstraction it is hard to keep track of the details.
	hex_to_buffer(solution_hex, solution, 100);
	expand_indices_to_u32(solution, 100, indices, sizeof(indices), 25);
	for(i32 i = 0; i < 32; i += 1){
		LOG("indices[%d] = %u\n", i, indices[i]);
		u8 hash[BTCZ_BLAKE_OUTLEN];
		generate_hash(&base_state, indices[i] / 3, hash, BTCZ_BLAKE_OUTLEN);
		memcpy(hashes[i].data, hash + (indices[i] % 3) * 18, 18);
		//expand_indices(hash + (indices[i] % 3) * 18, 18, hashes[i].data, 18, 24, 0);
	}

#if 0
	u144 xor = hashes[0];
	for(i32 i = 1; i < 32; i += 1)
		xor = xor ^ hashes[i];
	print_buf("xor", xor.data, 18);
	for(i32 i = 0; i < 32; i += 2){
		i32 num_collisions = 0;
		for(i32 j = 0; j < 18; j += 1){
			if(hashes[i].data[j] == hashes[i + 1].data[j])
				num_collisions += 1;
		}

		LOG("pair = (%d, %d), num_collisions = %d\n", i, i + 1, num_collisions);
		LOG("indices[%d] < indices[%d] == %s\n", i, i + 1,
			indices[i] < indices[i + 1] ? "yes" : "no");
	}
#endif

	for(i32 stage = 0; stage < 4; stage += 1){
		i32 n = (1 << stage);
		for(i32 i = 0; i < 32; i += 2 * n){
			i32 cur = i;
			i32 next = i + n;
			hashes[cur] ^= hashes[next];

			i32 num_collisions = 0;
			for(i32 j = 3 * stage; j < 3 * (stage + 1); j += 1){
				if(hashes[cur].data[j] == 0x00)
					num_collisions += 1;
			}

			LOG("stage = %d, pair = (%d, %d), num_collisions = %d\n",
				stage, cur, next, num_collisions);

			for(i32 j = 0; j < (next - cur); j += 1){
				if(indices[cur + j] < indices[next + j])
					LOG("\tindices[%d] < indices[%d]\n", cur + j, next + j);
				else if(indices[cur + j] > indices[next + j])
					LOG("\tindices[%d] > indices[%d]\n", cur + j, next + j);
				else
					LOG("\tindices[%d] = indices[%d]\n", cur + j, next + j);
			}
		}
	}

	{
		i32 cur = 0;
		i32 next = 16;
		hashes[cur] ^= hashes[next];

		i32 num_collisions = 0;
		for(i32 j = 12; j < 18; j += 1){
			if(hashes[0].data[j] == 0x00)
				num_collisions += 1;
		}
		LOG("stage = 4, pair = (0, 16), num_collisions = %d\n", num_collisions);
		for(i32 j = 0; j < 16; j += 1){
			if(indices[cur + j] < indices[next + j])
				LOG("\tindices[%d] < indices[%d]\n", cur + j, next + j);
			else if(indices[cur + j] > indices[next + j])
				LOG("\tindices[%d] > indices[%d]\n", cur + j, next + j);
			else
				LOG("\tindices[%d] = indices[%d]\n", cur + j, next + j);
		}

		print_buf("xor", hashes[cur].data, 18);
	}
}
#endif
