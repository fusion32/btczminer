// TODO: Add a description of the equihash algorithm.

#include "common.hh"

struct u256{
	// NOTE: `data` is encoded in little endian order.
	u8 data[32];
};

static
bool operator>(const u256 &a, const u256 &b){
	for(i32 i = 31; i >= 0; i -= 1){
		if(a.data[i] > b.data[i])
			return true;
		if(a.data[i] < b.data[i])
			return false;
	}
	return false;
}

static
bool operator==(const u256 &a, const u256 &b){
	for(i32 i = 0; i < 32; i += 1){
		if(a.data[i] != b.data[i])
			return false;
	}
	return true;
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
	buffer[0] = (u8)(value >> 0);
	buffer[1] = (u8)(value >> 8);
	buffer[2] = (u8)(value >> 16);
	buffer[3] = (u8)(value >> 24);
}

static INLINE
void serialize_u256(u8 *buffer, u256 value){
	memcpy(buffer, value.data, 32);
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


void pack_uints(i32 uint_bits,
		u32 *unpacked, i32 num_unpacked,
		u8 *packed, i32 packed_len){
	// NOTE: This seems to be a restriction on equihash
	// but also on having a 32-bits bitbuffer.
	DEBUG_ASSERT(uint_bits >= 8 && uint_bits <= 25);

	i32 uint_bytes = BITS_TO_BYTES(uint_bits);

	// NOTE: Make sure `packed` has enough room to receive the
	// packed data.
	i32 num_uints = BYTES_TO_BITS(packed_len) / uint_bits;
	DEBUG_ASSERT(num_unpacked == num_uints);

	// NOTE: Bytes in the packed buffer are stored
	// in big endian order.
	u32 write_mask = (1 << uint_bits) - 1;
	u32 bitbuffer = 0;
	i32 bitcount = 0;
	for(i32 i = 0; i < packed_len; i += 1){
		if(bitcount < 8){
			// read an entire uint into the bitbuffer
			bitcount += uint_bits;
			bitbuffer <<= uint_bits;
			bitbuffer |= *unpacked & write_mask;
			unpacked += 1;
		}

		bitcount -= 8;
		packed[i] = (u8)(bitbuffer >> bitcount);
	}
}

void unpack_uints(i32 uint_bits,
		u8 *packed, i32 packed_len,
		u32 *unpacked, i32 num_unpacked){
	// NOTE: This seems to be a restriction on equihash
	// but also on having a 32-bits bitbuffer.
	DEBUG_ASSERT(uint_bits >= 8 && uint_bits <= 25);

	// NOTE: Make sure `unpacked` has enough room to receive
	// the unpacked data.
	i32 num_uints = BYTES_TO_BITS(packed_len) / uint_bits;
	DEBUG_ASSERT(num_unpacked == num_uints);

	// NOTE: Bytes in the packed buffer are stored
	// in big endian order.
	u32 read_mask = (1 << uint_bits) - 1;
	u32 bitbuffer = 0;
	i32 bitcount = 0;
	for(i32 i = 0; i < packed_len; i += 1){
		bitbuffer = (bitbuffer << 8) | packed[i];
		bitcount += 8;
		if(bitcount >= uint_bits){
			bitcount -= uint_bits;
			DEBUG_ASSERT(bitcount < 8);
			*unpacked = (bitbuffer >> bitcount) & read_mask;
			unpacked += 1;
		}
	}
}

struct u144{
	// NOTE: `data` is encoded in little endian order.
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

void equihash_solve(blake2b_state *base_state);
bool equihash_check_solution(blake2b_state *base_state, u8 *solution);
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

	//equihash_solve(&base_state);

	u8 solution[100];
	hex_to_buffer(solution_hex, solution, 100);
	LOG("solution = %d\n", equihash_check_solution(&base_state, solution));
	return 0;

#if 0
	u8 solution[100];
	u32 indices[32];
	//ZHashDigits hashes[32];
	u144 hashes[32];

	// NOTE: Why? The solution seems to be stored in big endian order.
	// But why? It took me days of reading the mess that is the BitcoinZ's
	// codebase. But now looking at it, it should be obvious. Solution is
	// an std::vector instead of a u256 in the block header. Because u256 is
	// stored in little endian I thought for some reason that the solution
	// would be stored in the same fashion. The codebase has so many levels
	// of abstraction it is hard to keep track of the details.
	hex_to_buffer(solution_hex, solution, 100);
	unpack_uints(25, solution, 100, indices, NARRAY(indices));

#if 0
	pack_uints(25, indices, NARRAY(indices), solution, 100);
	unpack_uints(25, solution, 100, indices, NARRAY(indices));
#endif

	for(i32 i = 0; i < 32; i += 1){
		LOG("indices[%d] = %u\n", i, indices[i]);
		u8 hash[BTCZ_BLAKE_OUTLEN];
		generate_hash(&base_state, indices[i] / 3, hash, BTCZ_BLAKE_OUTLEN);
		//hashes[i] = make_zhash_digits(hash + (indices[i] % 3) * 18, 18);
		memcpy(hashes[i].data, hash + (indices[i] % 3) * 18, 18);

		//u32 hash_offset = (indices[i] % BTCZ_HASHES_PER_BLAKE) * BTCZ_HASH_BYTES;
		//unpack_uints(BTCZ_HASH_DIGIT_BITS,
		//	hash + hash_offset, BTCZ_HASH_BYTES,
		//	hash_digits, BTC_HASH_DIGITS);
	}

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
#endif
}

static
void eh__merge_sort_aux(
		PartialJoin *array, PartialJoin *aux,
		i32 first, i32 last){
	i32 num = last - first + 1;
	if(num <= 1){
		return;
	}else if(num == 2){
		if(array[last].hash_digits[0] < array[first].hash_digits[0]){
			PartialJoin tmp = array[first];
			array[first] = array[last];
			array[last] = tmp;
		}
		return;
	}

	i32 mid = (first + last) / 2;
	i32 half1_first = first;
	i32 half1_last = mid;
	i32 half2_first = mid + 1;
	i32 half2_last = last;
	memcpy(aux + first, array + first, sizeof(PartialJoin) * num);
	eh__merge_sort_aux(aux, array, half1_first, half1_last);
	eh__merge_sort_aux(aux, array, half2_first, half2_last);

	i32 ptr1 = half1_first;
	i32 ptr2 = half2_first;
	i32 ptr = first;
	while(1){
		if(ptr1 > half1_last){
			// first half is empty so just copy the remaining of
			// the second half to the sorted list
			memcpy(array + ptr, aux + ptr2,
				sizeof(PartialJoin) * (half2_last - ptr2 + 1));
			break;
		}else if(ptr2 > half2_last){
			// second half is empty so just copy the remaining of
			// the first half to the sorted list
			memcpy(array + ptr, aux + ptr1,
				sizeof(PartialJoin) * (half1_last - ptr1 + 1));
			break;
		}else{
			if(aux[ptr1].hash_digits[0] < aux[ptr2].hash_digits[0]){
				array[ptr] = aux[ptr1];
				ptr1 += 1;
				ptr += 1;
			}else{
				array[ptr] = aux[ptr2];
				ptr2 += 1;
				ptr += 1;
			}
		}
	}
}

static
void eh_merge_sort(PartialJoin *array, PartialJoin *aux, i32 num){
	eh__merge_sort_aux(array, aux, 0, num - 1);
}

bool partial_distinct_indices(PartialJoin *p1, PartialJoin *p2){
	// TODO: We can reduce the number of comparissons if we keep
	// indices sorted.

	DEBUG_ASSERT(p1->num_indices == p2->num_indices);
	i32 num_indices = p1->num_indices;
	for(i32 i = 0; i < num_indices; i += 1){
		for(i32 j = 0; j < num_indices; j += 1){
			if(p1->indices[i] == p2->indices[j])
				return false;
		}
	}
	return true;
}

PartialJoin partial_join(PartialJoin *p1, PartialJoin *p2){
	DEBUG_ASSERT(p1->num_hash_digits == p2->num_hash_digits);
	DEBUG_ASSERT(p1->num_indices == p2->num_indices);

	i32 num_hash_digits = p1->num_hash_digits - 1;
	i32 prev_num_indices = p1->num_indices;
	i32 num_indices = prev_num_indices * 2;
	DEBUG_ASSERT(num_indices <= BTCZ_PROOF_INDICES / 2);

	PartialJoin result;

	result.num_hash_digits = num_hash_digits;
	for(i32 i = 0; i < num_hash_digits; i += 1){
		result.hash_digits[i] =
			p1->hash_digits[i + 1] ^ p2->hash_digits[i + 1];
	}

	result.num_indices = num_indices;
	if(p1->indices[0] < p2->indices[0]){
		for(i32 i = 0; i < prev_num_indices; i += 1){
			result.indices[i] = p1->indices[i];
			result.indices[i + prev_num_indices] = p2->indices[i];
		}
	}else{
		for(i32 i = 0; i < prev_num_indices; i += 1){
			result.indices[i] = p2->indices[i];
			result.indices[i + prev_num_indices] = p1->indices[i];
		}
	}

	return result;
}

FinalJoin final_join(PartialJoin *p1, PartialJoin *p2){
	DEBUG_ASSERT(p1->num_hash_digits == p2->num_hash_digits);
	DEBUG_ASSERT(p1->num_indices == p2->num_indices);

	i32 prev_num_indices = p1->num_indices;
	i32 num_indices = prev_num_indices * 2;
	DEBUG_ASSERT(num_indices == BTCZ_PROOF_INDICES);

	FinalJoin result;
	if(p1->indices[0] < p2->indices[0]){
		for(i32 i = 0; i < prev_num_indices; i += 1){
			result.indices[i] = p1->indices[i];
			result.indices[i + prev_num_indices] = p2->indices[i];
		}
	}else{
		for(i32 i = 0; i < prev_num_indices; i += 1){
			result.indices[i] = p2->indices[i];
			result.indices[i + prev_num_indices] = p1->indices[i];
		}
	}
	return result;
}

void equihash_solve(blake2b_state *base_state){
	i32 num_partial = BTCZ_DOMAIN + BTCZ_HASHES_PER_BLAKE;
	PartialJoin *partial = (PartialJoin*)malloc(num_partial * sizeof(PartialJoin));
	PartialJoin *aux = (PartialJoin*)malloc(num_partial * sizeof(PartialJoin));

	i32 num_results = 0;
	FinalJoin results[16];

	for(i32 i = 0; i < (num_partial / BTCZ_HASHES_PER_BLAKE); i += 1){
		u8 hash[BTCZ_BLAKE_OUTLEN];
		generate_hash(base_state, i, hash, BTCZ_BLAKE_OUTLEN);
		for(i32 j = 0; j < BTCZ_HASHES_PER_BLAKE; j += 1){
			i32 index = i * BTCZ_HASHES_PER_BLAKE + j;
			PartialJoin *cur = &partial[index];
			cur->num_hash_digits = BTCZ_HASH_DIGITS;
			unpack_uints(BTCZ_HASH_DIGIT_BITS,
				hash + j * BTCZ_HASH_BYTES, BTCZ_HASH_BYTES,
				cur->hash_digits, BTCZ_HASH_DIGITS);

#if 0
			// TODO: Remove. I was testing if the order was
			// different.
			for(i32 k = 0; k < BTCZ_HASH_DIGITS / 2; k += 1){
				i32 l = BTCZ_HASH_DIGITS - 1 - k;
				u32 tmp = cur->hash_digits[k];
				cur->hash_digits[k] = cur->hash_digits[l];
				cur->hash_digits[l] = tmp;
			}
#endif

			cur->num_indices = 1;
			cur->indices[0] = index;
		}
	}
	num_partial -= BTCZ_HASHES_PER_BLAKE;

	for(i32 digit = 0; digit < (BTCZ_HASH_DIGITS - 2); digit += 1){
		LOG("digit %d - start\n", digit);

		eh_merge_sort(partial, aux, num_partial);

		LOG("digit %d - sorted\n", digit);
	
		i32 num_aux = 0;
		for(i32 i = 0; i < num_partial;){
			i32 j = 1;
			while((i + j) < num_partial){
				if(partial[i].hash_digits[0] != partial[i + j].hash_digits[0])
					break;
				if(partial_distinct_indices(&partial[i], &partial[i + j]))
					aux[num_aux++] = partial_join(&partial[i], &partial[i + j]);
				j += 1;
			}
			i += j;
		}

		LOG("digit %d - end (num_partial = %d, num_aux = %d)\n",
			digit, num_partial, num_aux);

		num_partial = num_aux;
		memcpy(partial, aux, sizeof(PartialJoin) * num_aux);
	}

	for(i32 i = 0; i < num_partial;){
		i32 j = 1;
		while((i + j) < num_partial){
			if(partial[i].hash_digits[0] != partial[i + j].hash_digits[0]
			  || partial[i].hash_digits[1] != partial[i + j].hash_digits[1])
				break;
			if(partial_distinct_indices(&partial[i], &partial[i + j]))
				results[num_results++] = final_join(&partial[i], &partial[i + j]);
			j += 1;
		}
		i += j;
	}

	LOG("num_results = %d\n", num_results);
	for(i32 i = 0; i < num_results; i += 1){
		LOG("proof #%d:\n", i);
		for(i32 j = 0; j < BTCZ_PROOF_INDICES; j += 1){
			LOG("\t%08X\n", results[i].indices[j]);
		}
	}

	free(partial);
	free(aux);
}

bool equihash_check_solution(blake2b_state *base_state, u8 *solution){
	u32 indices[BTCZ_PROOF_INDICES];
	unpack_uints(BTCZ_PROOF_INDEX_BITS,
		solution, BTCZ_PACKED_PROOF_BYTES,
		indices, BTCZ_PROOF_INDICES);

	PartialJoin partial[BTCZ_PROOF_INDICES];
	for(i32 i = 0; i < BTCZ_PROOF_INDICES; i += 1){
		u8 hash[BTCZ_BLAKE_OUTLEN];
		generate_hash(base_state, indices[i] / 3, hash, BTCZ_BLAKE_OUTLEN);

		partial[i].num_hash_digits = BTCZ_HASH_DIGITS;
		unpack_uints(BTCZ_HASH_DIGIT_BITS,
			hash + (indices[i] % 3) * BTCZ_HASH_BYTES, BTCZ_HASH_BYTES,
			partial[i].hash_digits, BTCZ_HASH_DIGITS);

		partial[i].num_indices = 1;
		partial[i].indices[0] = indices[i];
	}

	i32 num_partial = BTCZ_PROOF_INDICES;
	i32 num_aux = 0;
	PartialJoin aux[BTCZ_PROOF_INDICES];
	for(i32 digit = 0; digit < (BTCZ_HASH_DIGITS - 2); digit += 1){
		num_aux = 0;
		for(i32 i = 0; i < num_partial; i += 2){
			if(!(partial[i].hash_digits[0] == partial[i + 1].hash_digits[0]))
				return false;
			if(!partial_distinct_indices(&partial[i], &partial[i + 1]))
				return false;
			if(!(partial[i].indices[0] < partial[i + 1].indices[0]))
				return false;
			aux[num_aux++] = partial_join(&partial[i], &partial[i + 1]);
		}

		DEBUG_ASSERT(num_aux == (num_partial / 2));
		num_partial = num_aux;
		memcpy(partial, aux, num_aux * sizeof(PartialJoin));
	}

	DEBUG_ASSERT(num_aux == 2);
	if(!(partial[0].hash_digits[0] == partial[1].hash_digits[0])
	  && !(partial[0].hash_digits[1] == partial[1].hash_digits[1]))
		return false;
	if(!partial_distinct_indices(&partial[0], &partial[1]))
		return false;
	if(!(partial[0].indices[0] < partial[1].indices[0]))
		return false;

	return true;
}
