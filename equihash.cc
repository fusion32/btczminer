// TODO: Add a description of the equihash algorithm.

#include "common.hh"

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
	//encode_u32_le(buffer, value);
}

static INLINE
void serialize_u256(u8 *buffer, u256 value){
	memcpy(buffer, value.data, 32);

	//for(i32 i = 0; i < 8; i += 1)
	//	encode_u32_le(buffer + i * 4, value.data[i]);
}

static
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

static
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

	blake2b_init_eh(state, EH_PERSONAL, EH_N, EH_K);
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
int main_eh_test(int argc, char **argv){
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
	hex_to_buffer_inv(hash_prev_block_hex, block_header.hash_prev_block.data, 32);
	hex_to_buffer_inv(hash_merkle_root_hex, block_header.hash_merkle_root.data, 32);
	hex_to_buffer_inv(hash_final_sapling_root_hex, block_header.hash_final_sapling_root.data, 32);
	block_header.time = time;
	block_header.bits = bits;
	hex_to_buffer_inv(nonce_hex, block_header.nonce.data, 32);
	init_state(&base_state, &block_header);

	equihash_solve(&base_state);

	u8 solution[100];
	hex_to_buffer(solution_hex, solution, 100);
	LOG("solution = %d\n", equihash_check_solution(&base_state, solution));
	return 0;
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
	DEBUG_ASSERT(p1->num_hash_digits > 0 && p1->num_indices > 0);
	DEBUG_ASSERT(p1->indices[0] != p2->indices[0]);

	i32 num_hash_digits = p1->num_hash_digits - 1;
	i32 prev_num_indices = p1->num_indices;
	i32 num_indices = prev_num_indices * 2;
	DEBUG_ASSERT(num_indices > 0 && num_indices <= (EH_PROOF_INDICES / 2));

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
	DEBUG_ASSERT(p1->num_hash_digits > 0 && p1->num_indices > 0);
	DEBUG_ASSERT(p1->indices[0] != p2->indices[0]);

	i32 prev_num_indices = p1->num_indices;
	i32 num_indices = prev_num_indices * 2;
	DEBUG_ASSERT(num_indices == EH_PROOF_INDICES);

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
	// NOTE: Doing some probability analysis, the output of each stage
	// should contain around the same number of inputs. Because there
	// can be cases where we get more outputs than inputs, we need to
	// add some extra room.

	// TODO: The other workaround would be to allocate a large chunk of virtual
	// memory and manually commit pages as we need them. This is simpler to
	// do on Linux where the kernel only assigns memory pages when you touch
	// the memory but requires extra steps on Windows with VirtualAlloc(MEM_COMMIT).

	float extra_room = 1.05f; // 5% should work for now
	i32 total_slots = (i32)(EH_DOMAIN * extra_room);
	PartialJoin *partial = (PartialJoin*)malloc(total_slots * sizeof(PartialJoin));
	PartialJoin *aux = (PartialJoin*)malloc(total_slots * sizeof(PartialJoin));

	i32 num_partial = 0;
	for(i32 i = 0; num_partial < EH_DOMAIN; i += 1){
		u8 hash[EH_BLAKE_OUTLEN];
		generate_hash(base_state, i, hash, EH_BLAKE_OUTLEN);
		for(i32 j = 0; j < EH_HASHES_PER_BLAKE && num_partial < EH_DOMAIN; j += 1){
			i32 index = num_partial++;
			DEBUG_ASSERT((index / EH_HASHES_PER_BLAKE) == i);
			DEBUG_ASSERT((index % EH_HASHES_PER_BLAKE) == j);
			PartialJoin *cur = &partial[index];

			cur->num_hash_digits = EH_HASH_DIGITS;
			unpack_uints(EH_HASH_DIGIT_BITS,
				hash + j * EH_HASH_BYTES, EH_HASH_BYTES,
				cur->hash_digits, EH_HASH_DIGITS);

			cur->num_indices = 1;
			cur->indices[0] = index;
		}
	}

	for(i32 digit = 0; digit < (EH_HASH_DIGITS - 2); digit += 1){
		LOG("digit %d - start\n", digit);

		eh_merge_sort(partial, aux, num_partial);

		LOG("digit %d - sorted\n", digit);
	
		i32 num_aux = 0;
		for(i32 i = 0; i < (num_partial - 1);){
			// NOTE: The list is sorted so we only need to check subsequent
			// elements. If N elements have the same first digit, we need to
			// consider all their combinations (without repetition) which should
			// yield (N choose 2) pairs.

			i32 j = 1;
			while((i + j) < num_partial
			  && (partial[i].hash_digits[0] == partial[i + j].hash_digits[0])){
				j += 1;
			}

			for(i32 m = 0; m < (j - 1); m += 1){
				for(i32 n = m + 1; n < j; n += 1){
					if(partial_distinct_indices(&partial[i + m], &partial[i + n]))
						aux[num_aux++] = partial_join(&partial[i + m], &partial[i + n]);
				}
			}
			i += j;
		}

		LOG("digit %d - end (num_partial = %d, num_aux = %d)\n",
			digit, num_partial, num_aux);

		num_partial = num_aux;
		memcpy(partial, aux, num_partial * sizeof(PartialJoin));
	}

	// TODO: We should fix the sorting method here to consider both
	// digits at this stage. We can still find the solution with the
	// block we're currently testing but this may cause us to miss
	// solutions in other cases.

	LOG("last two digits - start\n");

	eh_merge_sort(partial, aux, num_partial);

	LOG("last two digits - sorted\n");

	i32 num_results = 0;
	FinalJoin results[16];
	for(i32 i = 0; i < num_partial;){
		i32 j = 1;
		while((i + j) < num_partial
			&& (partial[i].hash_digits[0] == partial[i + j].hash_digits[0])
			&& (partial[i].hash_digits[1] == partial[i + j].hash_digits[1])){
			j += 1;
		}

		for(i32 m = 0; m < (j - 1); m += 1){
			for(i32 n = m + 1; n < j; n += 1){
				if(partial_distinct_indices(&partial[i + m], &partial[i + n])){
					results[num_results++] = final_join(&partial[i + m], &partial[i + n]);
				}
			}
		}
		i += j;
	}

	LOG("num_results = %d\n", num_results);
	for(i32 i = 0; i < num_results; i += 1){
		LOG("proof #%d:\n", i);
		for(i32 j = 0; j < EH_PROOF_INDICES; j += 1){
			LOG("\t[%d] = %u\n", j, results[i].indices[j]);
		}

		u8 solution[EH_PACKED_PROOF_BYTES];
		pack_uints(EH_PROOF_INDEX_BITS,
			results[i].indices, EH_PROOF_INDICES,
			solution, EH_PACKED_PROOF_BYTES);
		print_buf("solution", solution, EH_PACKED_PROOF_BYTES);
	}

	free(partial);
	free(aux);
}

bool equihash_check_solution(blake2b_state *base_state, u8 *solution){
	u32 indices[EH_PROOF_INDICES];
	unpack_uints(EH_PROOF_INDEX_BITS,
		solution, EH_PACKED_PROOF_BYTES,
		indices, EH_PROOF_INDICES);

	PartialJoin partial[EH_PROOF_INDICES];
	for(i32 i = 0; i < EH_PROOF_INDICES; i += 1){
		u8 hash[EH_BLAKE_OUTLEN];

		i32 j = indices[i] / EH_HASHES_PER_BLAKE;
		i32 k = indices[i] % EH_HASHES_PER_BLAKE;

		generate_hash(base_state, j, hash, EH_BLAKE_OUTLEN);

		partial[i].num_hash_digits = EH_HASH_DIGITS;
		unpack_uints(EH_HASH_DIGIT_BITS,
			hash + k * EH_HASH_BYTES, EH_HASH_BYTES,
			partial[i].hash_digits, EH_HASH_DIGITS);

		partial[i].num_indices = 1;
		partial[i].indices[0] = indices[i];
	}

	i32 num_partial = EH_PROOF_INDICES;
	PartialJoin aux[EH_PROOF_INDICES];
	for(i32 digit = 0; digit < (EH_HASH_DIGITS - 2); digit += 1){
		i32 num_aux = 0;
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

	DEBUG_ASSERT(num_partial == 2);
	if(!(partial[0].hash_digits[0] == partial[1].hash_digits[0])
	  && !(partial[0].hash_digits[1] == partial[1].hash_digits[1]))
		return false;
	if(!partial_distinct_indices(&partial[0], &partial[1]))
		return false;
	if(!(partial[0].indices[0] < partial[1].indices[0]))
		return false;

#if 0
	// TODO: Remove.
	FinalJoin result = final_join(&partial[0], &partial[1]);
	for(i32 i = 0; i < EH_PROOF_INDICES; i += 1){
		LOG("result.indices[%d] = %d, indices[%d] = %u, equal = %s\n",
			i, result.indices[i], i, indices[i],
			(result.indices[i] == indices[i]) ? "yes" : "no");
	}
#endif

	return true;
}
