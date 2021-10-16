// TODO: Add a description of the equihash algorithm.

#include "common.hh"
#include "buffer_util.hh"

// TODO: PartialJoin is a weird name for this but StepRow
// isn't any good either. Come up with something else.
struct PartialJoin{
	// TODO: Both hash_digits and indices can be packed on the same
	// array. This could lead to using dynamic memory instead of a
	// static size.

	i32 num_hash_digits;
	u32 hash_digits[EH_HASH_DIGITS];

	i32 num_indices;
	u32 indices[EH_SOLUTION_INDICES / 2];
};

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

void generate_hash(blake2b_state *base_state, u32 index, u8 *out, i32 outlen){
	blake2b_state state = *base_state;
	u32 le_index = u32_cpu_to_le(index);
	blake2b_update(&state, (u8*)&le_index, 4);
	blake2b_final(&state, out, outlen);
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

static
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

static
PartialJoin partial_join(PartialJoin *p1, PartialJoin *p2){
	DEBUG_ASSERT(p1->num_hash_digits == p2->num_hash_digits);
	DEBUG_ASSERT(p1->num_indices == p2->num_indices);
	DEBUG_ASSERT(p1->num_hash_digits > 0 && p1->num_indices > 0);
	DEBUG_ASSERT(p1->indices[0] != p2->indices[0]);

	i32 num_hash_digits = p1->num_hash_digits - 1;
	i32 prev_num_indices = p1->num_indices;
	i32 num_indices = prev_num_indices * 2;
	DEBUG_ASSERT(num_indices > 0 && num_indices <= (EH_SOLUTION_INDICES / 2));

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

static
void final_join(PartialJoin *p1, PartialJoin *p2, u32 *out_indices){
	DEBUG_ASSERT(p1->num_hash_digits == p2->num_hash_digits);
	DEBUG_ASSERT(p1->num_indices == p2->num_indices);
	DEBUG_ASSERT(p1->num_hash_digits > 0 && p1->num_indices > 0);
	DEBUG_ASSERT(p1->indices[0] != p2->indices[0]);

	i32 prev_num_indices = p1->num_indices;
	i32 num_indices = prev_num_indices * 2;
	DEBUG_ASSERT(num_indices == EH_SOLUTION_INDICES);

	if(p1->indices[0] < p2->indices[0]){
		for(i32 i = 0; i < prev_num_indices; i += 1){
			out_indices[i] = p1->indices[i];
			out_indices[i + prev_num_indices] = p2->indices[i];
		}
	}else{
		for(i32 i = 0; i < prev_num_indices; i += 1){
			out_indices[i] = p2->indices[i];
			out_indices[i + prev_num_indices] = p1->indices[i];
		}
	}
}

i32 eh_solve(blake2b_state *base_state, EH_Solution *sol_buffer, i32 max_sols){
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

	i32 num_sols = 0;
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
					u32 indices[EH_SOLUTION_INDICES];
					final_join(&partial[i + m], &partial[i + n], indices);
					if(num_sols < max_sols){
						pack_uints(EH_SOLUTION_INDEX_BITS,
							indices, EH_SOLUTION_INDICES,
							sol_buffer[num_sols].packed, EH_PACKED_SOLUTION_BYTES);
					}
					num_sols += 1;
				}
			}
		}
		i += j;
	}

	free(partial);
	free(aux);
	return num_sols;
}

bool eh_check_solution(blake2b_state *base_state, EH_Solution *solution){
	u32 indices[EH_SOLUTION_INDICES];
	unpack_uints(EH_SOLUTION_INDEX_BITS,
		solution->packed, EH_PACKED_SOLUTION_BYTES,
		indices, EH_SOLUTION_INDICES);

	PartialJoin partial[EH_SOLUTION_INDICES];
	for(i32 i = 0; i < EH_SOLUTION_INDICES; i += 1){
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

	i32 num_partial = EH_SOLUTION_INDICES;
	PartialJoin aux[EH_SOLUTION_INDICES];
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
