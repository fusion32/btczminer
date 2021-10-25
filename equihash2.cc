
#include "common.hh"
#include "buffer_util.hh"
#include "thread.hh"

#define	EH_BUCKET_BITS			((EH_HASH_DIGIT_BITS * 3) / 5)
#define EH_BUCKET_MASK			((1 << EH_BUCKET_BITS) - 1)
#define	EH_NUM_BUCKETS			(1 << EH_BUCKET_BITS)

// NOTE: We could increase the number of max bucket slots by a
// percentage but it seems that if we discard some of the
// collisions we'll still be able to find most of the solutions.
//#define EH_MAX_BUCKET_SLOTS		(EH_RANGE / EH_NUM_BUCKETS)

// NOTE2: If we increase the number of max bucket slots by 5% we'll
// discard almost no collisions and will find more solutions than
// if we don't.
#define EH_MAX_BUCKET_SLOTS		((i32)(1.05f * (EH_RANGE / EH_NUM_BUCKETS)))

struct EH_Slot{
	// TODO: This uses too much memory. After we get the new
	// algorithm working we should reduce this.
	i32 num_hash_digits;
	u32 hash_digits[EH_HASH_DIGITS];
	i32 num_indices;
	u32 indices[EH_SOLUTION_INDICES/2];
};

struct EH_State{
	blake2b_state *base_state;
	i32 num_threads;
	i32 *num_bucket_slots[2];
	EH_Slot *slots[2];
	i32 max_sols;
	i32 num_sols;
	EH_Solution *sol_buffer;

	// statistics
	i32 num_discarded_hashes;
	i32 num_discarded_collisions;
	i32 num_discarded_solutions;
};

struct EH_ThreadContext{
	EH_State *eh;
	barrier_t *barrier;
	i32 thread_id;
	thread_t thread_handle;
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

static
void eh_generate_blake(blake2b_state *base_state,
		i32 generator, u8 *out, i32 outlen){
	u32 le_generator = u32_cpu_to_le(generator);
	blake2b_state extended_state = *base_state;
	blake2b_update(&extended_state, (u8*)&le_generator, 4);
	blake2b_final(&extended_state, out, outlen);
}

static
EH_Slot *eh_push_bucket_slot(EH_Slot *slots, i32 *num_bucket_slots, i32 bucket_id){
	i32 slot_id = atomic_add(&num_bucket_slots[bucket_id], 1);
	if(slot_id >= EH_MAX_BUCKET_SLOTS)
		return NULL;
	return slots + bucket_id * EH_MAX_BUCKET_SLOTS + slot_id;
}

static
EH_Slot *eh_get_bucket(EH_Slot *slots, i32 bucket_id){
	return slots + bucket_id * EH_MAX_BUCKET_SLOTS;
}

static
i32 eh_get_num_bucket_slots(i32 *num_bucket_slots, i32 bucket_id){
	i32 result = atomic_exchange(&num_bucket_slots[bucket_id], 0);
	//LOG("bucket_id = %d, num_slots = %d\n", bucket_id, result);
	if(result > EH_MAX_BUCKET_SLOTS)
		result = EH_MAX_BUCKET_SLOTS;
	return result;
}

static
EH_Solution *eh_push_solution(EH_State *eh){
	i32 sol_slot_id = atomic_add(&eh->num_sols, 1);
	if(sol_slot_id >= eh->max_sols)
		return NULL;
	return eh->sol_buffer + sol_slot_id;
}

static
void eh_solve_init(EH_State *eh, i32 thread_id,
		EH_Slot *output_slots, i32 *output_num_bucket_slots){
	i32 num_blakes = (EH_RANGE + EH_HASHES_PER_BLAKE - 1) / EH_HASHES_PER_BLAKE;
	for(i32 i = thread_id; i < num_blakes; i += eh->num_threads){
		u8 blake[EH_BLAKE_OUTLEN];
		eh_generate_blake(eh->base_state, i, blake, EH_BLAKE_OUTLEN);
		for(i32 j = 0; j < EH_HASHES_PER_BLAKE; j += 1){
			i32 index = EH_HASHES_PER_BLAKE * i + j;
			u32 hash_digits[EH_HASH_DIGITS];
			unpack_uints(EH_HASH_DIGIT_BITS,
				blake + j * EH_HASH_BYTES, EH_HASH_BYTES,
				hash_digits, EH_HASH_DIGITS);

			i32 bucket_id = hash_digits[0] & EH_BUCKET_MASK;
			EH_Slot *slot = eh_push_bucket_slot(output_slots,
					output_num_bucket_slots, bucket_id);
			if(!slot){
				atomic_add(&eh->num_discarded_hashes, 1);
				continue;
			}

			slot->num_hash_digits = EH_HASH_DIGITS;
			memcpy(slot->hash_digits, hash_digits, sizeof(hash_digits));
			slot->num_indices = 1;
			slot->indices[0] = index;

#if 0
			if(bucket_id == 0){
				LOG("bucket_id = 0, slot = %d, num_hash_digits = %d,"
					" hash_digits[0] = %08X\n", eh->num_bucket_slots[0] - 1,
					slot->num_hash_digits, slot->hash_digits[0]);
			}
#endif
		}
	}
}

static
int eh_slot_cmp_1(const void *p1, const void *p2){
	EH_Slot *a = (EH_Slot*)p1;
	EH_Slot *b = (EH_Slot*)p2;
	if(a->hash_digits[0] < b->hash_digits[0])
		return -1;
	else if(a->hash_digits[0] > b->hash_digits[0])
		return 1;
	return 0;
}

static
bool eh_distinct_indices(EH_Slot *a, EH_Slot *b){
	DEBUG_ASSERT(a->num_indices == b->num_indices);
	i32 num_indices = a->num_indices;
	for(i32 i = 0; i < num_indices; i += 1){
		for(i32 j = 0; j < num_indices; j += 1){
			if(a->indices[i] == b->indices[j])
				return false;
		}
	}
	return true;
}

static
EH_Slot eh_partial_join(EH_Slot *a, EH_Slot *b){
	DEBUG_ASSERT(a->num_hash_digits == b->num_hash_digits);
	DEBUG_ASSERT(a->num_indices == b->num_indices);
	DEBUG_ASSERT(a->num_hash_digits > 0 && a->num_indices > 0);
	DEBUG_ASSERT(a->indices[0] != b->indices[0]);

	i32 num_hash_digits = a->num_hash_digits - 1;
	i32 prev_num_indices = a->num_indices;
	i32 num_indices = prev_num_indices * 2;
	DEBUG_ASSERT(num_indices > 0 && num_indices <= (EH_SOLUTION_INDICES / 2));

	EH_Slot result;

	result.num_hash_digits = num_hash_digits;
	for(i32 i = 0; i < num_hash_digits; i += 1){
		result.hash_digits[i] =
			a->hash_digits[i + 1] ^ b->hash_digits[i + 1];
	}

	result.num_indices = num_indices;
	if(a->indices[0] < b->indices[0]){
		for(i32 i = 0; i < prev_num_indices; i += 1){
			result.indices[i] = a->indices[i];
			result.indices[i + prev_num_indices] = b->indices[i];
		}
	}else{
		for(i32 i = 0; i < prev_num_indices; i += 1){
			result.indices[i] = b->indices[i];
			result.indices[i + prev_num_indices] = a->indices[i];
		}
	}

	return result;
}

static
void eh_solve_one(EH_State *eh, i32 thread_id,
		EH_Slot *input_slots, i32 *input_num_bucket_slots,
		EH_Slot *output_slots, i32 *output_num_bucket_slots){
	// NOTE: Solve for collisions in input and store them in output.
	for(i32 bucket_id = thread_id;
			bucket_id < EH_NUM_BUCKETS;
			bucket_id += eh->num_threads){
		EH_Slot *slots = eh_get_bucket(input_slots, bucket_id);
		i32 num_slots = eh_get_num_bucket_slots(
				input_num_bucket_slots, bucket_id);

		qsort(slots, num_slots, sizeof(EH_Slot), eh_slot_cmp_1);

		i32 num_collisions = 0;
		for(i32 i = 0; i < (num_slots - 1);){
			i32 j = 1;
			while((i + j) < num_slots
			&& eh_slot_cmp_1(&slots[i], &slots[i + j]) == 0){
				j += 1;
			}

			for(i32 m = 0; m < (j - 1); m += 1){
				for(i32 n = m + 1; n < j; n += 1){
					if(eh_distinct_indices(&slots[i + m], &slots[i + n])){
						num_collisions += 1;
						EH_Slot join_result = eh_partial_join(&slots[i + m], &slots[i + n]);
						i32 out_bucket_id = join_result.hash_digits[0] & EH_BUCKET_MASK;
						EH_Slot *out_slot = eh_push_bucket_slot(output_slots,
								output_num_bucket_slots, out_bucket_id);
						if(!out_slot){
							atomic_add(&eh->num_discarded_collisions, 1);
							continue;
						}
						*out_slot = join_result;
					}
				}
			}

			i += j;
		}
	}
}

static
int eh_slot_cmp_2(const void *p1, const void *p2){
	EH_Slot *a = (EH_Slot*)p1;
	EH_Slot *b = (EH_Slot*)p2;
	if(a->hash_digits[0] < b->hash_digits[0])
		return -1;
	else if(a->hash_digits[0] > b->hash_digits[0])
		return 1;
	else if(a->hash_digits[1] < b->hash_digits[1])
		return -1;
	else if(a->hash_digits[1] > b->hash_digits[1])
		return 1;
	return 0;
}

static
void eh_last_join(EH_Slot *a, EH_Slot *b, u32 *out_indices){
	DEBUG_ASSERT(a->num_hash_digits == b->num_hash_digits);
	DEBUG_ASSERT(a->num_indices == b->num_indices);
	DEBUG_ASSERT(a->num_hash_digits > 0 && a->num_indices > 0);
	DEBUG_ASSERT(a->indices[0] != b->indices[0]);

	i32 prev_num_indices = a->num_indices;
	i32 num_indices = prev_num_indices * 2;
	DEBUG_ASSERT(num_indices == EH_SOLUTION_INDICES);

	if(a->indices[0] < b->indices[0]){
		for(i32 i = 0; i < prev_num_indices; i += 1){
			out_indices[i] = a->indices[i];
			out_indices[i + prev_num_indices] = b->indices[i];
		}
	}else{
		for(i32 i = 0; i < prev_num_indices; i += 1){
			out_indices[i] = b->indices[i];
			out_indices[i + prev_num_indices] = a->indices[i];
		}
	}
}

static
void eh_solve_last(EH_State *eh, i32 thread_id,
		EH_Slot *input_slots, i32 *input_num_bucket_slots){
	for(i32 bucket_id = thread_id;
			bucket_id < EH_NUM_BUCKETS;
			bucket_id += eh->num_threads){
		EH_Slot *slots = eh_get_bucket(input_slots, bucket_id);
		i32 num_slots = eh_get_num_bucket_slots(
				input_num_bucket_slots, bucket_id);

		qsort(slots, num_slots, sizeof(EH_Slot), eh_slot_cmp_2);

		for(i32 i = 0; i < (num_slots - 1);){
			i32 j = 1;
			while((i + j) < num_slots
			&& eh_slot_cmp_2(&slots[i], &slots[i + j]) == 0){
				j += 1;
			}

			for(i32 m = 0; m < (j - 1); m += 1){
				for(i32 n = m + 1; n < j; n += 1){
					if(eh_distinct_indices(&slots[i + m], &slots[i + n])){
						u32 sol_indices[EH_SOLUTION_INDICES];
						eh_last_join(&slots[i + m], &slots[i + n], sol_indices);

						EH_Solution *out_sol = eh_push_solution(eh);
						if(out_sol){
							pack_uints(EH_SOLUTION_INDEX_BITS,
								sol_indices, EH_SOLUTION_INDICES,
								out_sol->packed, EH_PACKED_SOLUTION_BYTES);
						}else{
							atomic_add(&eh->num_discarded_solutions, 1);
						}
					}
				}
			}

			i += j;
		}
	}
}

static
void eh_print_stats(EH_State *eh){
	LOG("\tnum_discarded_hashes = %d\n", eh->num_discarded_hashes);
	LOG("\tnum_discarded_collisions = %d\n", eh->num_discarded_collisions);
	LOG("\tnum_discarded_solutions = %d\n", eh->num_discarded_solutions);
}

static
void eh_worker_thread(void *arg){
	EH_ThreadContext *ctx = (EH_ThreadContext*)arg;
	eh_solve_init(ctx->eh, ctx->thread_id,
		ctx->eh->slots[0], ctx->eh->num_bucket_slots[0]);
	barrier_wait(ctx->barrier);
	for(i32 i = 0; i < (EH_HASH_DIGITS - 2); i += 1){
		if(ctx->thread_id == 0){
			LOG("starting digit %d\n", i);
			eh_print_stats(ctx->eh);
		}
		barrier_wait(ctx->barrier);

		if((i & 1) == 0){
			eh_solve_one(ctx->eh, ctx->thread_id,
				ctx->eh->slots[0], ctx->eh->num_bucket_slots[0],
				ctx->eh->slots[1], ctx->eh->num_bucket_slots[1]);
		}else{
			eh_solve_one(ctx->eh, ctx->thread_id,
				ctx->eh->slots[1], ctx->eh->num_bucket_slots[1],
				ctx->eh->slots[0], ctx->eh->num_bucket_slots[0]);
		}
		barrier_wait(ctx->barrier);
	}

	if(ctx->thread_id == 0){
		LOG("starting last two digits\n");
		eh_print_stats(ctx->eh);
	}
	barrier_wait(ctx->barrier);

	// NOTE: EH_K is almost always odd but...
	if(EH_K & 1)
		eh_solve_last(ctx->eh, ctx->thread_id,
			ctx->eh->slots[0], ctx->eh->num_bucket_slots[0]);
	else
		eh_solve_last(ctx->eh, ctx->thread_id,
			ctx->eh->slots[1], ctx->eh->num_bucket_slots[1]);

	barrier_wait(ctx->barrier);
	if(ctx->thread_id == 0){
		LOG("equihash end\n");
		eh_print_stats(ctx->eh);
	}
}

i32 eh_solve(blake2b_state *base_state, EH_Solution *sol_buffer, i32 max_sols){
	i32 num_threads = num_cpu_cores();
	// NOTE: Leave one thread for the system.
	if(num_threads > 1)
		num_threads -= 1;

	i32 num_slots = EH_NUM_BUCKETS * EH_MAX_BUCKET_SLOTS;

	// initialize state
	EH_State eh = {};
	eh.base_state = base_state;
	eh.num_threads = num_threads;
	eh.num_bucket_slots[0] = (i32*)calloc(2 * EH_NUM_BUCKETS, sizeof(i32));
	eh.num_bucket_slots[1] = eh.num_bucket_slots[0] + EH_NUM_BUCKETS;
	eh.slots[0] = (EH_Slot*)calloc(2 * num_slots, sizeof(EH_Slot));
	eh.slots[1] = eh.slots[0] + num_slots;
	eh.max_sols = max_sols;
	eh.num_sols = 0;
	eh.sol_buffer = sol_buffer;

	// TODO: We should use a thread pool.
	// spawn threads
	barrier_t barrier;
	barrier_init(&barrier, num_threads);
	EH_ThreadContext *thr_context =
		(EH_ThreadContext*)malloc(num_threads * sizeof(EH_ThreadContext));
	for(i32 i = 0; i < num_threads; i += 1){
		thr_context[i].eh = &eh;
		thr_context[i].barrier = &barrier;
		thr_context[i].thread_id = i;
		if(i != 0){
			thread_spawn(&thr_context[i].thread_handle,
				eh_worker_thread, &thr_context[i]);
		}
	}

	// do work alongside other threads (this is thread_id == 0)
	eh_worker_thread(&thr_context[0]);

	// join other threads
	for(i32 i = 1; i < num_threads; i += 1)
		thread_join(&thr_context[i].thread_handle);
	barrier_delete(&barrier);

	// release used memory
	free(eh.num_bucket_slots[0]);
	free(eh.slots[0]);
	free(thr_context);

	return eh.num_sols;
}

bool eh_check_solution(blake2b_state *base_state, EH_Solution *solution){
	u32 indices[EH_SOLUTION_INDICES];
	unpack_uints(EH_SOLUTION_INDEX_BITS,
		solution->packed, EH_PACKED_SOLUTION_BYTES,
		indices, EH_SOLUTION_INDICES);

	EH_Slot slots[EH_SOLUTION_INDICES];
	for(i32 i = 0; i < EH_SOLUTION_INDICES; i += 1){
		u8 blake[EH_BLAKE_OUTLEN];

		i32 j = indices[i] / EH_HASHES_PER_BLAKE;
		i32 k = indices[i] % EH_HASHES_PER_BLAKE;

		eh_generate_blake(base_state, j, blake, EH_BLAKE_OUTLEN);

		slots[i].num_hash_digits = EH_HASH_DIGITS;
		unpack_uints(EH_HASH_DIGIT_BITS,
			blake + k * EH_HASH_BYTES, EH_HASH_BYTES,
			slots[i].hash_digits, EH_HASH_DIGITS);

		slots[i].num_indices = 1;
		slots[i].indices[0] = indices[i];
	}

	i32 num_slots = EH_SOLUTION_INDICES;
	EH_Slot aux[EH_SOLUTION_INDICES];
	for(i32 digit = 0; digit < (EH_HASH_DIGITS - 2); digit += 1){
		i32 num_aux = 0;
		for(i32 i = 0; i < num_slots; i += 2){
			if(!(slots[i].hash_digits[0] == slots[i + 1].hash_digits[0]))
				return false;
			if(!eh_distinct_indices(&slots[i], &slots[i + 1]))
				return false;
			if(!(slots[i].indices[0] < slots[i + 1].indices[0]))
				return false;
			aux[num_aux++] = eh_partial_join(&slots[i], &slots[i + 1]);
		}

		DEBUG_ASSERT(num_aux == (num_slots / 2));
		num_slots = num_aux;
		memcpy(slots, aux, num_aux * sizeof(EH_Slot));
	}

	DEBUG_ASSERT(num_slots == 2);
	if(!(slots[0].hash_digits[0] == slots[1].hash_digits[0])
	  && !(slots[0].hash_digits[1] == slots[1].hash_digits[1]))
		return false;
	if(!eh_distinct_indices(&slots[0], &slots[1]))
		return false;
	if(!(slots[0].indices[0] < slots[1].indices[0]))
		return false;

	return true;
}
