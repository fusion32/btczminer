
#include "common.hh"
#include "buffer_util.hh"
#include "thread.hh"

#define EH_BUCKET_BITS			((EH_HASH_DIGIT_BITS * 3) / 5)
#define EH_BUCKET_MASK			((1 << EH_BUCKET_BITS) - 1)
#define	EH_NUM_BUCKETS			(1 << EH_BUCKET_BITS)

#define EH_OTHER_BITS			(EH_HASH_DIGIT_BITS - EH_BUCKET_BITS)

// NOTE: The number of bucket slots can be calculated as follows:
//	num_bucket_slots = extra_room * (EH_RANGE / EH_NUM_BUCKETS)
//		= extra_room * ((1 << EH_SOLUTION_INDEX_BITS) / (1 << EH_BUCKET_BITS))
//		= extra_room * (1 << (EH_SOLUTION_INDEX_BITS - EH_BUCKET_BITS))
//		= extra_room * (1 << (EH_HASH_DIGIT_BITS + 1 - EH_BUCKET_BITS))
//		= extra_room * (1 << (EH_OTHER_BITS + 1))
//
//	Now, if we define extra_room as any value between 1.0 and 2.0, we'll
//	need at least one extra bit for the slot which means that adding 5%
//	of extra_room or 100% of extra room will result in the same number of
//	bits for the slot. If we then fix extra_room being 2.0, we get:
//	num_bucket_slots = 2 * (1 << (EH_OTHER_BITS + 1))
//		= (1 << (EH_OTHER_BITS + 1 + 1))
//		= (1 << EH_SLOT_BITS)
//
//	Where EH_SLOT_BITS = EH_OTHER_BITS + 2.
//
//	Note that in the case of BTCZ we have 24 bits hash digits, so we'd have
// EH_BUCKET_BITS = 20, EH_OTHER_BITS = 4, EH_SLOT_BITS = 6. This may be a
// problem because with so little other bits we are more likely to hit some
// statistical edge cases.
//	We could improve these numbers by using cantor pairing which is used in
// the tromp implementation but in the NOTE below I'll discuss another method.
//

// This will make us discard more collisions but will consume a lot less memory
// and will be a little faster (haven't measured but it seems to be faster and
// it makes sense because the program requires less bandwidth).
//#define EH_SLOT_BITS			(EH_OTHER_BITS + 1)

#define EH_SLOT_BITS			(EH_OTHER_BITS + 2)
#define EH_SLOT_MASK			((1 << EH_SLOT_BITS) - 1)
#define EH_NUM_BUCKET_SLOTS		(1 << EH_SLOT_BITS)

#define EH_LAST_ROUND			(EH_K - 1)


// NOTE: This struct should always be interpreted as the remainder of hash
// digits and a back reference to the bucket and slots used in the previous
// round to generate the current slot. For the visualization below, A B C ...
// are hash digits, 0 1 2 ... are back references, and I is the index used
// to generate the whole hash on round 0.
//
//	For BTCZ, each round should look like this:
//	  round 0 = [A B C D E F I]
//	  round 1 = [B C D E F 0]
//	  round 2 = [C D E F 1]
//	  round 3 = [D E F 2]
//	  round 4 = [E F 3]
//
//	In reality, the data will look different but we need to remember that
//	the back references must not be touched after being set or we may break
//	them.
//	  round 0 = [A B C D E F I]
//	  round 1 = [B C D E F 0 I]
//	  round 2 = [C D E F 1 0 I]
//	  round 3 = [D E F 2 1 0 I]
//	  round 4 = [E F 3 2 1 0 I]
//
//	Now, the visualization is missing a detail. We can't have only one set of
// buckets. Since we plan to process buckets individually, if we had a single
// set of buckets, we'd end up mixing up slots. If we reset all buckets at
// the start, we lose input information. If we reset only the counter on each
// bucket, we overwrite input information. If we don't reset any buckets, we'll
// overflow them while mixing old slots with new slots.
//
//	So we need to have at least two sets of buckets. If we redo the visualization
// for BTCZ and now using ? for undefined elements we get:
//	                set 0             set 1
//	  init    = [A B C D E F I]    [? ? ? ? ? ? ?]
//	  round 0 = [A B C D E F I] -> [B C D E F 0 ?]
//	  round 1 = [C D E F 1 ? I] <- [B C D E F 0 ?]
//	  round 2 = [C D E F 1 ? I] -> [D E F 2 ? 0 ?]
//	  round 3 = [E F 3 ? 1 ? I] <- [D E F 2 ? 0 ?]
//	  round 4 = [E F 3 ? 1 ? I] -> [we don't output at the last round]
//
//	There are two things to notice here. The first is that we end up with a few
// undefined elements in both sets. The second is that when retrieving indices,
// we'll need to to do sort of a zig-zag between the sets to get the correct values.
//
//	But there is another problem. As discussed in the NOTE we calculated slot_bits,
// if we want to have less bucket_bits, we'll need more than only 32 bits for
// a back reference.
//
//	So what we are gonna do, is to use the undefined elements we saw in the
// visualization to address this problem. It won't cost any extra memory and
// will allow us to arbitrarily (not really) choose the number of bucket_bits.
//
//	One last view of how it should all work and now using Kl and Kh for the
// low and high 32 bits of the back reference K:
//	                   set 0                     set 1
//	  init    = [A  B  C  D  E  F  I]    [?  ?  ?  ?  ?  ?  ? ]
//	  round 0 = [A  B  C  D  E  F  I] -> [B  C  D  E  F  0l 0h]
//	  round 1 = [C  D  E  F  1l 1h I] <- [B  C  D  E  F  0l 0h]
//	  round 2 = [C  D  E  F  1l 1h I] -> [D  E  F  2l 2h 0l 0h]
//	  round 3 = [E  F  3l 3h 1l 1h I] <- [D  E  F  2l 2h 0l 0h]
//	  round 4 = [E  F  3l 3h 1l 1h I] -> [we don't output at the last round]
//
struct EH_Slot{
	u32 data[EH_HASH_DIGITS + 1];
};

#define EH_INPUT_IDX(round)		((round) & 1)
#define EH_OUTPUT_IDX(round)	(1 - ((round) & 1))

struct EH_State{
	blake2b_state *base_state;
	i32 num_threads;

	i32 *num_slots_taken[2];
	// TODO: Maybe this should be called "slot_pool" or
	// something instead of only "slots".
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
EH_Slot *eh_get_bucket(EH_Slot *slots, i32 bucket_id){
	return slots + bucket_id * EH_NUM_BUCKET_SLOTS;
}

static
i32 eh_get_num_slots_taken(i32 *num_slots_taken, i32 bucket_id){
	i32 result = atomic_exchange(&num_slots_taken[bucket_id], 0);
	if(result > EH_NUM_BUCKET_SLOTS)
		result = EH_NUM_BUCKET_SLOTS;
	return result;
}

static
EH_Slot *eh_push_slot(EH_Slot *slots, i32 *num_slots_taken, i32 bucket_id){
	i32 slot_id = atomic_add(&num_slots_taken[bucket_id], 1);
	if(slot_id >= EH_NUM_BUCKET_SLOTS)
		return NULL;
	return slots + bucket_id * EH_NUM_BUCKET_SLOTS + slot_id;
}

static
EH_Solution *eh_push_solution(EH_State *eh){
	i32 sol_id = atomic_add(&eh->num_sols, 1);
	if(sol_id >= eh->max_sols)
		return NULL;
	return eh->sol_buffer + sol_id;
}

static INLINE
u64 eh_get_ancestor(i32 round, EH_Slot *a){
	i32 i = NARRAY(a->data) - round - 1;
	DEBUG_ASSERT(i > 0);
	if(round == 0){
		return (u64)a->data[i];
	}else{
		return (u64)a->data[i] | ((u64)a->data[i + 1] << 32);
	}
}

static
bool eh_same_ancestor(i32 round, EH_Slot *a, EH_Slot *b){
	i32 i = NARRAY(a->data) - round - 1;
	DEBUG_ASSERT(i > 0);
	if(round == 0){
		return a->data[i] == b->data[i];
	}else{
		return a->data[i] == b->data[i]
			&& a->data[i + 1] == b->data[i + 1];
	}
}

static
void eh_write_to_output_slot(i32 round, EH_Slot *dest, EH_Slot *src){
	i32 n = NARRAY(dest->data) - round;
	DEBUG_ASSERT(n > 0);
	for(i32 i = 0; i < n; i += 1)
		dest->data[i] = src->data[i];
}

static
u64 eh_ref(i32 bucket_id, i32 s0, i32 s1){
	DEBUG_ASSERT(bucket_id < EH_NUM_BUCKETS);
	DEBUG_ASSERT(s0 < EH_NUM_BUCKET_SLOTS);
	DEBUG_ASSERT(s1 < EH_NUM_BUCKET_SLOTS);
	u64 result = (u64)bucket_id << (2 * EH_SLOT_BITS)
		| (u64)s0 << EH_SLOT_BITS | (u64)s1;
	return result;
}

static
i32 eh_ref_bucket_id(u64 ref){
	i32 result = (i32)((ref >> (2 * EH_SLOT_BITS)) & EH_BUCKET_MASK);
	return result;
}

static
i32 eh_ref_s0(u64 ref){
	i32 result = (i32)((ref >> EH_SLOT_BITS) & EH_SLOT_MASK);
	return result;
}

static
i32 eh_ref_s1(u64 ref){
	i32 result = (i32)(ref & EH_SLOT_MASK);
	return result;
}

static
EH_Slot eh_join(i32 round, EH_Slot *a, EH_Slot *b,
		i32 bucket_id, i32 s0, i32 s1){
	i32 num_hash_digits = NARRAY(a->data) - round - 2;
	DEBUG_ASSERT(num_hash_digits > 0);

	EH_Slot result;
	for(i32 i = 0; i < num_hash_digits; i += 1)
		result.data[i] = a->data[i + 1] ^ b->data[i + 1];

	u64 ref = eh_ref(bucket_id, s0, s1);
	// NOTE: The order is important and must match the order
	// used inside eh_get_ancestor.
	result.data[num_hash_digits] = (u32)ref;
	result.data[num_hash_digits + 1] = (u32)(ref >> 32);
	return result;
}

static
void eh_get_indices(EH_State *eh, i32 round, u64 ref, u32 *out_indices){
	i32 bucket_id = eh_ref_bucket_id(ref);
	i32 s0 = eh_ref_s0(ref);
	i32 s1 = eh_ref_s1(ref);
	EH_Slot *slots = eh->slots[EH_INPUT_IDX(round)];
	EH_Slot *bucket = eh_get_bucket(slots, bucket_id);
	i32 step = 1 << round;

	if(round == 0){
		DEBUG_ASSERT(EH_INPUT_IDX(0) == 0);
		out_indices[0] = (u32)eh_get_ancestor(0, &bucket[s0]);
		out_indices[1] = (u32)eh_get_ancestor(0, &bucket[s1]);
	}else{
		eh_get_indices(eh, round - 1,
			eh_get_ancestor(round, &bucket[s0]), out_indices);
		eh_get_indices(eh, round - 1,
			eh_get_ancestor(round, &bucket[s1]), out_indices + step);
	}

	if(out_indices[0] > out_indices[step]){
		for(i32 i = 0; i < step; i += 1){
			u32 tmp = out_indices[i];
			out_indices[i] = out_indices[i + step];
			out_indices[i + step] = tmp;
		}
	}
}

static
bool eh_get_distinct_indices(EH_State *eh, EH_Slot *a, EH_Slot *b, u32 *out_indices){
	i32 round = EH_LAST_ROUND;
	i32 step = 1 << round;
	eh_get_indices(eh, round - 1,
		eh_get_ancestor(round, a), out_indices);
	eh_get_indices(eh, round - 1,
		eh_get_ancestor(round, b), out_indices + step);
	if(out_indices[0] > out_indices[step]){
		for(i32 i = 0; i < step; i += 1){
			u32 tmp = out_indices[i];
			out_indices[i] = out_indices[i + step];
			out_indices[i + step] = tmp;
		}
	}

	for(i32 i = 0; i < EH_SOLUTION_INDICES; i += 1){
		for(i32 j = i + 1; j < EH_SOLUTION_INDICES; j += 1){
			if(out_indices[i] == out_indices[j])
				return false;
		}
	}
	return true;
}

static
void eh_solve_init(EH_State *eh, i32 thread_id,
		EH_Slot *output_slots, i32 *output_num_slots_taken){
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
			EH_Slot *out_slot = eh_push_slot(output_slots,
					output_num_slots_taken, bucket_id);
			if(!out_slot){
				atomic_add(&eh->num_discarded_hashes, 1);
				continue;
			}
			memcpy(out_slot->data, hash_digits, sizeof(hash_digits));
			out_slot->data[EH_HASH_DIGITS] = index;
		}
	}
}

struct EH_Collisions{
	// NOTE: So, we partially sorted all hashes by assigning them to buckets
	// based on the bucket bits of their first hash digit. To fully sort them
	// tho, we still need to consider the other bits.
	//	Now, one way to do this is to do a regular sort but since we want to
	// preserve the last u32s inside each EH_Slot, we could try to create a
	// linked list for each of the combinations of the other bits.

	i32 head[1 << EH_OTHER_BITS];
	i32 next[EH_NUM_BUCKET_SLOTS];
};

void eh_collisions_init(EH_Collisions *c){
	for(i32 i = 0; i < NARRAY(c->head); i += 1)
		c->head[i] = -1;
	for(i32 i = 0; i < NARRAY(c->next); i += 1)
		c->next[i] = -1;
}

i32 eh_collisions_insert_slot(EH_Collisions *c, i32 slot, u32 other_bits){
	DEBUG_ASSERT(other_bits < NARRAY(c->head));
	DEBUG_ASSERT(slot >= 0 && slot < EH_NUM_BUCKET_SLOTS);
	i32 head = c->head[other_bits];
	c->next[slot] = head;
	c->head[other_bits] = slot;
	return head;
}

i32 eh_collisions_next_slot(EH_Collisions *c, i32 slot){
	DEBUG_ASSERT(slot >= 0 && slot < EH_NUM_BUCKET_SLOTS);
	return c->next[slot];
}

static
void eh_solve_one(EH_State *eh, i32 round, i32 thread_id,
		EH_Slot *input_slots, i32 *input_num_slots_taken,
		EH_Slot *output_slots, i32 *output_num_slots_taken){
	for(i32 bucket_id = thread_id;
			bucket_id < EH_NUM_BUCKETS;
			bucket_id += eh->num_threads){
		EH_Slot *bucket = eh_get_bucket(input_slots, bucket_id);
		i32 num_slots_taken = eh_get_num_slots_taken(
				input_num_slots_taken, bucket_id);

		EH_Collisions collisions;
		eh_collisions_init(&collisions);
		for(i32 s0 = 0; s0 < num_slots_taken; s0 += 1){
			i32 s1 = eh_collisions_insert_slot(&collisions, s0,
				(bucket[s0].data[0] >> EH_BUCKET_BITS));
			for(; s1 >= 0; s1 = eh_collisions_next_slot(&collisions, s1)){
				if(eh_same_ancestor(round, &bucket[s0], &bucket[s1]))
					continue;
				EH_Slot tmp = eh_join(round,
					&bucket[s0], &bucket[s1], bucket_id, s0, s1);
				i32 out_bucket_id = tmp.data[0] & EH_BUCKET_MASK;
				EH_Slot *out_slot = eh_push_slot(output_slots,
						output_num_slots_taken, out_bucket_id);
				if(!out_slot){
					atomic_add(&eh->num_discarded_collisions, 1);
					continue;
				}
				eh_write_to_output_slot(round, out_slot, &tmp);
			}
		}
	}
}

static
void eh_solve_last(EH_State *eh, i32 thread_id,
		EH_Slot *input_slots, i32 *input_num_slots_taken){
	for(i32 bucket_id = thread_id;
			bucket_id < EH_NUM_BUCKETS;
			bucket_id += eh->num_threads){
		EH_Slot *bucket = eh_get_bucket(input_slots, bucket_id);
		i32 num_slots_taken = eh_get_num_slots_taken(
				input_num_slots_taken, bucket_id);

		EH_Collisions collisions;
		eh_collisions_init(&collisions);
		for(i32 s0 = 0; s0 < num_slots_taken; s0 += 1){
			i32 s1 = eh_collisions_insert_slot(&collisions, s0,
				(bucket[s0].data[0] >> EH_BUCKET_BITS));
			for(; s1 >= 0; s1 = eh_collisions_next_slot(&collisions, s1)){
				// NOTE: EH_Collisions will check for collisions on the first
				// hash digit but we still need to check the second hash digit.
				if(bucket[s0].data[1] != bucket[s1].data[1])
					continue;

				if(eh_same_ancestor(EH_LAST_ROUND, &bucket[s0], &bucket[s1]))
					continue;

				u32 sol_indices[EH_SOLUTION_INDICES];
				if(eh_get_distinct_indices(eh, &bucket[s0], &bucket[s1], sol_indices)){
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
		ctx->eh->slots[0], ctx->eh->num_slots_taken[0]);
	barrier_wait(ctx->barrier);
	for(i32 round = 0; round < EH_LAST_ROUND; round += 1){
		if(ctx->thread_id == 0){
			LOG("starting digit %d\n", round);
			eh_print_stats(ctx->eh);
		}
		barrier_wait(ctx->barrier);

		i32 input_idx = EH_INPUT_IDX(round);
		i32 output_idx = EH_OUTPUT_IDX(round);
		eh_solve_one(ctx->eh, round, ctx->thread_id,
			ctx->eh->slots[input_idx], ctx->eh->num_slots_taken[input_idx],
			ctx->eh->slots[output_idx], ctx->eh->num_slots_taken[output_idx]);
		barrier_wait(ctx->barrier);
	}

	if(ctx->thread_id == 0){
		LOG("starting last two digits\n");
		eh_print_stats(ctx->eh);
	}
	barrier_wait(ctx->barrier);

	i32 input_idx = EH_INPUT_IDX(EH_LAST_ROUND);
	eh_solve_last(ctx->eh, ctx->thread_id,
		ctx->eh->slots[input_idx], ctx->eh->num_slots_taken[input_idx]);

	barrier_wait(ctx->barrier);
	if(ctx->thread_id == 0){
		LOG("equihash end\n");
		eh_print_stats(ctx->eh);
	}
}

i32 eh_solve(blake2b_state *base_state, EH_Solution *sol_buffer, i32 max_sols){
	// TODO: Use a thread pool and an arena.
	i32 num_threads = num_cpu_cores();
	// NOTE: Leave one thread for the system.
	if(num_threads > 1)
		num_threads -= 1;

	i32 num_slots = EH_NUM_BUCKETS * EH_NUM_BUCKET_SLOTS;

	// initialize state
	EH_State eh = {};
	eh.base_state = base_state;
	eh.num_threads = num_threads;
	eh.num_slots_taken[0] = (i32*)calloc(2 * EH_NUM_BUCKETS, sizeof(i32));
	eh.num_slots_taken[1] = eh.num_slots_taken[0] + EH_NUM_BUCKETS;
	eh.slots[0] = (EH_Slot*)calloc(2 * num_slots, sizeof(EH_Slot));
	eh.slots[1] = eh.slots[0] + num_slots;
	eh.max_sols = max_sols;
	eh.num_sols = 0;
	eh.sol_buffer = sol_buffer;

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
	free(eh.num_slots_taken[0]);
	free(eh.slots[0]);
	free(thr_context);

	return eh.num_sols;
}

bool eh_check_solution(blake2b_state *base_state, EH_Solution *solution){
	u32 indices[EH_SOLUTION_INDICES];
	unpack_uints(EH_SOLUTION_INDEX_BITS,
		solution->packed, EH_PACKED_SOLUTION_BYTES,
		indices, EH_SOLUTION_INDICES);

	// check for duplicate indices only once
	for(i32 i = 0; i < EH_SOLUTION_INDICES; i += 1){
		for(i32 j = i + 1; j < EH_SOLUTION_INDICES; j += 1){
			if(indices[i] == indices[j])
				return false;
		}
	}

	// generate hashes
	struct{
		u32 hash_digits[EH_HASH_DIGITS];
	}slots[EH_SOLUTION_INDICES];
	for(i32 i = 0; i < EH_SOLUTION_INDICES; i += 1){
		u8 blake[EH_BLAKE_OUTLEN];
		i32 j = indices[i] / EH_HASHES_PER_BLAKE;
		i32 k = indices[i] % EH_HASHES_PER_BLAKE;
		eh_generate_blake(base_state, j, blake, EH_BLAKE_OUTLEN);
		unpack_uints(EH_HASH_DIGIT_BITS,
			blake + k * EH_HASH_BYTES, EH_HASH_BYTES,
			slots[i].hash_digits, EH_HASH_DIGITS);
	}

	for(i32 round = 0; round < EH_LAST_ROUND; round += 1){
		i32 step = 1 << round;
		for(i32 i = 0; i < EH_SOLUTION_INDICES; i += 2 * step){
			for(i32 j = 0; j < EH_HASH_DIGITS; j += 1){
				slots[i].hash_digits[j] ^=
					slots[i + step].hash_digits[j];
			}
			if(slots[i].hash_digits[0] != 0)
				return false;
			if(indices[i] > indices[i + step])
				return false;
		}
	}

	if(slots[0].hash_digits[0] != slots[16].hash_digits[0]
	|| slots[0].hash_digits[1] != slots[16].hash_digits[1])
		return false;
	if(indices[0] > indices[16])
		return false;

	return true;
}
