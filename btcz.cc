#include "common.hh"
#include "buffer_util.hh"

struct BlockHeader{
	i32 version;
	u256 hash_prev_block;
	u256 hash_merkle_root;
	u256 hash_final_sapling_root;
	u32 time;
	u32 bits;
	u256 nonce;
	EH_Solution solution;
};

static INLINE
void serialize_u32(u8 *buffer, u32 value){
	encode_u32_le(buffer, value);
}

static INLINE
void serialize_u256(u8 *buffer, u256 value){
	memcpy(buffer, value.data, 32);
}

static INLINE
void serialize_eh_solution(u8 *buffer, EH_Solution solution){
	memcpy(buffer, solution.packed, EH_PACKED_SOLUTION_BYTES);
}

static
bool btcz_check_block(BlockHeader *header){
	static_assert(sizeof(BlockHeader) == 240, "");
	static_assert(sizeof(EH_Solution) == 100, "");

	u8 buf[241];
	serialize_u32(buf + 0x00, header->version);
	serialize_u256(buf + 0x04, header->hash_prev_block);
	serialize_u256(buf + 0x24, header->hash_merkle_root);
	serialize_u256(buf + 0x44, header->hash_final_sapling_root);
	serialize_u32(buf + 0x64, header->time);
	serialize_u32(buf + 0x68, header->bits);
	serialize_u256(buf + 0x6C, header->nonce);

	// NOTE: This byte is because the solution is preceeded by
	// it's length in a "compact" form. In the case of BTCZ, it
	// is always 100 so this byte is essentially wasted.
	encode_u8(buf + 0x8C, 0x64);
	serialize_eh_solution(buf + 0x8D, header->solution);

	print_buf("eh header", buf, 140);
	print_buf("full header", buf, 241);

	// 1st - Check if the solution is an actual solution to the equihash.
	// Note that the solution itself must not be included in the blake2b,
	// that's why we use 140 bytes instead of 240 below.
	blake2b_state block_state;
	blake2b_init_eh(&block_state, EH_PERSONAL, EH_N, EH_K);
	blake2b_update(&block_state, buf, 140);
	if(!eh_check_solution(&block_state, &header->solution)){
		LOG_ERROR("invalid equihash solution\n");
		return false;
	}

	// 2nd - Check proof-of-work.
	u256 wsha256_result = wsha256(buf, 241);
	u256 wsha256_target = compact_to_u256(header->bits);
	print_buf("wsha256_result", wsha256_result.data, 32);
	print_buf("wsha256_target", wsha256_target.data, 32);
	if(wsha256_result > wsha256_target){
		LOG_ERROR("invalid pow\n");
		return false;
	}

	// OK
	return true;
}

static
bool btcz_check_pow_target(MiningParams *params,
		u256 nonce, EH_Solution solution){
	static_assert(sizeof(EH_Solution) == 100, "");
	u8 buf[241];
	serialize_u32(buf + 0x00, params->version);
	serialize_u256(buf + 0x04, params->prev_hash);
	serialize_u256(buf + 0x24, params->merkle_root);
	serialize_u256(buf + 0x44, params->final_sapling_root);
	serialize_u32(buf + 0x64, params->time);
	serialize_u32(buf + 0x68, params->bits);
	serialize_u256(buf + 0x6C, nonce);

	// NOTE: This byte is because the solution is preceeded by
	// it's length in a "compact" form. In the case of BTCZ, it
	// is always 100 so this byte is essentially wasted.
	encode_u8(buf + 0x8C, 0x64);
	serialize_eh_solution(buf + 0x8D, solution);

	u256 wsha256_result = wsha256(buf, 241);
	return !(wsha256_result > params->target);
}

static
void btcz_state_init(blake2b_state *state, MiningParams *params){
	u8 buf[108];
	serialize_u32(buf + 0x00, params->version);
	serialize_u256(buf + 0x04, params->prev_hash);
	serialize_u256(buf + 0x24, params->merkle_root);
	serialize_u256(buf + 0x44, params->final_sapling_root);
	serialize_u32(buf + 0x64, params->time);
	serialize_u32(buf + 0x68, params->bits);

	blake2b_init_eh(state, EH_PERSONAL, EH_N, EH_K);
	blake2b_update(state, buf, 108);
}

static
void btcz_state_add_nonce(blake2b_state *state, u256 nonce){
	u8 buf[32];
	serialize_u256(buf, nonce);
	blake2b_update(state, buf, 32);
}

static
void btcz_nonce_init(MiningParams *params, u256 *nonce){
	*nonce = params->nonce1;
	srand(params->time);
	for(i32 i = params->nonce1_bytes; i < 32; i += 1)
		nonce->data[i] = ((u32)rand() << 16) | ((u32)rand() << 0);
}

static
void btcz_nonce_increase(MiningParams *params, u256 *nonce){
	// NOTE: Realistically the nonce won't wrap, given that
	// the time for a block is ~2.5 minutes. So we don't need
	// to report that kind of event since it won't happen.

	for(i32 i = params->nonce1_bytes; i < 32; i += 1){
		nonce->data[i] += 1;
		if(nonce->data[i] != 0)
			return;
	}
}

#if 1
int main(int argc, char **argv){
	// NOTE: This is the address and port of the BTCZ mining pool
	// https://btcz.darkfibermines.com/ and my personal BTCZ public
	// address which I used for testing.
	const char *connect_addr = "142.4.211.28";
	const char *connect_port = "4000";
	const char *user = "t1Rxx8pUgs29isFXV8mjDPuBbNf22SDqZGq";
	const char *password = "x";

	MiningParams params;
	STRATUM *S = btcz_stratum_connect(
			connect_addr, connect_port,
			user, password, &params);
	if(!S){
		LOG_ERROR("failed to connect to pool\n");
		return -1;
	}

	LOG("connected...\n");
	while(1){
		LOG("job_id: %s\n", params.job_id);
		blake2b_state base_state;
		btcz_state_init(&base_state, &params);

		u256 nonce;
		btcz_nonce_init(&params, &nonce);
		while(1){
			// prepare blake2b state for the current nonce
			blake2b_state cur_state = base_state;
			btcz_state_add_nonce(&cur_state, nonce);

			// solve the equihash
			EH_Solution sols[8];
			i32 max_sols = NARRAY(sols);
			i32 num_sols = eh_solve(&cur_state, sols, max_sols);
			if(num_sols > max_sols){
				LOG("missed %d solutions (max_sols = %d, num_sols = %d)\n",
					(num_sols - max_sols), max_sols, num_sols);
				num_sols = max_sols;
			}

			// submit results
			LOG("num_sols = %d\n", num_sols);
			for(i32 i = 0; i < num_sols; i += 1){
				bool is_eh_solution = eh_check_solution(&cur_state, &sols[i]);
				bool is_above_pow_target = !btcz_check_pow_target(&params, nonce, sols[i]);
				LOG("sol %d: is_eh_solution = %s, is_above_pow_target = %s\n",
					i, is_eh_solution ? "yes" : "no",
					is_above_pow_target ? "yes" : "no");
				if(is_above_pow_target)
					continue;
				LOG("sending sol %d...\n", i);
				if(!btcz_stratum_submit_solution(S, &params, nonce, sols[i]))
					LOG_ERROR("failed to submit solution %d\n", i);
			}

			// NOTE: Check if the server updated our mining params and if
			// so, we should re-initialize our blake2b state and nonce with
			// the new params.
			if(btcz_stratum_update_params(S, &params))
				break;

			// increase nonce
			btcz_nonce_increase(&params, &nonce);
		}
	}
	return 0;
}

#else

void btcz_test_state_init(blake2b_state *state){
	// block = 818128
	u32 version = 4;
	char *prev_hash_hex = "0000007b753e415f80614ba8130aa4668ca4731b0539d9919c2074b43a46b9e8";
	char *merkle_root_hex = "6b2198b49e2055535c403830a3c124a8c235004b4662901010bc0927c43979ec";
	char *final_sapling_root_hex = "189df3ceb26643f3b90ec7059316c7ccb26aeaf1e96559c63b8c6d52f04e79b5";
	u32 time = 1632007626;
	u32 bits = 0x1e009cb8;
	char *nonce_hex = "81b601c200000000000000006dcdf558dd65a0dd9e68012952b8df1003cefade";

	DEBUG_ASSERT(count_hex_digits(prev_hash_hex) == 64);
	DEBUG_ASSERT(count_hex_digits(merkle_root_hex) == 64);
	DEBUG_ASSERT(count_hex_digits(final_sapling_root_hex) == 64);
	DEBUG_ASSERT(count_hex_digits(nonce_hex) == 64);

	u8 buf[140];
	serialize_u32(buf + 0x00, version);
	serialize_u256(buf + 0x04, hex_be_to_u256(prev_hash_hex));
	serialize_u256(buf + 0x24, hex_be_to_u256(merkle_root_hex));
	serialize_u256(buf + 0x44, hex_be_to_u256(final_sapling_root_hex));
	serialize_u32(buf + 0x64, time);
	serialize_u32(buf + 0x68, bits);
	serialize_u256(buf + 0x6C, hex_be_to_u256(nonce_hex));

	blake2b_init_eh(state, EH_PERSONAL, EH_N, EH_K);
	blake2b_update(state, buf, 140);
}

int main(int argc, char **argv){
	LOG("BTCZ TEST\n");

	blake2b_state state;
	btcz_test_state_init(&state);

	// solve the equihash
	EH_Solution sols[8];
	i32 max_sols = NARRAY(sols);
	i32 num_sols = eh_solve(&state, sols, max_sols);
	if(num_sols > max_sols){
		LOG("missed %d solutions (max_sols = %d, num_sols = %d)\n",
			(num_sols - max_sols), max_sols, num_sols);
		num_sols = max_sols;
	}

	// submit results
	LOG("num_sols = %d\n", num_sols);
	for(i32 i = 0; i < num_sols; i += 1){
		bool is_eh_solution = eh_check_solution(&state, &sols[i]);
		LOG("sol %d: is_eh_solution = %s\n",
			i, is_eh_solution ? "yes" : "no");
		print_buf("sol", sols[i].packed, EH_PACKED_SOLUTION_BYTES);
	}
	return 0;
}

#endif
