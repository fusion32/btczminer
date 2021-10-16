#include "common.hh"
#include "buffer_util.hh"

#if 0
struct JSON_BlockHeader{
	i32 version;
	const char *hash_prev_block;
	const char *hash_merkle_root;
	const char *hash_final_sapling_root;
	u32 time;
	u32 bits;
	const char *nonce;
	const char *equihash_solution;
};
#endif

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
void init_state(blake2b_state *state, BlockHeader *header){
	// TODO: Init state without the nonce then add the nonce
	// after. This way we'll save the work of re-initializing
	// the whole BLAKE2B state.

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

static
bool check_btcz_block(BlockHeader *header){
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
		LOG_ERROR("not a valid equihash solution\n");
		return false;
	}

	// 2nd - Check proof-of-work.
	u256 sha256_result = wsha256(buf, 241);
	u256 sha256_target = compact_to_u256(header->bits);
	print_buf("sha256_result", sha256_result.data, 32);
	print_buf("sha256_target", sha256_target.data, 32);
	if(sha256_result > sha256_target){
		LOG_ERROR("invalid pow\n");
		return false;
	}

	// OK
	return true;
}

int main(int argc, char **argv){
	//int test_sha256(int argc, char **argv);
	//return test_sha256(argc, argv);

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

	BlockHeader block_header;
	block_header.version = version;
	hex_to_buffer_inv(hash_prev_block_hex, block_header.hash_prev_block.data, 32);
	hex_to_buffer_inv(hash_merkle_root_hex, block_header.hash_merkle_root.data, 32);
	hex_to_buffer_inv(hash_final_sapling_root_hex, block_header.hash_final_sapling_root.data, 32);
	block_header.time = time;
	block_header.bits = bits;
	hex_to_buffer_inv(nonce_hex, block_header.nonce.data, 32);
	block_header.solution = hex_to_eh_solution(solution_hex);

	LOG("check_block = %d\n", check_btcz_block(&block_header));

#if 0
	EH_Solution sol_buffer[10];
	i32 max_sols = NARRAY(sol_buffer);
	i32 num_sols = eh_solve(&block_state, sol_buffer, max_sols);
	LOG("num_sols = %d\n", num_sols);
	num_sols = i32_min(num_sols, max_sols);
	for(i32 i = 0; i < num_sols; i += 1){
		LOG("solution #%d:\n", i);
		print_buf("solution", sol_buffer[i].packed, EH_PACKED_SOLUTION_BYTES);
	}
#endif
	return 0;
}
