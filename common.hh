#ifndef COMMON_HH_
#define COMMON_HH_ 1

// ----------------------------------------------------------------
// Types/Defines
// ----------------------------------------------------------------

// ensure we're compiling in 64bit
static_assert(sizeof(void*) == 8, "");

// stdlib base
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// int types
typedef int8_t		i8;
typedef uint8_t		u8;
typedef int16_t		i16;
typedef uint16_t	u16;
typedef int32_t		i32;
typedef uint32_t	u32;
typedef int64_t		i64;
typedef uint64_t	u64;
typedef size_t		usize;

// arch settings
#ifdef ARCH_X64
#	define ARCH_BIG_ENDIAN 0
#	define ARCH_UNALIGNED_ACCESS 1
#else
#	error "add arch settings"
#endif

// debug settings
#define ASSERT(expr)								\
	do{ if(!(expr)){								\
		LOG("%s:%d: \"%s\" assertion failed\n",		\
			__FILE__, __LINE__, #expr);				\
		abort();									\
	} } while(0)
#ifdef _DEBUG
#	define BUILD_DEBUG 1
#endif
#ifndef BUILD_DEBUG
#	define DEBUG_LOG(...)		((void)0)
#	define DEBUG_ASSERT(...)	((void)0)
#else
#	define DEBUG_LOG(...)		LOG(__VA_ARGS__)
#	define DEBUG_ASSERT(expr)	ASSERT(expr)
#endif

// compiler settings
#if defined(_MSC_VER)
#	define INLINE __forceinline
#	define UNREACHABLE abort()
#	define FALLTHROUGH ((void)0)
#elif defined(__GNUC__)
#	define INLINE __attribute__((always_inline)) inline
#	define UNREACHABLE abort()
#	define FALLTHROUGH __attribute__((fallthrough))
#else
#	error "add compiler settings"
#endif

// common macros
#define NARRAY(arr) (sizeof(arr)/sizeof((arr)[0]))
#define IS_POWER_OF_TWO(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))
#define BITS_TO_BYTES(x) (((x) + 7) / 8)
#define BYTES_TO_BITS(x) (8 * (x))

// TODO: logging
#include <stdio.h>
#define LOG(...)		fprintf(stdout, __FUNCTION__ ": " __VA_ARGS__)
#define LOG_ERROR(...)	fprintf(stdout, __FUNCTION__ ": " __VA_ARGS__)

// ----------------------------------------------------------------
// u256
// ----------------------------------------------------------------
struct u256{
	// NOTE: `data` is encoded in little endian order.
	u8 data[32];

	// NOTE: Each 32-bits word is encoded in cpu endian order.
	// But words are ordered in little endian so `data[0]` contains
	// the low 32 bits of the u256 and so on.
	//u32 data[8];
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

// ----------------------------------------------------------------
// Utility - main.cc
// ----------------------------------------------------------------
void hex_to_buffer(const char *hex, u8 *buf, i32 buflen);
void hex_to_buffer_inv(const char *hex, u8 *buf, i32 buflen);
i32 count_hex_digits(const char *hex);
void print_buf(const char *debug_name, u8 *buf, i32 buflen);

// ----------------------------------------------------------------
// BLAKE2B - blake2b.cc
// ----------------------------------------------------------------
#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_OUTBYTES 64
struct blake2b_state{
	u64 h[8];
	u64 t[2];
	u64 f[2];
	u8 buf[BLAKE2B_BLOCKBYTES];
	u64 buflen;
	u64 outlen;
};

void blake2b_init_eh(blake2b_state *S, const char *personal, u32 N, u32 K);
void blake2b_update(blake2b_state *S, u8 *in, u64 inlen);
void blake2b_final(blake2b_state *S, u8 *out, u64 outlen);

// ----------------------------------------------------------------
// SHA-256 - sha256.cc
// ----------------------------------------------------------------


// ----------------------------------------------------------------
// Equihash - equihash.cc
//	ZEC: personal = "ZcashPoW", N = 200, K = 9
//	YEC: personal = "ZcashPoW", N = 192, K = 7
//	BTCZ: personal = "BitcoinZ", N = 144, K = 5
// ----------------------------------------------------------------

// TODO: Add notes on how equihash works and how these defines
// are calculated.

#define EH_PERSONAL				"BitcoinZ"
#define EH_N					144
#define EH_K					5

#define EH_HASH_BYTES			(BITS_TO_BYTES(EH_N))
#define EH_HASHES_PER_BLAKE		(BLAKE2B_OUTBYTES / EH_HASH_BYTES)
#define EH_BLAKE_OUTLEN			(EH_HASHES_PER_BLAKE * EH_HASH_BYTES)

#define EH_HASH_DIGITS			(EH_K + 1)
#define EH_HASH_DIGIT_BITS		(EH_N / EH_HASH_DIGITS)
#define EH_HASH_DIGIT_BYTES		(BITS_TO_BYTES(EH_HASH_DIGIT_BITS))

#define EH_PROOF_INDEX_BITS		(EH_HASH_DIGIT_BITS + 1)
#define EH_PROOF_INDICES		(1 << EH_K)
#define EH_PACKED_PROOF_BYTES	(BITS_TO_BYTES(EH_PROOF_INDEX_BITS * EH_PROOF_INDICES))

#define EH_DOMAIN				(1 << EH_PROOF_INDEX_BITS)

// NOTE: PartialJoin is meant to be used for the first (EH_HASH_DIGITS - 2)
// digits. FinalJoin is meant to be used for the last two digits. See the equihash
// algorithm description in `equihash.cc` for more info.
struct PartialJoin{
	// TODO: Both hash_digits and indices can be packed on the same
	// array. This could lead to using dynamic memory instead of a
	// static size.

	i32 num_hash_digits;
	u32 hash_digits[EH_HASH_DIGITS];

	i32 num_indices;
	u32 indices[EH_PROOF_INDICES / 2];
};

struct FinalJoin{
	u32 indices[EH_PROOF_INDICES];
};

#endif //COMMON_HH_
