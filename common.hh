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
#	define ARCH_UNALIGNED_ACCESS 1
#	define ARCH_BIG_ENDIAN 0
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
#	define UNREACHABLE abort() //do { __assume(0); abort(); } while(0)
#	define FALLTHROUGH ((void)0)
#elif defined(__GNUC__)
#	define INLINE __attribute__((always_inline)) inline
#	define UNREACHABLE abort() //do { __builtin_unreachable(); abort(); } while(0)
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
// BLAKE2B
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

void blake2b_init(blake2b_state *S, u8 outlen);
void blake2b_init_btcz(blake2b_state *S);
void blake2b_update(blake2b_state *S, u8 *in, u64 inlen);
void blake2b_final(blake2b_state *S, u8 *out, u64 outlen);

// ----------------------------------------------------------------
// BitcoinZ = Equihash (N = 144, K = 5)
// ----------------------------------------------------------------

// TODO: Add notes on how equihash works and how these defines
// are calculated.

#define BTCZ_EH_N				144
#define BTCZ_EH_K				5

#define BTCZ_HASH_BYTES			18	// == BITS_TO_BYTES(BTCZ_EH_N)
#define BTCZ_HASHES_PER_BLAKE	3	// == BLAKE2B_OUTBYTES / BTCZ_HASH_BYTES
#define BTCZ_BLAKE_OUTLEN		54	// == BTCZ_HASHES_PER_BLAKE * BTCZ_HASH_BYTES
#define BTCZ_HASH_DIGIT_BITS	24	// == BTCZ_EH_N / (BTCZ_EH_K + 1)
#define BTCZ_HASH_DIGIT_BYTES	3	// == BITS_TO_BYTES(BTCZ_HASH_DIGIT_BITS)
#define BTCZ_HASH_DIGITS		6	// == BTCZ_EH_K + 1

#define BTCZ_PROOF_INDEX_BITS	25	// == BTCZ_HASH_DIGIT_BITS + 1
#define BTCZ_PROOF_INDICES		32	// == 1 << BTCZ_EH_K
#define BTCZ_PACKED_PROOF_BYTES	100	// == BITS_TO_BYTES(BTCZ_PROOF_INDEX_BITS * BTCZ_PROOF_INDICES)

#define BTCZ_DOMAIN				(1 << 25) // == 1 << BTCZ_PROOF_INDEX_BITS

// NOTE: PartialJoin is meant to be used for the first (BTCZ_HASH_DIGITS - 2)
// digits. FinalJoin is meant to be used for the last two digits. See the equihash
// algorithm description in `equihash.cc` for more info.
struct PartialJoin{
	// TODO: Both hash_digits and indices can be packed on the same
	// array. This could lead to using dynamic memory instead of a
	// static size.

	i32 num_hash_digits;
	u32 hash_digits[BTCZ_HASH_DIGITS];

	i32 num_indices;
	u32 indices[BTCZ_PROOF_INDICES / 2];
};

struct FinalJoin{
	u32 indices[BTCZ_PROOF_INDICES];
};

#endif //COMMON_HH_
