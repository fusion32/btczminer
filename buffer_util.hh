#ifndef BUFFER_UTIL_HH_
#define BUFFER_UTIL_HH_ 1

#include "common.hh"

static INLINE u16 swap_u16(u16 x){
	return (x & 0xFF00) >> 8
		| (x & 0x00FF) << 8;
}
static INLINE u32 swap_u32(u32 x){
	return (x & 0xFF000000) >> 24
		| (x & 0x00FF0000) >> 8
		| (x & 0x0000FF00) << 8
		| (x & 0x000000FF) << 24;
}
static INLINE u64 swap_u64(u64 x){
	return (x & 0xFF00000000000000) >> 56
		| (x & 0x00FF000000000000) >> 40
		| (x & 0x0000FF0000000000) >> 24
		| (x & 0x000000FF00000000) >> 8
		| (x & 0x00000000FF000000) << 8
		| (x & 0x0000000000FF0000) << 24
		| (x & 0x000000000000FF00) << 40
		| (x & 0x00000000000000FF) << 56;
}

#if ARCH_BIG_ENDIAN
#define u16_be_to_cpu(x)	(x)
#define u16_le_to_cpu(x)	swap_u16(x)
#define u32_be_to_cpu(x)	(x)
#define u32_le_to_cpu(x)	swap_u32(x)
#define u64_be_to_cpu(x)	(x)
#define u64_le_to_cpu(x)	swap_u64(x)
#define u16_cpu_to_be(x)	(x)
#define u16_cpu_to_le(x)	swap_u16(x)
#define u32_cpu_to_be(x)	(x)
#define u32_cpu_to_le(x)	swap_u32(x)
#define u64_cpu_to_be(x)	(x)
#define u64_cpu_to_le(x)	swap_u64(x)
#else //ARCH_BIG_ENDIAN
#define u16_be_to_cpu(x)	swap_u16(x)
#define u16_le_to_cpu(x)	(x)
#define u32_be_to_cpu(x)	swap_u32(x)
#define u32_le_to_cpu(x)	(x)
#define u64_be_to_cpu(x)	swap_u64(x)
#define u64_le_to_cpu(x)	(x)
#define u16_cpu_to_be(x)	swap_u16(x)
#define u16_cpu_to_le(x)	(x)
#define u32_cpu_to_be(x)	swap_u32(x)
#define u32_cpu_to_le(x)	(x)
#define u64_cpu_to_be(x)	swap_u64(x)
#define u64_cpu_to_le(x)	(x)
#endif //ARCH_BIG_ENDIAN

static INLINE void encode_u8(u8 *data, u8 val){
	data[0] = val;
}

static INLINE u8 decode_u8(u8 *data){
	return data[0];
}

#if ARCH_UNALIGNED_ACCESS
static INLINE void encode_u16_be(u8 *data, u16 val){
	*(u16*)(data) = u16_cpu_to_be(val);
}

static INLINE u16 decode_u16_be(u8 *data){
	u16 val = *(u16*)(data);
	return u16_be_to_cpu(val);
}

static INLINE void encode_u16_le(u8 *data, u16 val){
	*(u16*)(data) = u16_cpu_to_le(val);
}

static INLINE u16 decode_u16_le(u8 *data){
	u16 val = *(u16*)(data);
	return u16_le_to_cpu(val);
}

static INLINE void encode_u32_be(u8 *data, u32 val){
	*(u32*)(data) = u32_cpu_to_be(val);
}

static INLINE u32 decode_u32_be(u8 *data){
	u32 val = *(u32*)(data);
	return u32_be_to_cpu(val);
}

static INLINE void encode_u32_le(u8 *data, u32 val){
	*(u32*)(data) = u32_cpu_to_le(val);
}

static INLINE u32 decode_u32_le(u8 *data){
	u32 val = *(u32*)(data);
	return u32_le_to_cpu(val);
}

static INLINE void encode_u64_be(u8 *data, u64 val){
	*(u64*)(data) = u64_cpu_to_be(val);
}

static INLINE u64 decode_u64_be(u8 *data){
	u64 val = *(u64*)(data);
	return u64_be_to_cpu(val);
}

static INLINE void encode_u64_le(u8 *data, u64 val){
	*(u64*)(data) = u64_cpu_to_le(val);
}

static INLINE u64 decode_u64_le(u8 *data){
	u64 val = *(u64*)(data);
	return u64_le_to_cpu(val);
}

#else //ARCH_UNALIGNED_ACCESS

static INLINE void encode_u16_be(u8 *data, u16 val){
	data[0] = (u8)(val >> 8);
	data[1] = (u8)(val);
}

static INLINE u16 decode_u16_be(u8 *data){
	return ((u16)(data[0]) << 8) |
		((u16)(data[1]));
}

static INLINE void encode_u16_le(u8 *data, u16 val){
	data[0] = (u8)(val);
	data[1] = (u8)(val >> 8);
}

static INLINE u16 decode_u16_le(u8 *data){
	return ((u16)(data[0])) |
		((u16)(data[1]) << 8);
}

static INLINE void encode_u32_be(u8 *data, u32 val){
	data[0] = (u8)(val >> 24);
	data[1] = (u8)(val >> 16);
	data[2] = (u8)(val >> 8);
	data[3] = (u8)(val);
}

static INLINE u32 decode_u32_be(u8 *data){
	return ((u32)(data[0]) << 24) |
		((u32)(data[1]) << 16) |
		((u32)(data[2]) << 8) |
		((u32)(data[3]));
}

static INLINE void encode_u32_le(u8 *data, u32 val){
	data[0] = (u8)(val);
	data[1] = (u8)(val >> 8);
	data[2] = (u8)(val >> 16);
	data[3] = (u8)(val >> 24);
}

static INLINE u32 decode_u32_le(u8 *data){
	return ((u32)(data[0])) |
		((u32)(data[1]) << 8) |
		((u32)(data[2]) << 16) |
		((u32)(data[3]) << 24);
}

static INLINE void encode_u64_be(u8 *data, u64 val){
	data[0] = (u8)(val >> 56);
	data[1] = (u8)(val >> 48);
	data[2] = (u8)(val >> 40);
	data[3] = (u8)(val >> 32);
	data[4] = (u8)(val >> 24);
	data[5] = (u8)(val >> 16);
	data[6] = (u8)(val >> 8);
	data[7] = (u8)(val);
}

static INLINE u64 decode_u64_be(u8 *data){
	return ((u64)(data[0]) << 56) |
		((u64)(data[1]) << 48) |
		((u64)(data[2]) << 40) |
		((u64)(data[3]) << 32) |
		((u64)(data[4]) << 24) |
		((u64)(data[5]) << 16) |
		((u64)(data[6]) << 8) |
		((u64)(data[7]));
}

static INLINE void encode_u64_le(u8 *data, u64 val){
	data[0] = (u8)(val);
	data[1] = (u8)(val >> 8);
	data[2] = (u8)(val >> 16);
	data[3] = (u8)(val >> 24);
	data[4] = (u8)(val >> 32);
	data[5] = (u8)(val >> 40);
	data[6] = (u8)(val >> 48);
	data[7] = (u8)(val >> 56);
}

static INLINE u64 decode_u64_le(u8 *data){
	return ((u64)(data[0])) |
		((u64)(data[1]) << 8) |
		((u64)(data[2]) << 16) |
		((u64)(data[3]) << 24) |
		((u64)(data[4]) << 32) |
		((u64)(data[5]) << 40) |
		((u64)(data[6]) << 48) |
		((u64)(data[7]) << 56);
}

#endif //ARCH_UNALIGNED_ACCESS

#endif //BUFFER_UTIL_HH_
