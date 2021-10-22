#include "common.hh"

static
i32 hexdigit(u8 c){
	static const i8 hex_to_digit[256] = {
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20
		 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, // 0x30
		-1, 10, 11, 12, 13, 14, 15, 16, -1, -1, -1, -1, -1, -1, -1, -1, // 0x40
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x50
		-1, 10, 11, 12, 13, 14, 15, 16, -1, -1, -1, -1, -1, -1, -1, -1, // 0x60
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x70
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
	};
	return hex_to_digit[c];
}

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

void hex_to_buffer_inv(const char *hex, u8 *buf, i32 buflen){
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

i32 count_hex_digits(const char *hex){
	if(hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
		hex += 2;
	i32 result = 0;
	while(hexdigit(*hex++) != -1)
		result += 1;
	return result;
}

void print_buf(const char *debug_name, u8 *buf, i32 buflen){
	printf("buf (%s, len = %d):\n", debug_name, buflen);
	for(i32 i = 0; i < buflen; i += 1){
		if((i & 15) == 15)
			printf("%02X\n", buf[i]);
		else
			printf("%02X ", buf[i]);
	}

	if(buflen & 15)
		printf("\n");
}

static
void u32_to_hex_le(char *dest, i32 dest_len, u32 source){
	DEBUG_ASSERT(dest_len >= 9);
	for(i32 i = 0; i < 4; i += 1){
		u8 b = source >> (i * 8);
		//dest[i*2 + 0] = source >>;
	}
	dest[0] = (char)((source >> 0));
	dest[8] = 0;
}

static
void u256_to_hex_le(char *dest, i32 dest_len, u256 source){
	//
}

static
void eh_solution_to_hex(char *dest, i32 dest_len, EH_Solution source){
	//
}
