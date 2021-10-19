#ifndef JSON_HH_
#define JSON_HH_

#include "common.hh"

enum{
	// single-character tokens use their ASCII code values
	// ',', ':', '[', ']', '{', '}'

	TOKEN_EOF = 128,
	TOKEN_NUMBER,
	TOKEN_STRING,
	TOKEN_TRUE,
	TOKEN_FALSE,
	TOKEN_NULL,

	TOKEN_INVALID,	// special token to signal an error on the lexer
};

struct JSON_Token{
	int token;
	union{
		i64 token_number;
		char token_string[256];
		bool token_boolean;
	};
};

struct JSON_State{
	u8 *ptr;
	JSON_Token tok;
};

JSON_State json_init(u8 *json_string);
bool json_consume_token(JSON_State *state, JSON_Token *tok, int token);
bool json_consume_either(JSON_State *state, JSON_Token *tok, int token1, int token2);
bool json_consume_boolean(JSON_State *state, JSON_Token *tok);
bool json_consume_key(JSON_State *state, const char *key);

#endif //JSON_HH_
