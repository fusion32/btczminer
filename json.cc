// NOTE: This is a simplified JSON lexer for the
// purpose of parsing STRATUM messages.

#include "json.hh"

static bool ch_is_num(int ch){
	return ch >= 48 && ch <= 57; // 0-9 characters
}
static bool ch_is_hex(int ch){
	return (ch >= 48 && ch <= 57) // 0-9 characters
		|| (ch >= 65 && ch <= 70) // A-F characters
		|| (ch >= 97 && ch <= 102); // a-f characters
}

static
void json_lexnumber(JSON_State *state, JSON_Token *tok){
	// NOTE: We're only lexing integers.
	bool negative = false;
	if(state->ptr[0] == '+'){
		negative = false;
		state->ptr += 1;
	}else if(state->ptr[0] == '-'){
		negative = true;
		state->ptr += 1;
	}

	i64 result = 0;
	while(ch_is_num(state->ptr[0])){
		result = result * 10 + (state->ptr[0] - '0');
		state->ptr += 1;
	}

	if(negative)
		result *= -1;

	tok->token = TOKEN_NUMBER;
	tok->token_number = result;
}

static
bool json_lexstring(JSON_State *state, JSON_Token *tok){
	state->ptr += 1; // skip opening quote
	u8 *start = state->ptr;
	while(state->ptr[0] && state->ptr[0] != '"'){
		// disallow control characters
		if(state->ptr[0] < 0x20){
			return false; // unexpected character
		// allow some escape sequences
		}else if(state->ptr[0] == '\\' && state->ptr[1]){
			switch(state->ptr[1]){
				case '"': case '\\': case '/': case 'b':
				case 'f': case 'n': case 'r': case 't':
					state->ptr += 2;
					break;

				// \uXXXX
				case 'u':
					if(!(ch_is_hex(state->ptr[2]) && ch_is_hex(state->ptr[3])
					  && ch_is_hex(state->ptr[4]) && ch_is_hex(state->ptr[5]))){
						return false; // unexpected character
					}
					state->ptr += 6;
					break;
	
				default:
					return false; // unexpected escape sequence
			}
		}else{
			state->ptr += 1;
		}
	}

	if(state->ptr[0]){
		u8 *end = state->ptr;
		usize len = end - start;
		tok->token = TOKEN_STRING;
		if(len >= sizeof(tok->token_string))
			len = sizeof(tok->token_string) - 1;
		memcpy(tok->token_string, start, len);
		tok->token_string[len] = 0;
		state->ptr += 1; // skip closing quote
		return true;
	}else{
		return false; // unexpected EOF
	}
}

void json_next_token(JSON_State *state, JSON_Token *tok){
	while(true){
		switch(state->ptr[0]){
			// whitespace
			case '\n': case '\r':
				if((state->ptr[0] == '\n' && state->ptr[1] == '\r')
				|| (state->ptr[0] == '\r' && state->ptr[1] == '\n')){
					state->ptr += 2;
				}else{
					state->ptr += 1;
				}
				continue;
			case '\t': case ' ':
				state->ptr += 1;
				continue;

			// end of file
			case '\0':
				tok->token = TOKEN_EOF;
				return;

			// number
			case '-':
				if(!ch_is_num(state->ptr[1])){
					tok->token = TOKEN_INVALID;
					return;
				}
				FALLTHROUGH;

			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				json_lexnumber(state, tok);
				return;

			// string
			case '"':
				if(!json_lexstring(state, tok))
					tok->token = TOKEN_INVALID;
				return;

			// ascii tokens
			case ',':
			case ':':
			case '[':
			case ']':
			case '{':
			case '}':
				tok->token = state->ptr[0];
				state->ptr += 1;
				return;

			default:
				if(strncmp((const char*)state->ptr, "true", 4) == 0){
					tok->token = TOKEN_TRUE;
					tok->token_boolean = true;
					state->ptr += 4;
				}else if(strncmp((const char*)state->ptr, "false", 5) == 0){
					tok->token = TOKEN_FALSE;
					tok->token_boolean = false;
					state->ptr += 5;
				}else if(strncmp((const char*)state->ptr, "null", 4) == 0){
					tok->token = TOKEN_NULL;
					state->ptr += 4;
				}else{
					tok->token = TOKEN_INVALID;
				}
				return;
		}
	}
}

JSON_State json_init(u8 *json_string){
	JSON_State result;
	result.ptr = json_string;
	json_next_token(&result, &result.tok);
	return result;
}

bool json_consume_token(JSON_State *state, JSON_Token *tok, int token){
	if(state->tok.token == token){
		if(tok) *tok = state->tok;
		json_next_token(state, &state->tok);
		return true;
	}
	return false;
}

bool json_consume_either(JSON_State *state, JSON_Token *tok, int token1, int token2){
	if(state->tok.token == token1 || state->tok.token == token2){
		if(tok) *tok = state->tok;
		json_next_token(state, &state->tok);
		return true;
	}
	return false;
}

bool json_consume_boolean(JSON_State *state, JSON_Token *tok){
	return json_consume_either(state, tok, TOKEN_TRUE, TOKEN_FALSE);
}

bool json_consume_key(JSON_State *state, const char *key){
	JSON_Token tok;
	if(!json_consume_token(state, &tok, TOKEN_STRING))
		return false;
	if(!json_consume_token(state, NULL, ':'))
		return false;
	return strcmp(key, tok.token_string) == 0;
}
