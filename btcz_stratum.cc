// NOTE: STRATUM is the name of the protocol used by mining pools
// to coordinate and distribute work to miners in such a way that
// each miner only has to test for a range of nonce values.

// NOTE: It looks like hex numbers are sent in little endian order
// and that's why I used hex_data_to_u32 and hex_data_to_u256 to
// convert them to numbers instead of their hex_number_* relative.

#include "common.hh"
#include "buffer_util.hh"
#include "json.hh"

#include <winsock2.h>

struct ServerResponse{
	// NOTE: These are the same for every response.
	i32 id;
	bool result;
	bool error_is_null;
	i32 error_code;
	char error_message[256];
	//char error_traceback[256];

	// NOTE: These are specific to the subscribe response.
	u256 nonce1;
	u32 nonce1_bytes;
};

struct ServerCommand_SetTarget{
	u256 target;
};

struct ServerCommand_Notify{
	u32 job;
	u32 version;
	u256 prev_hash;
	u256 merkle_root;
	u256 final_sapling_root;
	u32 time;
	u32 bits;
	bool clean_jobs;
	bool unknown;
};

static
void string_copy(char *dest, i32 dest_len, char *source){
	i32 copy_len = (i32)strlen(source);
	if(copy_len >= dest_len)
		copy_len = dest_len - 1;
	memcpy(dest, source, copy_len);
	dest[copy_len] = 0;
}

static
u32 hex_data_to_u32(const char *hex){
	u8 le_number[4];
	hex_to_buffer(hex, le_number, 4);
	u32 result = decode_u32_le(le_number);
	return result;
}

static
bool parse_server_response_error(JSON_State *json, ServerResponse *response){
	// [error_code, error_message, error_traceback]

	JSON_Token tok;
	if(!json_consume_either(json, &tok, TOKEN_NULL, '['))
		return false;
	response->error_is_null = tok.token == TOKEN_NULL;
	if(response->error_is_null)
		return true;

	// error_code
	if(!json_consume_token(json, &tok, TOKEN_NUMBER)
	|| !json_consume_token(json, NULL, ','))
		return false;
	response->error_code = (i32)tok.token_number;

	// error_message
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	string_copy(response->error_message,
		sizeof(response->error_message),
		tok.token_string);

	// error_traceback (skip for now)
	if(!json_consume_token(json, NULL, TOKEN_STRING))
		return false;

	return json_consume_token(json, NULL, ']');
}

static
bool parse_server_response_subscribe_result(JSON_State *json, ServerResponse *response){
	JSON_Token tok;
	if(!json_consume_either(json, &tok, TOKEN_NULL, '['))
		return false;
	response->result = (tok.token != TOKEN_NULL);
	if(response->result){
		// session_id (skip for now)
		if(!json_consume_either(json, &tok, TOKEN_STRING, TOKEN_NULL)
		|| !json_consume_token(json, NULL, ','))
			return false;

		// nonce1
		if(!json_consume_token(json, &tok, TOKEN_STRING))
			return false;
		response->nonce1 = hex_data_to_u256(tok.token_string);
		response->nonce1_bytes = count_hex_digits(tok.token_string) / 2;
		if(response->nonce1_bytes & 2)
			return false;

		if(!json_consume_token(json, NULL, ']'))
			return false;
	}
	return true;
}

static
bool parse_server_response_common_result(JSON_State *json, ServerResponse *response){
	JSON_Token tok;
	if(!json_consume_boolean(json, &tok))
		return false;
	response->result = tok.token_boolean;
	return true;
}

static
bool parse_server_command_set_target(
		JSON_State *json, ServerCommand_SetTarget *out){
	// PARAMS: ["target"]
	JSON_Token tok;
	if(!json_consume_token(json, NULL, '[')
	|| !json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ']'))
		return false;
	out->target = hex_data_to_u256(tok.token_string);
	return true;
}

static
bool parse_server_command_notify(
		JSON_State *json, ServerCommand_Notify *out){
	// PARAMS: [
	//	"job_id", "version", "prevhash", "merkleroot",
	//	"reserved", "time", "bits", clean_jobs, ??
	// ]

	if(!json_consume_token(json, NULL, '['))
		return false;

	JSON_Token tok;

	// job_id
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	out->job = hex_data_to_u32(tok.token_string);

	// version
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	out->version = hex_data_to_u32(tok.token_string);

	// prev_hash
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	out->prev_hash = hex_data_to_u256(tok.token_string);

	// merkle_root
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	out->merkle_root = hex_data_to_u256(tok.token_string);

	// final_sapling_root
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	out->final_sapling_root = hex_data_to_u256(tok.token_string);

	// time
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	out->time = hex_data_to_u32(tok.token_string);

	// bits
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	out->bits = hex_data_to_u32(tok.token_string);

	// clean_jobs
	if(!json_consume_boolean(json, &tok)
	|| !json_consume_token(json, NULL, ','))
		return false;
	out->clean_jobs = tok.token_boolean;

	// unknown
	if(!json_consume_boolean(json, NULL))
		return false;

#if 1
	// TODO: Remove.
	printf("job = %08X\n", out->job);
	printf("version = %08X\n", out->version);
	print_buf("prev_hash", out->prev_hash.data, 32);
	print_buf("merkle_root", out->merkle_root.data, 32);
	print_buf("final_sapling_root", out->final_sapling_root.data, 32);
	printf("time = %08X\n", out->time);
	printf("bits = %08X\n", out->bits);
	printf("clean_jobs = %s\n",
		out->clean_jobs ? "true" : "false");
#endif

	return json_consume_token(json, NULL, ']');
}

struct STRATUM{
	// TODO: Use this struct.

	//
	// NOTE: We need to keep an id counter (next_id) for
	// each message we send the server. We also need to
	// keep the id of the latest id we used to send a
	// particular message because the response will contain
	// the same id and it should be used to determine which
	// response we should parse. This is mostly because
	// the protocol permits sending and receiving messages
	// out of order.
	//
	i32 next_id;
	i32 subscribe_id;
	i32 authorize_id;
	i32 submit_id;

	// NOTE: Some bookkeeping.
	i32 num_sent_command_subscribe;
	i32 num_sent_command_authorize;
	i32 num_sent_command_submit;
	i32 num_recv_response_subscribe;
	i32 num_recv_response_authorize;
	i32 num_recv_response_submit;
	i32 num_recv_command_set_target;
	i32 num_recv_command_notify;

	// subscribe response
	u256 nonce1;
	u32 nonce1_bytes;

	// set_target command
	u256 target;

	// notify command
	u32 job;
	u32 version;
	u256 prev_hash;
	u256 merkle_root;
	u256 final_sapling_root;
	u32 time;
	u32 bits;
};

static
bool handshake(SOCKET s,
		const char *connect_addr,
		const char *connect_port,
		const char *user,
		const char *password){
	char buf[4096];

	// 1 - SEND SUBSCRIBE
	{
		// PARAMS: ["user_agent", "session_id", "connect_addr", "connect_port"]
		static const char fmt_c2s_subscribe[] =
			"{"
				"\"id\": 1,"
				"\"method\": \"mining.subscribe\","
				"\"params\": [\"%s\", null, \"%s\", \"%s\"]"
			"}\n";

		int writelen = snprintf(buf, sizeof(buf), fmt_c2s_subscribe,
				"BTCZRefMiner/0.1", connect_addr, connect_port);
		DEBUG_ASSERT(writelen < sizeof(buf));

		int ret = send(s, buf, writelen, 0);
		if(ret <= 0){
			LOG_ERROR("failed to send \"mining.subscribe\" message (ret = %d)\n", ret);
			return false;
		}
	}

	// 2 - SEND AUTHORIZE
	{
		// PARAMS: ["user", "password"]
		static const char fmt_c2s_authorize[] =
			"{"
				"\"id\": 2,"
				"\"method\": \"mining.authorize\","
				"\"params\": [\"%s\", \"%s\"]"
			"}\n";

		int writelen = snprintf(buf, sizeof(buf),
				fmt_c2s_authorize, user, password);
		DEBUG_ASSERT(writelen < sizeof(buf));

		int ret = send(s, buf, writelen, 0);
		if(ret <= 0){
			LOG_ERROR("failed to send \"mining.authorize\" message (ret = %d)\n", ret);
			return false;
		}
	}

	bool got_server_response_subscribe = false;
	bool got_server_response_authorize = false;
	bool got_server_command_set_target = false;
	bool got_server_command_notify = false;
	while(!got_server_response_subscribe
			|| !got_server_response_authorize
			|| !got_server_command_set_target
			|| !got_server_command_notify){
		int ret = recv(s, buf, sizeof(buf), 0);
		if(ret <= 0){
			LOG_ERROR("recv failed (ret = %d)\n", ret);
			return false;
		}

		// NOTE: There may be one or more server messages in a
		// single packet.
		if(buf[ret - 1] != '\n')
			return false;
		buf[ret - 1] = 0;
		JSON_State json = json_init((u8*)buf);
		while(json_consume_token(&json, NULL, '{')){
			JSON_Token tok;
			if(!json_consume_key(&json, "id")
			|| !json_consume_either(&json, &tok, TOKEN_NUMBER, TOKEN_NULL)
			|| !json_consume_token(&json, NULL, ','))
				return false;
	
			if(tok.token == TOKEN_NUMBER){
				// server response
				if(!json_consume_key(&json, "result"))
					return false;

				ServerResponse response;
				if(tok.token_number == 1){
					// subscribe response
					if(!parse_server_response_subscribe_result(&json, &response)
					|| !json_consume_token(&json, NULL, ',')
					|| !json_consume_key(&json, "error")
					|| !parse_server_response_error(&json, &response))
						return false;
	
					// TODO: We need to make a sort of STATE that will keep track
					// of all the parameters at all times and whenever get a server
					// message, we should just pass along this single STATE struct
					// to be updated.

					if(!response.result){
						DEBUG_ASSERT(!response.error_is_null);
						LOG_ERROR("\"mining.subscribe\" failed: (%d) %s\n",
							response.error_code, response.error_message);
						return false;
					}

					// response.nonce1
					// response.nonce1_bytes
					print_buf("mining.subscribe nonce1", response.nonce1.data, 32);

					got_server_response_subscribe = true;
				}else if(tok.token_number == 2){
					// authorize response
					if(!parse_server_response_common_result(&json, &response)
					|| !json_consume_token(&json, NULL, ',')
					|| !json_consume_key(&json, "error")
					|| !parse_server_response_error(&json, &response))
						return false;

					if(!response.result){
						DEBUG_ASSERT(!response.error_is_null);
						LOG_ERROR("\"mining.authorize\" failed: (%d) %s\n",
							response.error_code, response.error_message);
						return false;
					}

					got_server_response_authorize = true;
				}else{
					return false;
				}
			}else{
				// server message
				if(!json_consume_key(&json, "method")
				|| !json_consume_token(&json, &tok, TOKEN_STRING)
				|| !json_consume_token(&json, NULL, ',')
				|| !json_consume_key(&json, "params"))
					return false;

				if(strcmp("mining.set_target", tok.token_string) == 0){
					// set_target
					ServerCommand_SetTarget cmd;
					if(!parse_server_command_set_target(&json, &cmd))
						return false;
					got_server_command_set_target = true;
				}else if(strcmp("mining.notify", tok.token_string) == 0){
					// notify
					ServerCommand_Notify cmd;
					if(!parse_server_command_notify(&json, &cmd))
						return false;	
					got_server_command_notify = true;
				}else{
					return false;
				}
			}

			if(!json_consume_token(&json, NULL, '}'))
				return false;
		}

	}
	return true;
}

static
void c2s_submit_work(SOCKET s){
	// ANSWER: {"id": $, "result": true, "error": null}
	// PARAMS: ["user", "job_id", "time", "nonce2", "eh_solution"]
	static const char fmt_c2s_submit[] =
		"{"
			"\"id\": %d,"
			"\"method\": \"mining.submit\","
			"\"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"]"
		"}\n";
}

#define CHECK(condition, ...)			\
	if(!(condition)){					\
		LOG_ERROR(__VA_ARGS__);			\
		exit(-1);						\
	}
int main(int argc, char **argv){
	// NOTE: We're currently only figuring out the protocol and one
	// of the BTCZ mining pools is https://btcz.darkfibermines.com/
	// and it'll be the one we'll test the protocol.

	// NOTE: Big endian is used for network byte order so whenever we
	// use htons or htonl, we're actually converting from the cpu native
	// byte order into big endian byte order. If the native byte order
	// is already big endian, no convertion is done.

	const char *user = "t1Rxx8pUgs29isFXV8mjDPuBbNf22SDqZGq";
	const char *password = "x";
	const char *connect_addr = "142.4.211.28";
	const char *connect_port = "4000";

	u8 server_ipv4_addr[4] = { 142, 4, 211, 28 };
	u32 server_addr =
		  ((u32)server_ipv4_addr[0] << 0)
		| ((u32)server_ipv4_addr[1] << 8)
		| ((u32)server_ipv4_addr[2] << 16)
		| ((u32)server_ipv4_addr[3] << 24);
	//u32 server_addr = decode_u32_le(server_ipv4_addr);
	u16 server_port = htons(4000);

	while(1){
		SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
		CHECK(s != INVALID_SOCKET, "failed to create server socket");
	
		{
			sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_port = server_port;
			addr.sin_addr.s_addr = server_addr;
			int connect_result = connect(s, (sockaddr*)&addr, sizeof(sockaddr_in));
			CHECK(connect_result == 0, "failed to connect to server");
		}
	
		LOG("connected...\n");
		LOG("handshake = %d\n", handshake(s, connect_addr, connect_port, user, password));


		closesocket(s);
		break;
	}
}

struct WSAInit{
	WSAInit(void){
		WSADATA dummy;
		if(WSAStartup(MAKEWORD(2, 2), &dummy) != 0){
			LOG_ERROR("failed to initialize windows sockets\n");
			abort();
		}
	}
	~WSAInit(void){
		WSACleanup();
	}
};
static WSAInit wsa_init;
