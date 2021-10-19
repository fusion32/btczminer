// NOTE: STRATUM is the name of the protocol used by mining pools
// to coordinate and distribute work to miners in such a way that
// each miner only has to test for a range of nonce values.

#include "common.hh"
#include "buffer_util.hh"
#include "json.hh"

#include <winsock2.h>

struct STRATUM{
	SOCKET server;

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


	// NOTE: All data required to mine.

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

struct ServerResponse{
	// NOTE: These are the same for every response.
	bool result;
	bool error_is_null;
	i32 error_code;
	char error_message[256];
	//char error_traceback[256];
};

// ----------------------------------------------------------------
// (client -> server) message handling
// ----------------------------------------------------------------

static
bool send_subscribe_command(STRATUM *S, const char *user_agent,
		const char *connect_addr, const char *connect_port){
	static const char fmt_subscribe[] =
		"{"
			"\"id\": %d,"
			"\"method\": \"mining.subscribe\","
			"\"params\": [\"%s\", null, \"%s\", \"%s\"]"
		"}\n";

	char buf[2048];
	i32 id = S->next_id;
	int writelen = snprintf(buf, sizeof(buf), fmt_subscribe,
			id, user_agent, connect_addr, connect_port);
	DEBUG_ASSERT(writelen < sizeof(buf));

	int ret = send(S->server, buf, writelen, 0);
	if(ret <= 0){
		LOG_ERROR("send failed (ret = %d, error = %d)\n",
			ret, WSAGetLastError());
		return false;
	}

	S->next_id += 1;
	S->subscribe_id = id;
	S->num_sent_command_subscribe += 1;
	return true;
}

static
bool send_authorize_command(STRATUM *S,
		const char *user, const char *password){
	static const char fmt_authorize[] =
		"{"
			"\"id\": %d,"
			"\"method\": \"mining.authorize\","
			"\"params\": [\"%s\", \"%s\"]"
		"}\n";

	char buf[2048];
	i32 id = S->next_id;
	int writelen = snprintf(buf, sizeof(buf),
			fmt_authorize, id, user, password);
	DEBUG_ASSERT(writelen < sizeof(buf));

	int ret = send(S->server, buf, writelen, 0);
	if(ret <= 0){
		LOG_ERROR("send failed (ret = %d, error = %d)\n",
			ret, WSAGetLastError());
		return false;
	}

	S->next_id += 1;
	S->authorize_id = id;
	S->num_sent_command_authorize += 1;
	return true;
}

#if 0
static
void send_submit_command(STRATUM *S){
	// ANSWER: {"id": $, "result": true, "error": null}
	// PARAMS: ["user", "job_id", "time", "nonce2", "eh_solution"]
	static const char fmt_c2s_submit[] =
		"{"
			"\"id\": %d,"
			"\"method\": \"mining.submit\","
			"\"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"]"
		"}\n";
}
#endif

// ----------------------------------------------------------------
// (server -> client) message handling
// ----------------------------------------------------------------

static
void string_copy(char *dest, i32 dest_len, char *source){
	i32 copy_len = (i32)strlen(source);
	if(copy_len >= dest_len)
		copy_len = dest_len - 1;
	memcpy(dest, source, copy_len);
	dest[copy_len] = 0;
}

static
u32 hex_le_to_u32(const char *hex){
	u8 le_number[4];
	hex_to_buffer(hex, le_number, 4);
	u32 result = decode_u32_le(le_number);
	return result;
}

static
bool parse_server_response_subscribe_result(
		JSON_State *json, ServerResponse *response, STRATUM *S){
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
		S->nonce1 = hex_le_to_u256(tok.token_string);
		S->nonce1_bytes = count_hex_digits(tok.token_string) / 2;
		if(S->nonce1_bytes & 2)
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
bool parse_server_command_set_target(JSON_State *json, STRATUM *S){
	// NOTE: The target here must be parsed in big endian order.
	// This is really confusing since other u256s are parsed in
	// little endian order.

	// PARAMS: ["target"]
	JSON_Token tok;
	if(!json_consume_token(json, NULL, '[')
	|| !json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ']'))
		return false;
	S->target = hex_be_to_u256(tok.token_string);
	return true;
}

static
bool parse_server_command_notify(JSON_State *json, STRATUM *S){
	// NOTE: All hex strings here must be parsed in little endian
	// order.

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
	S->job = hex_le_to_u32(tok.token_string);

	// version
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	S->version = hex_le_to_u32(tok.token_string);

	// prev_hash
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	S->prev_hash = hex_le_to_u256(tok.token_string);

	// merkle_root
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	S->merkle_root = hex_le_to_u256(tok.token_string);

	// final_sapling_root
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	S->final_sapling_root = hex_le_to_u256(tok.token_string);

	// time
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	S->time = hex_le_to_u32(tok.token_string);

	// bits
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	S->bits = hex_le_to_u32(tok.token_string);

	// clean_jobs
	if(!json_consume_boolean(json, &tok))
		return false;
	// TODO: Do we need a job queue?
	//S->clean_jobs = tok.token_boolean;
	if(!tok.token_boolean)
		return false;

	// NOTE: This last unknown boolean seems to be optional
	// as it does not appear in some of the server messages.
	if(json_consume_token(json, NULL, ',')
	&& !json_consume_boolean(json, &tok))
		return false;
	//S->unknown = tok.token_boolean;

	return json_consume_token(json, NULL, ']');
}

static
bool inbound_data(SOCKET s){
	timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(s, &readfds);
	int ret = select(0, &readfds, NULL, NULL, &timeout);
	if(ret == SOCKET_ERROR){
		LOG_ERROR("select failed (ret = %d, error = %d)\n",
			ret, WSAGetLastError());
		return false;
	}
	return FD_ISSET(s, &readfds);
}

static
bool consume_messages(STRATUM *S){
	while(inbound_data(S->server)){
		char buf[4096];
		int ret = recv(S->server, buf, sizeof(buf), 0);
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

				i32 response_id = (i32)tok.token_number;
				ServerResponse response;
				if(response_id == S->subscribe_id){
					// subscribe response
					if(!parse_server_response_subscribe_result(&json, &response, S)
					|| !json_consume_token(&json, NULL, ',')
					|| !json_consume_key(&json, "error")
					|| !parse_server_response_error(&json, &response))
						return false;
					if(!response.result){
						if(response.error_is_null){
							LOG_ERROR("\"mining.subscribe\" failed"
								" without description of the error\n");
						}else{
							LOG_ERROR("\"mining.subscribe\" failed: (%d) %s\n",
								response.error_code, response.error_message);
						}
						return false;
					}
					S->num_recv_response_subscribe += 1;
				}else if(response_id == S->authorize_id){
					// authorize response
					if(!parse_server_response_common_result(&json, &response)
					|| !json_consume_token(&json, NULL, ',')
					|| !json_consume_key(&json, "error")
					|| !parse_server_response_error(&json, &response))
						return false;
					if(!response.result){
						if(response.error_is_null){
							LOG_ERROR("\"mining.authorize\" failed"
								" without description of the error\n");
						}else{
							LOG_ERROR("\"mining.authorize\" failed: (%d) %s\n",
								response.error_code, response.error_message);
						}
						return false;
					}
					S->num_recv_response_authorize += 1;
				}else if(response_id == S->submit_id){
					if(!parse_server_response_common_result(&json, &response)
					|| !json_consume_token(&json, NULL, ',')
					|| !json_consume_key(&json, "error")
					|| !parse_server_response_error(&json, &response))
						return false;
					if(!response.result){
						if(response.error_is_null){
							LOG_ERROR("\"mining.submit\" failed"
								" without description of the error\n");
						}else{
							LOG_ERROR("\"mining.submit\" failed: (%d) %s\n",
								response.error_code, response.error_message);
						}
						return false;
					}
					S->num_recv_response_submit += 1;
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
					if(!parse_server_command_set_target(&json, S))
						return false;
					S->num_recv_command_set_target += 1;
				}else if(strcmp("mining.notify", tok.token_string) == 0){
					// notify
					if(!parse_server_command_notify(&json, S))
						return false;	
					S->num_recv_command_notify += 1;
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

// ----------------------------------------------------------------
// server thread
// ----------------------------------------------------------------

static
bool handshake(STRATUM *S,
		const char *connect_addr, const char *connect_port,
		const char *user, const char *password){

	if(!send_subscribe_command(S, "BTCZRefMiner/0.1", connect_addr, connect_port)){
		LOG_ERROR("failed to send `subscribe` message\n");
		return false;
	}

	if(!send_authorize_command(S, user, password)){
		LOG_ERROR("failed to send `authorize` message\n");
		return false;
	}

	// NOTE: Loop while we don't have the necessary
	// information to start working.
	while(S->num_recv_response_subscribe == 0
			|| S->num_recv_response_authorize == 0
			|| S->num_recv_command_set_target == 0
			|| S->num_recv_command_notify == 0){
		if(!consume_messages(S))
			return false;
	}
	return true;
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

	SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if(server == INVALID_SOCKET){
		LOG_ERROR("failed to create server socket (error = %d)\n",
			WSAGetLastError());
		return -1;
	}

	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = server_port;
	addr.sin_addr.s_addr = server_addr;
	int ret = connect(server, (sockaddr*)&addr, sizeof(sockaddr_in));
	if(ret != 0){
		LOG_ERROR("failed to connect to server"
			" (ret = %d, error = %d)\n",
			ret, WSAGetLastError());
		return -1;
	}

	LOG("connected...\n");

	STRATUM S = {};
	S.server = server;
	S.next_id = 1;
	if(!handshake(&S, connect_addr, connect_port, user, password)){
		LOG_ERROR("failed to do server handshake\n");
		return -1;
	}

	LOG("handshake... ok\n");

	// TODO: receive submit commands from the mining thread
	// and consume mining parameters from the server to feed
	// the mining thread
	//consume_messages(&S);

	closesocket(S.server);
	return 0;
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
