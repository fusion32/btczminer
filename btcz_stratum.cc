// NOTE: STRATUM is the name of the protocol used by mining pools
// to coordinate and distribute work to miners in such a way that
// each miner only has to test for a range of nonce values.

#include "common.hh"
#include "buffer_util.hh"
#include "json.hh"

#include <winsock2.h>

struct STRATUM{
	SOCKET server;
	const char *connect_addr;
	const char *connect_port;
	const char *user;
	const char *password;

	// NOTE: We need to keep an id counter (next_id) for
	// each message we send the server. We also need to
	// keep the id of the latest id we used to send a
	// particular message because the response will contain
	// the same id and it should be used to determine which
	// response we should parse. This is mostly because
	// the protocol permits sending and receiving messages
	// out of order.
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

	bool connection_closed;
	bool connection_error;
	bool update_params;
	MiningParams params;
};

struct ServerResponse{
	bool result;
	bool error_is_null;
	i32 error_code;
	char error_message[256];
};

// ----------------------------------------------------------------
// some extra utility
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
char hexch(u8 digit){
	if(digit <= 0x09){
		return '0' + digit;
	}else if(digit <= 0x0F){
		return 'a' - 0x0A + digit;
	}else{
		return '?';
	}
}

static
void __u8_to_hex(char *dest, u8 source){
	dest[1] = hexch((source >> 0) & 0x0F);
	dest[0] = hexch((source >> 4) & 0x0F);
}

static
void u32_to_hex_le(char *dest, u32 source){
	__u8_to_hex(dest + 0, (u8)(source >>  0));
	__u8_to_hex(dest + 2, (u8)(source >>  8));
	__u8_to_hex(dest + 4, (u8)(source >> 16));
	__u8_to_hex(dest + 6, (u8)(source >> 24));
	dest[8] = 0;
}

static
void u256_to_hex_le(char *dest, u256 source, i32 source_offset){
	i32 insert_pos = 0;
	for(i32 i = source_offset; i < 32; i += 1){
		__u8_to_hex(dest + insert_pos, source.data[i]);
		insert_pos += 2;
	}
	dest[insert_pos] = 0;
}

static
void eh_solution_to_hex(char *dest, EH_Solution source){
	// NOTE: This will work for BTCZ only since this length
	// that is added at the beggining is in "compact" form
	// and can be larger than 1 byte.
	DEBUG_ASSERT(EH_PACKED_SOLUTION_BYTES == 0x64);
	__u8_to_hex(dest, EH_PACKED_SOLUTION_BYTES);
	for(i32 i = 0; i < EH_PACKED_SOLUTION_BYTES; i += 1)
		__u8_to_hex(dest + 2 * (i + 1), source.packed[i]);
	dest[2 * (EH_PACKED_SOLUTION_BYTES + 1)] = 0;
}

// ----------------------------------------------------------------
// (client -> server) message handling
// ----------------------------------------------------------------

static
bool send_command_subscribe(STRATUM *S, const char *user_agent,
		const char *connect_addr, const char *connect_port){
	static const char fmt_subscribe[] =
		"{"
			"\"id\":%d,"
			"\"method\":\"mining.subscribe\","
			"\"params\":[\"%s\", null, \"%s\", \"%s\"]"
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
		S->connection_closed = (ret == 0);
		S->connection_error = (ret < 0);
		return false;
	}

	S->next_id += 1;
	S->subscribe_id = id;
	S->num_sent_command_subscribe += 1;
	return true;
}

static
bool send_command_authorize(STRATUM *S,
		const char *user, const char *password){
	static const char fmt_authorize[] =
		"{"
			"\"id\":%d,"
			"\"method\":\"mining.authorize\","
			"\"params\":[\"%s\", \"%s\"]"
		"}\n";

	char buf[2048];
	i32 id = S->next_id;
	int writelen = snprintf(buf, sizeof(buf), fmt_authorize,
			id, user, password);
	DEBUG_ASSERT(writelen < sizeof(buf));

	int ret = send(S->server, buf, writelen, 0);
	if(ret <= 0){
		LOG_ERROR("send failed (ret = %d, error = %d)\n",
			ret, WSAGetLastError());
		S->connection_closed = (ret == 0);
		S->connection_error = (ret < 0);
		return false;
	}

	S->next_id += 1;
	S->authorize_id = id;
	S->num_sent_command_authorize += 1;
	return true;
}

static
bool send_command_submit(
		STRATUM *S, MiningParams *params,
		u256 nonce, EH_Solution eh_solution){
	static const char fmt_submit[] =
		"{"
			"\"id\":%d,"
			"\"method\":\"mining.submit\","
			"\"params\":[\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"]"
		"}\n";

	char hex_time[32];
	u32_to_hex_le(hex_time, params->time);

	char hex_nonce[128];
	u256_to_hex_le(hex_nonce, nonce, params->nonce1_bytes);

	// NOTE: These will do for BTCZ only since the packed solution for
	// ZEC is 1344 bytes which translates to 2688 hex characters.
	char hex_sol[256];
	eh_solution_to_hex(hex_sol, eh_solution);


	char buf[2048];
	i32 id = S->next_id;
	int writelen = snprintf(buf, sizeof(buf), fmt_submit,
			id, S->user, params->job_id, hex_time, hex_nonce, hex_sol);
	DEBUG_ASSERT(writelen < sizeof(buf));

	int ret = send(S->server, buf, writelen, 0);
	if(ret <= 0){
		LOG_ERROR("send failed (ret = %d, error = %d)\n",
			ret, WSAGetLastError());
		S->connection_closed = (ret == 0);
		S->connection_error = (ret < 0);
		return false;
	}

	S->next_id += 1;
	S->submit_id = id;
	S->num_sent_command_submit += 1;
	return true;
}

// ----------------------------------------------------------------
// (server -> client) message handling
// ----------------------------------------------------------------

static
bool parse_server_response_subscribe_result(
		JSON_State *json, ServerResponse *response, MiningParams *params){
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
		params->nonce1 = hex_le_to_u256(tok.token_string);
		params->nonce1_bytes = count_hex_digits(tok.token_string) / 2;
		if(params->nonce1_bytes & 2)
			return false;

		if(!json_consume_token(json, NULL, ']'))
			return false;
	}
	return true;
}

static
bool parse_server_response_common_result(JSON_State *json, ServerResponse *response){
	JSON_Token tok;
	if(json_consume_boolean(json, &tok)){
		response->result = tok.token_boolean;
		return true;
	}
	if(!json_consume_token(json, NULL, TOKEN_NULL))
		return false;
	response->result = false;
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
	if(!json_consume_token(json, &tok, TOKEN_STRING))
		return false;
	string_copy(response->error_message,
		sizeof(response->error_message),
		tok.token_string);

	// NOTE: This error traceback seems to be optional and
	// since we aren't interested in it we'll parse it when
	// it's there but we'll ignore it always.
	if(json_consume_token(json, NULL, ',')
	&& !json_consume_token(json, NULL, TOKEN_STRING))
		return false;

	return json_consume_token(json, NULL, ']');
}

static
bool parse_server_command_set_target(JSON_State *json, MiningParams *params){
	// NOTE: The target here must be parsed in big endian order.
	// This is really confusing since other u256s are parsed in
	// little endian order.

	// PARAMS: ["target"]
	JSON_Token tok;
	if(!json_consume_token(json, NULL, '[')
	|| !json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ']'))
		return false;
	params->target = hex_be_to_u256(tok.token_string);
	return true;
}

static
bool parse_server_command_notify(JSON_State *json, MiningParams *params){
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
	string_copy(params->job_id, sizeof(params->job_id), tok.token_string);

	// version
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	params->version = hex_le_to_u32(tok.token_string);

	// prev_hash
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	params->prev_hash = hex_le_to_u256(tok.token_string);

	// merkle_root
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	params->merkle_root = hex_le_to_u256(tok.token_string);

	// final_sapling_root
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	params->final_sapling_root = hex_le_to_u256(tok.token_string);

	// time
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	params->time = hex_le_to_u32(tok.token_string);

	// bits
	if(!json_consume_token(json, &tok, TOKEN_STRING)
	|| !json_consume_token(json, NULL, ','))
		return false;
	params->bits = hex_le_to_u32(tok.token_string);

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
bool consume_messages_aux(STRATUM *S){
	while(inbound_data(S->server)){
		char buf[4096];
		int ret = recv(S->server, buf, sizeof(buf), 0);
		if(ret <= 0){
			LOG_ERROR("recv failed (ret = %d, error = %d)\n",
				ret, WSAGetLastError());
			S->connection_closed = (ret == 0);
			S->connection_error = (ret < 0);
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
				const char *method = "unknown";
				ServerResponse response;
				if(response_id == S->submit_id){
					// NOTE: Since we only do "mining.subscribe" and "mining.authorize"
					// at the beggining of the session, we'll be handling exclusively
					// "mining.submit" responses so it only makes sense that it is
					// checked first.
					if(!parse_server_response_common_result(&json, &response)
					|| !json_consume_token(&json, NULL, ',')
					|| !json_consume_key(&json, "error")
					|| !parse_server_response_error(&json, &response))
						return false;
					S->num_recv_response_submit += 1;
					method = "mining.submit";
				}else if(response_id == S->subscribe_id){
					// NOTE: We don't add "S->update_params = true" in here
					// because this message is sent to the server at the
					// beggining of the session and it should be sent only
					// once. It means that whenever we get the nonce1 from
					// this response we won't need to update it until we
					// disconnect or get disconnected.
					if(!parse_server_response_subscribe_result(&json, &response, &S->params)
					|| !json_consume_token(&json, NULL, ',')
					|| !json_consume_key(&json, "error")
					|| !parse_server_response_error(&json, &response))
						return false;
					S->num_recv_response_subscribe += 1;
					method = "mining.subscribe";
				}else if(response_id == S->authorize_id){
					if(!parse_server_response_common_result(&json, &response)
					|| !json_consume_token(&json, NULL, ',')
					|| !json_consume_key(&json, "error")
					|| !parse_server_response_error(&json, &response))
						return false;
					S->num_recv_response_authorize += 1;
					method = "mining.authorize";
				}else{
					return false;
				}

				if(!response.result){
					if(response.error_is_null){
						LOG_ERROR("\"%s\" failed without"
							" description of the error\n", method);
					}else{
						LOG_ERROR("\"%s\" failed: (%d) %s\n", method,
							response.error_code, response.error_message);
					}
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
					if(!parse_server_command_set_target(&json, &S->params))
						return false;
					S->num_recv_command_set_target += 1;
					S->update_params = true;
				}else if(strcmp("mining.notify", tok.token_string) == 0){
					// notify
					if(!parse_server_command_notify(&json, &S->params))
						return false;	
					S->num_recv_command_notify += 1;
					S->update_params = true;
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
void consume_messages(STRATUM *S){
	if(!consume_messages_aux(S) && (S->connection_closed || S->connection_error)){
		if(S->connection_closed)
			LOG("connection has been closed by the server\n");
		if(S->connection_error)
			LOG("connection error has occurred\n");
		closesocket(S->server);

		LOG("reconnecting...\n");
		STRATUM *tmp = btcz_stratum_connect(
			S->connect_addr, S->connect_port,
			S->user, S->password, NULL);
		if(!tmp){
			FATAL_ERROR("reconnect failed\n");
			return;
		}
		*S = *tmp;
		free(tmp);
	}
}

// ----------------------------------------------------------------
// server thread
// ----------------------------------------------------------------

static
bool handshake(STRATUM *S,
		const char *connect_addr, const char *connect_port,
		const char *user, const char *password){

	if(!send_command_subscribe(S, "BTCZRefMiner/0.1", connect_addr, connect_port)){
		LOG_ERROR("failed to send `subscribe` message\n");
		return false;
	}

	if(!send_command_authorize(S, user, password)){
		LOG_ERROR("failed to send `authorize` message\n");
		return false;
	}

	// NOTE: Loop while we don't have the necessary
	// information to start working.
	while(S->num_recv_response_subscribe == 0
			|| S->num_recv_response_authorize == 0
			|| S->num_recv_command_set_target == 0
			|| S->num_recv_command_notify == 0){
		consume_messages(S);
	}
	return true;
}

static
bool parse_ip_string(const char *str, u32 *out){
	u32 ip0, ip1, ip2, ip3;
	if(sscanf(str, "%u.%u.%u.%u", &ip0, &ip1, &ip2, &ip3) != 4)
		return false;
	if(ip0 > 255 || ip1 > 255 || ip2 > 255 || ip3 > 255)
		return false;
	*out = (ip0 << 0) | (ip1 << 8) | (ip2 << 16) | (ip3 << 24);
	return true;
}

static
bool parse_port_string(const char *str, u16 *out){
	u32 port;
	if(sscanf(str, "%u", &port) != 1)
		return false;
	if(port > 0xFFFF)
		return false;
	*out = u16_cpu_to_be((u16)port);
	return true;
}

STRATUM *btcz_stratum_connect(
		const char *connect_addr,
		const char *connect_port,
		const char *user,
		const char *password,
		MiningParams *out_params){

	u32 server_addr;
	u16 server_port;
	if(!parse_ip_string(connect_addr, &server_addr)){
		LOG_ERROR("failed to parse server address\n");
		return NULL;
	}
	if(!parse_port_string(connect_port, &server_port)){
		LOG_ERROR("failed to parse server port");
		return NULL;
	}

	SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if(server == INVALID_SOCKET){
		LOG_ERROR("failed to create server socket (error = %d)\n",
			WSAGetLastError());
		return NULL;
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
		closesocket(server);
		return NULL;
	}

	STRATUM *S = (STRATUM*)malloc(sizeof(STRATUM));
	memset(S, 0, sizeof(STRATUM));
	S->server = server;
	S->connect_addr = connect_addr;
	S->connect_port = connect_port;
	S->user = user;
	S->password = password;
	S->next_id = 1;
	if(!handshake(S, connect_addr, connect_port, user, password)){
		LOG_ERROR("failed to do server handshake\n");
		closesocket(server);
		free(S);
		return NULL;
	}
	if(out_params){
		S->update_params = false;
		*out_params = S->params;
	}else{
		S->update_params = true;
	}
	return S;
}

bool btcz_stratum_submit_solution(
		STRATUM *S, MiningParams *params,
		u256 nonce, EH_Solution solution){
	// TODO: We should do a submit queue.
	if(!send_command_submit(S, params, nonce, solution))
		return false;

	i32 prev = S->num_recv_response_submit;
	while(prev == S->num_recv_response_submit)
		consume_messages(S);
	return true;
}

bool btcz_stratum_update_params(
		STRATUM *S, MiningParams *out_params){
	consume_messages(S);
	if(S->update_params){
		S->update_params = false;
		*out_params = S->params;
		return true;
	}
	return false;
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
