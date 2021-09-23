#include "common.hh"

#include <stdio.h>
#include <winsock2.h>

#define CHECK(condition, ...)			\
	if(!(condition)){					\
		LOG_ERROR(__VA_ARGS__);			\
		exit(-1);						\
	}

void log_packet(i32 packet_num, i32 debug_num, const char *debug_name, u8 *buf, i32 buflen){
	char filename[256];
	snprintf(filename, NARRAY(filename),
		"log/%04d_%s_%04d.txt", packet_num, debug_name, debug_num);
	FILE *fp = fopen(filename, "w+");
	if(!fp){
		LOG_ERROR("failed to open file `%s` for writing\n", filename);
		return;
	}

	fprintf(fp, "HEX:\n");
	for(i32 i = 0; i < buflen; i += 1){
		if((i & 31) == 31)
			fprintf(fp, "%02X\n", buf[i]);
		else
			fprintf(fp, "%02X ", buf[i]);
	}
	fprintf(fp, "\n");

	fprintf(fp, "TXT:\n");
	for(i32 i = 0; i < buflen; i += 1){
		int c = isprint(buf[i]) ? buf[i] : '.';
		if((i & 31) == 31)
			fprintf(fp, "%c\n", c);
		else
			fprintf(fp, "%c ", c);
	}
	fprintf(fp, "\n");
	fclose(fp);
}

int proxy_main(int argc, char **argv){
	// 142.4.211.28:4000
	u8 server_ipv4_addr[4] = { 142, 4, 211, 28 };
	u32 server_addr =
		  ((u32)server_ipv4_addr[0] << 0)
		| ((u32)server_ipv4_addr[1] << 8)
		| ((u32)server_ipv4_addr[2] << 16)
		| ((u32)server_ipv4_addr[3] << 24);
	u16 server_port = htons(4000);
	u16 proxy_port = server_port;

	SOCKET proxy = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	CHECK(proxy != INVALID_SOCKET, "failed to create proxy socket\n");

	{
		sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = proxy_port;
		addr.sin_addr.s_addr = INADDR_ANY;
		int bind_result = bind(proxy, (sockaddr*)&addr, sizeof(sockaddr_in));
		CHECK(bind_result == 0, "failed to bind to port %d\n", ntohs(proxy_port));
	}

	{
		int listen_result = listen(proxy, SOMAXCONN);
		CHECK(listen_result == 0, "failed to start listening\n");
	}

	LOG("serving...\n");
	while(1){
		SOCKET client = accept(proxy, NULL, NULL);
		CHECK(client != INVALID_SOCKET, "failed to accept new connection\n");
		LOG("new connection!\n");
		LOG("connecting to server...\n");

		SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
		CHECK(server != INVALID_SOCKET, "failed to create server socket\n");
		{
			sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_port = server_port;
			addr.sin_addr.s_addr = server_addr;
			int connect_result = connect(server, (sockaddr*)&addr, sizeof(sockaddr_in));
			CHECK(connect_result == 0, "failed to connect to server\n");
		}
		LOG("connected!\n");

		i32 packet_num = 0;
		i32 client_to_server_num = 0;
		i32 server_to_client_num = 0;
		while(1){
			u8 buf[4096];
			int ret;
			fd_set readfds;
			FD_ZERO(&readfds);
			FD_SET(client, &readfds);
			FD_SET(server, &readfds);
			ret = select(0, &readfds, NULL, NULL, NULL);
			CHECK(ret != SOCKET_ERROR, "select failed (ret = %d)\n", ret);

			// route from client -> server
			if(FD_ISSET(client, &readfds)){
				ret = recv(client, (char*)buf, NARRAY(buf), 0);
				if(ret <= 0){
					LOG("client connection closed on recv (ret = %d)\n", ret);
					break;
				}
				log_packet(packet_num++, client_to_server_num++,
					"client_to_server", buf, ret);

				ret = send(server, (char*)buf, ret, 0);
				if(ret <= 0){
					LOG_ERROR("server connection closed on send (ret = %d)\n", ret);
					break;
				}
			}

			// route from server -> client
			if(FD_ISSET(server, &readfds)){
				ret = recv(server, (char*)buf, NARRAY(buf), 0);
				if(ret <= 0){
					LOG_ERROR("server connection closed on recv (ret = %d)\n", ret);
					break;
				}
				log_packet(packet_num++, server_to_client_num++,
					"server_to_client", buf, ret);

				ret = send(client, (char*)buf, ret, 0);
				if(ret <= 0){
					LOG("client connection closed on send (ret = %d)\n", ret);
					break;
				}
			}
		}

		closesocket(client);
		closesocket(server);
	}
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
