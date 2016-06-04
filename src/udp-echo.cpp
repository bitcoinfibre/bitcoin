// You probably want g++ -std=c++11 -Wall -o udp-echo -DHAVE_CONFIG_H -I. -Iconfig -lpthread -lanl -lboost_system -lboost_thread -lboost_filesystem -lboost_program_options -lcrypto -lrt crypto/sha256.cpp crypto/sha256_avx1.a util.cpp utiltime.cpp utilstrencodings.cpp netbase.cpp chainparamsbase.cpp random.cpp support/cleanse.cpp udp-echo.cpp

#include <sys/socket.h>
#include <assert.h>

#include "netbase.h"

int main(int argc, const char** argv) {
	if (argc < 4) {
		fprintf(stderr, "USAGE: %s listen_port (host:port)*\n", argv[0]);
		return 1;
	}

	struct sockaddr_in6 nodes[argc - 2];
	for (int i = 2; i < argc; i++) {
		CService addr;
		if (!Lookup(argv[i], addr, -1, true) || !addr.IsValid()) {
			fprintf(stderr, "Failed to lookup %s\n", argv[i]);
			return 1;
		}
		memset(&nodes[i - 2], 0, sizeof(nodes[i - 2]));
		nodes[i - 2].sin6_family = AF_INET6;
		assert(addr.GetIn6Addr(&nodes[i - 2].sin6_addr));
		nodes[i - 2].sin6_port = htons(addr.GetPort());
	}

	char *endptr = NULL;
	long port = strtol(argv[1], &endptr, 10);
	if (*endptr != 0 || port <= 0 || port >= 65536) {
		fprintf(stderr, "Failed to parse listen_port\n");
		return 1;
	}

	int udp_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	assert(udp_sock);

	int opt = 1;
	assert(setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &opt,  sizeof(opt)) == 0);
	opt = 0;
	assert(setsockopt(udp_sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt,  sizeof(opt)) == 0);
	//fcntl(udp_sock, F_SETFL, fcntl(udp_sock, F_GETFL) | O_NONBLOCK);

	struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	memcpy(&addr.sin6_addr, &in6addr_any, sizeof(in6addr_any));
	addr.sin6_port = htons(port);

	if (bind(udp_sock, (sockaddr*) &addr, sizeof(addr))) {
		close(udp_sock);
		fprintf(stderr, "Failed to bind listen socket\n");
		return 1;
	}

	char msg[1500];
	socklen_t addrlen = sizeof(addr);
	while (true) {
		ssize_t res = recvfrom(udp_sock, msg, sizeof(msg), 0, (sockaddr*)&addr, &addrlen);
		assert(res >= 0);
		assert(addrlen == sizeof(addr));

		for (int i = 0; i < argc - 2; i++) {
			if (memcmp(&nodes[i].sin6_addr, &addr.sin6_addr, sizeof(addr.sin6_addr)) || nodes[i].sin6_port != addr.sin6_port)
				assert(sendto(udp_sock, msg, res, 0, (const sockaddr*)&nodes[i], sizeof(nodes[i])) == res);
		}
	}

	return 0;
}
