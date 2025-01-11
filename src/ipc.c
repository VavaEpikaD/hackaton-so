// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"

struct sockaddr_un get_sockaddr(const char *path)
{
	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, strlen(path) + 1, "%s", path);

	return addr;
}

int create_socket(void)
{
	/* TODO: Implement create_socket(). */
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	DIE(sockfd < 0, "socket");
	return sockfd;
}

int connect_socket(int fd)
{
	/* TODO: Implement connect_socket(). */
	struct sockaddr_un addr = get_sockaddr(SOCKET_NAME);

	int rc = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
	DIE(rc < 0, "connect");

	return rc;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	/* TODO: Implement send_socket(). */
	ssize_t sent = send(fd, buf, len, 0);
	DIE(sent < 0, "send");
	return sent;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	/* TODO: Implement recv_socket(). */
	ssize_t received = recv(fd, buf, len, 0);
	DIE(received < 0, "recv");
	return received;
}

void close_socket(int fd)
{
	/* TODO: Implement close_socket(). */
	int rc = close(fd);
	DIE(rc < 0, "close");
}
