/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _IPC_H
#define _IPC_H

/* ssize_t */
#include <sys/types.h>
#include <errno.h>

#define BUFSIZE 1024
#define MAX_CLIENTS 1024
#define SOCKET_NAME "/tmp/sohack.socket"

#define DIE(assertion, call_description)				\
	do {								\
		if (assertion)	{					\
            strerror(errno);					\
            exit(EXIT_FAILURE);					\
		}							\
	} while (0)

struct sockaddr_un get_sockaddr(const char *path);

int create_socket(void);
int connect_socket(int fd);
ssize_t send_socket(int fd, const char *buf, size_t len);
ssize_t recv_socket(int fd, char *buf, size_t len);
void close_socket(int fd);

#endif /* _IPC_H */
