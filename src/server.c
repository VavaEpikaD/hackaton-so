// SPDX-License-Identifier: BSD-3-Clause

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h> // nou
#include <sys/socket.h> // nou
#include <sys/wait.h> // nou
#include <sys/epoll.h> // nou
#include <unistd.h>

#include "ipc.h"
#include "server.h"

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

int epollfd;
struct epoll_event ev, events[1000];

static int lib_prehooks(struct lib *lib)
{
	/* TODO: Implement lib_prehooks(). */
	return 0;
}

static int lib_load(struct lib *lib)
{
	/* TODO: Implement lib_load(). */

	lib->handle = dlopen(lib->libname, RTLD_LAZY);
	if(!lib->handle) {
		return -1;
	}

	dlerror();

	if (strcmp(lib->funcname, "") == 0) {
		strcpy(lib->funcname, "run");
	}

	char buf[BUFSIZE];

	if (strcmp(lib->filename, "") != 0) {
		lib->p_run = dlsym(lib->handle, lib->funcname);
		if (dlerror()) {
			return -1;
		}
	} else {
		lib->run = dlsym(lib->handle, lib->funcname);
		if (dlerror()) {
			return -1;
		}
	}

	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */
	strcpy(lib->outputfile, OUTPUT_TEMPLATE);
	int fd = mkstemp(lib->outputfile);
	DIE(fd < 0, "mkstemp");

	int pid = fork();
	DIE(pid < 0, "fork");

	if (pid == 0) {
		dup2(fd, STDOUT_FILENO);

		if (lib->p_run) {
			lib->p_run(lib->filename);
		} else {
			lib->run();
		}
		close(fd);

		exit(0);
	}

	// int rc = waitpid(pid, NULL, 0);
	// DIE(rc < 0, "waitpid");

	close(fd);
	
	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	int rc = dlclose(lib->handle);
	DIE(rc < 0, "dlclose");

	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	/* TODO: Implement lib_posthooks(). */
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err) {
		fprintf(stderr, "asuhda\n");
		return err;
	}

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;

	ret = sscanf(buf, "%s %s %s", name, func, params);
	if (ret < 0)
		return -1;

	return ret;
}

int main(void)
{
	/* TODO: Implement server connection. */
	int ret, sockfd, connectfd;
	char buf[BUFSIZE];
	struct lib lib;
	lib.libname = calloc(1, BUFSIZE);
	DIE(lib.libname == NULL, "calloc");
	lib.funcname = calloc(1, BUFSIZE);
	DIE(lib.funcname == NULL, "calloc");
	lib.filename = calloc(1, BUFSIZE);
	DIE(lib.filename == NULL, "calloc");
	lib.outputfile = calloc(1, BUFSIZE);
	DIE(lib.outputfile == NULL, "calloc");
	lib.p_run = NULL;
	lib.run = NULL;

	epollfd = epoll_create1(0);
    DIE(epollfd < 0, "epoll_create1");

	setvbuf(stdout, NULL, _IONBF, 0);

	sockfd = create_socket();
	DIE(sockfd < 0, "create_socket");

	struct sockaddr_un addr = get_sockaddr(SOCKET_NAME);

	unlink(SOCKET_NAME);
	int rc = bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
	DIE(rc < 0, "bind");

	while (1) {
		/* TODO - get message from client */

		ret = listen(sockfd, 1);
		DIE(ret < 0, "listen");

		connectfd = accept(sockfd, NULL, NULL);
		DIE(connectfd < 0, "accept");

		ev.events = EPOLLIN; // Monitor for incoming connections
		ev.data.fd = connectfd;
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, connectfd, &ev) == -1) {
			perror("epoll_ctl: listen_fd");
			exit(EXIT_FAILURE);
		}

		/* TODO - parse message with parse_command and populate lib */
		memset(buf, 0, BUFSIZE);
		ret = recv_socket(connectfd, buf, BUFSIZE);
		DIE(ret < 0, "recv_socket");

		ret = parse_command(buf, lib.libname, lib.funcname, lib.filename);
		DIE(ret < 0, "parse_command");

		/* TODO - handle request from client */
		char buf[BUFSIZE];
		int fd;
		ret = lib_run(&lib);
		if (ret < 0) {
			strcpy(lib.outputfile, OUTPUT_TEMPLATE);
			fd = mkstemp(lib.outputfile);
			DIE(fd < 0, "mkstemp");
			
			sprintf(buf, "Error: %s %s %s could not be executed.\n", lib.libname, lib.funcname, lib.filename);

			write(fd, buf, strlen(buf));
		}

		ret = send_socket(connectfd, lib.outputfile, strlen(lib.outputfile));
		DIE(ret < 0, "send_socket");

		close_socket(connectfd);
	}

	int nfds = epoll_wait(epollfd, events, 1000, -1);
	if (nfds == -1) {
		perror("epoll_wait");
		exit(EXIT_FAILURE);
	}

	close_socket(sockfd);
	free(lib.libname);
	free(lib.funcname);
	free(lib.filename);
	free(lib.outputfile);

	return 0;
}
