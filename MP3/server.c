#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<netdb.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<pthread.h>

#include "header.h"

#define MAX_FILENAME_LEN 50
#define SERVER_PORT "5578"
#define CLIENT_PORT 5580

char filename[MAX_FILENAME_LEN];

int create_udp_socket(char *port)
{
	int sockfd;
	struct addrinfo hints, *servinfo, *p;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(NULL,
			port,
			&hints,
			&servinfo) != 0) {
		perror("getaddrinfo");
		exit(1);
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				     p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		printf("Failed to bind\n");
		sockfd = -1;
	}

	freeaddrinfo(servinfo);

	return sockfd;
}

void prepare_for_udp_send(struct sockaddr_in *their_addr,
			  int port)
{
	struct hostent *he;

	if ((he=gethostbyname("localhost")) == NULL) {
		printf("gethostname failed\n");
		exit(1);
	}

	their_addr->sin_family = AF_INET;
	their_addr->sin_port = htons(port);
	their_addr->sin_addr = *((struct in_addr *)he->h_addr);
	memset(their_addr->sin_zero, '\0', sizeof(their_addr->sin_zero));
}

void *send_file(void *arg)
{
	FILE *fp;
	char str[MAX_DATA_SIZE];
	int ret;
	int server_sockfd;
	int seq_no = 1;
	struct sockaddr_in their_addr;

	printf("Server:sending file %s to client\n",filename);

	fp = fopen(filename,"r+");

	if (fp == NULL) {
		printf("Error opening file\n");
		exit(1);
	}

	server_sockfd = create_udp_socket(SERVER_PORT);

	if (server_sockfd == -1) {
		printf("Socket error\n");
		exit(1);
	}

	prepare_for_udp_send(&their_addr,
			     CLIENT_PORT);

	while ((ret = fread(str,
			    sizeof(char),
			    MAX_DATA_SIZE,
			    fp)) != 0) {
		struct packet *tmp;
		int count = sizeof(struct header) + ret;

		tmp = malloc(sizeof(*tmp));
		memcpy(tmp->data,
		       str,
		       ret);
		tmp->hdr.length = ret;
		tmp->hdr.seq_no = seq_no++;

		if (sendto(server_sockfd,
			   tmp,
			   count,
			   0,
			   (struct sockaddr*)&their_addr,
			   sizeof(their_addr)) < count) {
			printf("send to failed\n");
			exit(1);
		}
	}

	return arg;
}

int main(int argc,char **argv)
{
	pthread_t server_tid;

	if (argc != 2) {
		printf("Usage:%s <filename>\n",argv[0]);
		exit(1);
	}

	strcpy(filename,
	       argv[1]);

	pthread_create(&server_tid,
		       NULL,
		       &send_file,
		       NULL);
	while(1);
}
