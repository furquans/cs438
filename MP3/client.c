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

#define SERVER_PORT 5578
#define CLIENT_PORT "5580"

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

int main(int argc,
	 char **argv)
{
	FILE *fp;
	int client_sockfd;
	struct sockaddr_in their_addr;
	socklen_t their_len;
	struct packet tmp;
	char str[MAX_DATA_SIZE+1];
	int ret;

	if (argc != 2) {
		printf("Usage:%s <filename>\n",argv[0]);
		exit(1);
	}

	fp = fopen(argv[1],"w+");

	if (fp == NULL) {
		printf("Error opening file\n");
		exit(1);
	}

	client_sockfd = create_udp_socket(CLIENT_PORT);

	if (client_sockfd == -1) {
		printf("Socket error\n");
		exit(1);
	}

	their_len = sizeof(their_addr);
	while((ret = recvfrom(client_sockfd,
			      &tmp,
			      sizeof(tmp),
			      0,
			      (struct sockaddr*)&their_addr,
			      &their_len)) > 0) {
		struct packet resp;
		memcpy(str,
		       tmp.data,
		       MAX_DATA_SIZE-1);
		str[ret-sizeof(struct header)] = '\0';
		printf("%s",str);
		fwrite(tmp.data,
		       tmp.hdr.length,
		       1,
		       fp);

		resp.hdr.flags |= ACK_FLAG;
		resp.hdr.ack_no = tmp.hdr.seq_no + tmp.hdr.length;
		resp.hdr.length = 0;

		if (sendto(client_sockfd,
			   &resp,
			   sizeof(struct header),
			   0,
			   (struct sockaddr*)&their_addr,
			   sizeof(their_addr)) < (int)sizeof(struct header)) {
			perror("sendto");
			exit(1);
		}
			  

		if (ret < 100) {
			break;
		}
	}

	fclose(fp);
	close(client_sockfd);
	return 0;
}
