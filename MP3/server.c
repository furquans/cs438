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
#include "dll.h"

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

int free_data(unsigned int seq_no,
	      dll_t *packet_list)
{
	int count = 0;
	while(dll_size(packet_list)) {
		struct packet *tmp = dll_at(packet_list,0);
		if (tmp->hdr.seq_no < seq_no) {
			dll_remove_from_head(packet_list);
			free(tmp);
			count++;
		} else {
			break;
		}
	}
	return count;
}

void *send_file(void *arg)
{
	FILE *fp;
	char str[MAX_DATA_SIZE];
	int ret;
	int server_sockfd;
	int seq_no = 0;
	struct sockaddr_in their_addr;
	struct sockaddr tmp_addr;
	unsigned int wind_size = 5;
	unsigned int curr_wind = 0;
	fd_set rdfs;
	struct packet resp;
	socklen_t tmp_len;
	dll_t packet_list;

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

	dll_init(&packet_list);
	
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
		tmp->hdr.seq_no = seq_no;
		seq_no += tmp->hdr.length;

		if (sendto(server_sockfd,
			   tmp,
			   count,
			   0,
			   (struct sockaddr*)&their_addr,
			   sizeof(their_addr)) < count) {
			printf("send to failed\n");
			exit(1);
		}

		dll_add_to_tail(&packet_list,tmp);

		curr_wind++;
		printf("curr_wind:%d\n",curr_wind);
		while (curr_wind == wind_size) {
			int retval;
			printf("waiting for ack\n");
			FD_ZERO(&rdfs);
			FD_SET(server_sockfd, &rdfs);

			retval = select(server_sockfd+1,&rdfs,NULL,NULL,NULL);

			if (FD_ISSET(server_sockfd,&rdfs)) {
				if (recvfrom(server_sockfd,
					     &resp,
					     sizeof(resp),
					     0,
					     &tmp_addr,
					     &tmp_len) > 0) {
					if (resp.hdr.flags & ACK_FLAG) {
						curr_wind -= free_data(resp.hdr.ack_no,&packet_list);
						printf("received ack,curr_win=%d\n",curr_wind);
					}
				}
			} else {
				printf("error:%d\n",retval);
			}
		}
	}

	while(dll_size(&packet_list)) {
		int retval;
		FD_ZERO(&rdfs);
		FD_SET(server_sockfd, &rdfs);

		printf("packet waiting for ack\n");
		retval = select(server_sockfd+1,&rdfs,NULL,NULL,NULL);

		if (FD_ISSET(server_sockfd,&rdfs)) {
			if (recvfrom(server_sockfd,
				     &resp,
				     sizeof(resp),
				     0,
				     &tmp_addr,
				     &tmp_len) > 0) {
				if (resp.hdr.flags & ACK_FLAG) {
					curr_wind -= free_data(resp.hdr.ack_no,&packet_list);
					printf("received ack,curr_win=%d\n",curr_wind);
				}
			}
		} else {
			printf("error:%d\n",retval);
		}
	}

	dll_destroy(&packet_list);
	printf("Done sending file\n");
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
