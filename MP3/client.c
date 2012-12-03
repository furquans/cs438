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

#define SERVER_PORT 5578
#define CLIENT_PORT "5580"

dll_t packet_list;
unsigned int expected_seq = 0;

FILE *fp=NULL;

int client_sockfd=0;
struct sockaddr_in their_addr;
socklen_t their_len;

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

int send_ack()
{
	struct packet *tmp;
	struct packet resp;
	int ret = 0;

	tmp = dll_at(&packet_list,0);

	while (tmp && (tmp->hdr.seq_no == expected_seq)) {
		expected_seq += tmp->hdr.length;
		fwrite(tmp->data,
		       tmp->hdr.length,
		       1,
		       fp);

		if (tmp->hdr.flags & FIN_FLAG) {
			printf("FIN received\n");
			ret = 1;
		}
		dll_remove_from_head(&packet_list);
		free(tmp);
		tmp = dll_at(&packet_list,0);
	}

	resp.hdr.flags |= ACK_FLAG;
	resp.hdr.ack_no = expected_seq;
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

	return ret;
}

void add_to_packet_list(struct packet *curr)
{
	int i = 0;
	int size = dll_size(&packet_list);

	if (curr->hdr.seq_no < expected_seq) {
		return;
	}

	while (i < size) {
		struct packet *tmp = dll_at(&packet_list, i);
		if (tmp->hdr.seq_no == curr->hdr.seq_no) {
			return;
		}
		if (tmp->hdr.seq_no > curr->hdr.seq_no) {
			dll_add_at_index(&packet_list,curr,i);
			return;
		}
		i++;
	}
	dll_add_at_index(&packet_list,curr,i);
}

int main(int argc,
	 char **argv)
{
	struct packet tmp;
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

	dll_init(&packet_list);
	their_len = sizeof(their_addr);

	while((ret = recvfrom(client_sockfd,
			      &tmp,
			      sizeof(tmp),
			      0,
			      (struct sockaddr*)&their_addr,
			      &their_len)) > 0) {
		struct packet *new;

		new = malloc(sizeof(*new));
		*new = tmp;
		printf("seq no:%d\n",tmp.hdr.seq_no);

		add_to_packet_list(new);

		if (send_ack() == 1) {
			break;
		}
	}

	dll_destroy(&packet_list);

	fclose(fp);
	close(client_sockfd);
	return 0;
}
