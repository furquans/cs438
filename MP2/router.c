#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define HELO_MSG  "HELO\n"
#define READY_MSG "READY\n"
#define NEIGH_MSG "NEIGH?\n"

typedef unsigned char bool;

int create_tcp_connection(char *hostname,
			  char *port)
{
	struct addrinfo hints, *servinfo, *p;
	int sockfd;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(hostname,
			port,
			&hints,
			&servinfo) != 0) {
		perror("getaddrinfo");
		exit(1);
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family,
				     p->ai_socktype,
				     p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}

		if (connect(sockfd,
			    p->ai_addr,
			    p->ai_addrlen) == -1) {
			close(sockfd);
			perror("connect");
			continue;
		}
		break;
	}

	if (p == NULL) {
		printf("Failed to connect\n");
		sockfd = -1;
	}

	return sockfd;
}

void send_msg_to_manager(int sockfd,
			 char *msg)
{
	int count = strlen(msg);
	if (send(sockfd,
		 msg,
		 count,
		 0) < count) {
		printf("Error: msg sending error to manager\n");
		exit(1);
	}
}

bool recv_msg_from_manager(int sockfd,
			   char *msg)
{
	int ret;
#define MAX_MSG_LEN 100
	if ((ret = recv(sockfd,
			msg,
			MAX_MSG_LEN,
			0)) == -1) {
		printf("Error: HELO reply error\n");
		exit(1);
	}

	msg[ret-1] = '\0';
	return ret;
}

void get_addr_from_manager(int sockfd,
			   char *myaddr)
{
#define ADDR_STR_LEN 25
	char addr[MAX_MSG_LEN];

	send_msg_to_manager(sockfd,
			    HELO_MSG);

	recv_msg_from_manager(sockfd,
			      addr);

	strcpy(myaddr,
	       &addr[5]);

	printf("Received string:%s\n",addr);
}

bool send_udp_details_to_manager(int sockfd,
				char *hostname,
				char *udpport)
{
	char msg[25];
	char resp[MAX_MSG_LEN];

	sprintf(msg, "HOST %s %s\n",hostname, udpport);

	send_msg_to_manager(sockfd, msg);

	recv_msg_from_manager(sockfd, resp);

	return (strcmp(resp,
		       "OK") == 0);
}

int get_neigh_details_from_manager(int sockfd)
{
	char resp[MAX_MSG_LEN];
	char *ptr;

	send_msg_to_manager(sockfd, NEIGH_MSG);

	do {
		memset(resp, 0, MAX_MSG_LEN);
		recv_msg_from_manager(sockfd, resp);
		ptr = strchr(resp, '\n');
		if (ptr) {
			*ptr = '\0';
			ptr++;
		}
		printf("received msg:%s\n",resp);
	} while((ptr == NULL) || strcmp(ptr, "DONE"));

	send_msg_to_manager(sockfd, READY_MSG);
	recv_msg_from_manager(sockfd, resp);
	return (strcmp(resp,
		       "OK") == 0);
}

int main(int argc, char **argv)
{
	int sockfd;
	char myaddr[10];

	if (argc != 4) {
		printf("Usage: %s <manager hostname> <TCP port of manager> <UDP port of router>\n",argv[0]);
		exit(1);
	}

	/* Create a TCP connection with the manager */
	sockfd = create_tcp_connection(argv[1],
				       argv[2]);

	if (sockfd == -1) {
		exit(1);
	}

	/* Get self address from manager */
	get_addr_from_manager(sockfd,myaddr);

	/* Send self details to manager */
	if (!send_udp_details_to_manager(sockfd,
					 argv[1],
					 argv[3])) {
		printf("Error from manager in step 1\n");
		exit(1);
	}

	if (!get_neigh_details_from_manager(sockfd)) {
		printf("Error from manager in step 2\n");
		exit(1);
	}

	printf("success\n");
	close(sockfd);
}
