#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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

void get_addr_from_manager(int sockfd,
			   char *myaddr)
{
#define ADDR_STR_LEN 25
	char msg[] = "HELO\n";
	char addr[ADDR_STR_LEN];
	int count;

	count = strlen(msg);

	if (send(sockfd,
		 msg,
		 count,
		 0) < count) {
		printf("Error: HELO write failed\n");
		exit(1);
	}

	if ((count = recv(sockfd,
			  addr,
			  ADDR_STR_LEN,
			  0)) == -1) {
		printf("Error: HELO reply error\n");
		exit(1);
	}

	addr[count-1] = '\0';
	strcpy(myaddr,
	       &addr[5]);
	printf("Received string:%s\n",addr);
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
	printf("%s\n",myaddr);

	close(sockfd);
}
