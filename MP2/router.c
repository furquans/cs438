#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "dll.h"
#include "error.h"
#include "router.h"

dll_t node_list;
char myaddr[MAX_ADDR_LEN];
int manager_sockfd;
int udp_sockfd;

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
		exit(SOCK_ERROR);
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

void send_msg_to_manager(char *msg)
{
	int count = strlen(msg);
	if (send(manager_sockfd,
		 msg,
		 count,
		 0) < count) {
		exit(SOCK_ERROR);
	}
}

int recv_msg_from_manager(char *msg)
{
	int ret;
#define MAX_MSG_LEN 100
	if ((ret = recv(manager_sockfd,
			msg,
			MAX_MSG_LEN,
			0)) == -1) {
		exit(SOCK_ERROR);
	}

	msg[ret-1] = '\0';
	return ret;
}

void get_addr_from_manager()
{
#define ADDR_STR_LEN 25
	char addr[MAX_MSG_LEN];

	send_msg_to_manager(HELO_MSG);

	recv_msg_from_manager(addr);

	strcpy(myaddr,
	       &addr[5]);

	printf("My address is:%s\n",myaddr);
}

bool send_udp_details_to_manager(char *hostname,
				char *udpport)
{
	char msg[25];
	char resp[MAX_MSG_LEN];

	sprintf(msg, HOST_MSG "%s %s\n",hostname, udpport);

	send_msg_to_manager(msg);

	recv_msg_from_manager(resp);

	return (strcmp(resp,
		       OK_MSG) == 0);
}

void add_new_node(char *str)
{
	char *ptr;
	struct node *tmp = malloc(sizeof(*tmp));

	if (tmp == NULL) {
		exit(MEM_ALLOC_ERROR);
	}

	str += 6;

	/* Extract address */
	ptr = strtok(str, " ");
	strcpy(tmp->addr,
	       ptr);

	/* Extract hostname */
	ptr = strtok(NULL, " ");
	strcpy(tmp->hostname,
	       ptr);

	/* Extract udp port */
	ptr = strtok(NULL, " ");
	tmp->udp_port = atoi(ptr);

	/* Extract cost */
	ptr = strtok(NULL, " ");
	tmp->cost = atoi(ptr);

	/* Add the node to tail of the list */
	dll_add_to_tail(&node_list, tmp);
}

bool get_neigh_details_from_manager()
{
	char resp[MAX_MSG_LEN];
	char *ptr;

	send_msg_to_manager(NEIGH_MSG);

	do {
		memset(resp, 0, MAX_MSG_LEN);
		recv_msg_from_manager(resp);
		ptr = strchr(resp, '\n');
		if (ptr) {
			*ptr = '\0';
			ptr++;
		}
		printf("%s\n",resp);
		add_new_node(resp);
	} while((ptr == NULL) || strcmp(ptr, "DONE"));

	send_msg_to_manager(READY_MSG);
	recv_msg_from_manager(resp);
	return (strcmp(resp,
		       OK_MSG) == 0);
}

void print_node_list()
{
	int i;
	struct node *tmp;
	int size = dll_size(&node_list);


	printf(" Addr  Hostname   Port  Cost\n");
	for (i=0;i<size;i++) {
		tmp = dll_at(&node_list, i);
		printf("%5s ",tmp->addr);
		printf("%10s ",tmp->hostname);
		printf("%5u ",tmp->udp_port);
		printf("%5d\n",tmp->cost);
	}
}

void update_cost_for_node(char *ptr,
			  int cost)
{
	int i;
	struct node *tmp;
	int size = dll_size(&node_list);

	for (i=0;i<size;i++) {
		tmp = dll_at(&node_list, i);
		if (!strcmp(tmp->addr, ptr)) {
			tmp->cost = cost;
			break;
		}
	}
}

void update_cost_of_link(char *msg)
{
	char *node1, *node2, *ptr;
	int cost;
	char resp[MAX_MSG_LEN];

	node1 = strtok(msg + strlen(LINK_COST_MSG) + 1, " ");
	node2 = strtok(NULL, " ");
	cost  = atoi(strtok(NULL, " "));

	ptr = strcmp(node1,myaddr)?node1:node2;
	printf("Update:%s %s %d\n",node1,node2,cost);

	update_cost_for_node(ptr, cost);
	print_node_list();

	sprintf(resp, "COST %d OK\n", cost);
	send_msg_to_manager(resp);
}

void listen_for_events()
{
	char msg[MAX_MSG_LEN];
	do {
		recv_msg_from_manager(msg);

		if (!strncmp(msg,
			     LINK_COST_MSG,
			     strlen(LINK_COST_MSG))) {
			update_cost_of_link(msg);
		} else if (!strcmp(msg,
				   END_MSG)) {
			printf("END\n");
			send_msg_to_manager(BYE_MSG);
			break;
		}
	} while(1);
}

int main(int argc, char **argv)
{
	if (argc != 4) {
		printf("Usage: %s <manager hostname> <TCP port of manager> <UDP port of router>\n",argv[0]);
		exit(USAGE_ERROR);
	}

	/* Create a TCP connection with the manager */
	manager_sockfd = create_tcp_connection(argv[1],
				       argv[2]);

	if (manager_sockfd == -1) {
		exit(TCP_CONNECTION_ERROR);
	}

	/* Get self address from manager */
	get_addr_from_manager();

	/* Send self details to manager */
	if (!send_udp_details_to_manager(argv[1],
					 argv[3])) {
		exit(MANAGER_ERROR);
	}

	/* Initialize head of the list */
	dll_init(&node_list);

	/* Get neighbour details */
	if (!get_neigh_details_from_manager()) {
		exit(MANAGER_ERROR);
	}

	/* Print node list */
	print_node_list();

	/* Listen for incoming messages / events */
	listen_for_events();

	printf("success\n");
	close(manager_sockfd);
	return 0;
}
