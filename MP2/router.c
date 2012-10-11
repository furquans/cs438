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
bool logging_enabled;

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

	freeaddrinfo(servinfo);

	return sockfd;
}

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
		exit(SOCK_ERROR);
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

int recv_msg(int sockfd,
	     char *msg,
	     int len)
{
	int ret;
	if ((ret = recvfrom(sockfd,
			     msg,
			     len,
			     0,
			     NULL,
			     NULL)) < 0) {
		exit(SOCK_ERROR);
	}
	return ret;
}

int recv_msg_from_manager(char *msg)
{
	int ret = recv_msg(manager_sockfd,
			   msg,
			   MAX_MGR_MSG_LEN);
	msg[ret-1] = '\0';
	return ret;
}

int recv_msg_from_router(char *msg)
{
	return recv_msg(udp_sockfd,
			msg,
			MAX_RTR_MSG_LEN);
}

void get_addr_from_manager()
{
#define ADDR_STR_LEN 25
	char addr[MAX_MGR_MSG_LEN];

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
	char resp[MAX_MGR_MSG_LEN];

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
	char resp[MAX_MGR_MSG_LEN];
	char *ptr;

	send_msg_to_manager(NEIGH_MSG);

	do {
		memset(resp, 0, MAX_MGR_MSG_LEN);
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

void enable_logging()
{
	char resp[MAX_MGR_MSG_LEN];

	send_msg_to_manager(LOG_MSG "\n");

	recv_msg_from_manager(resp);

	if (!strcmp(resp,
		    LOG_MSG)) {
		printf("Logging on\n");
	}
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
	char resp[MAX_MGR_MSG_LEN];

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

int handle_manager_event()
{
	int ret_val = 0;
	char msg[MAX_MGR_MSG_LEN];

	recv_msg_from_manager(msg);

	if (!strncmp(msg,
		     LINK_COST_MSG,
		     strlen(LINK_COST_MSG))) {
		update_cost_of_link(msg);
	} else if (!strcmp(msg,
			   END_MSG)) {
		printf("END\n");
		send_msg_to_manager(BYE_MSG);
		ret_val = -1;
	}

	return ret_val;
}

void handle_router_event()
{
	char msg[MAX_RTR_MSG_LEN];
	char dest[3];

	recv_msg_from_router(msg);

	if (msg[0]  == '1') {
		printf("Type 1 message\n");
	}
	dest[0] = msg[1];
	dest[1] = msg[2];
	dest[2] = '\0';
	printf("Destination = %s\n", dest);
	printf("msg:%s\n",msg);
}

void listen_for_events()
{
	int result, max_fd;
	fd_set readset;

	do {

		do {
			FD_ZERO(&readset);
			FD_SET(manager_sockfd, &readset);
			FD_SET(udp_sockfd, &readset);
			max_fd = udp_sockfd > manager_sockfd ? udp_sockfd : manager_sockfd;
			result = select(max_fd+1, &readset, NULL, NULL, NULL);
		} while (result == -1);

		if (result > 0) {
			if (FD_ISSET(manager_sockfd, &readset)) {
				/* Some data on manager socket */
				if (handle_manager_event() == -1) {
					break;
				}
			} else if (FD_ISSET(udp_sockfd, &readset)) {
				/* Some data on UDP port */
				handle_router_event();
			}
		}
	} while(1);
}

void cleanup()
{
	struct node *tmp;
	while ((tmp = dll_remove_from_head(&node_list))) {
		free(tmp);
	}
	dll_destroy(&node_list);
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

	/* Create a udp socket to listen on */
	udp_sockfd = create_udp_socket(argv[3]);

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
	close(udp_sockfd);

	/* Cleanup */
	cleanup();

	return 0;
}
