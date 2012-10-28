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

dll_t neigh_list;
dll_t forward_table;
int myaddr;
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

void send_msg_to_router(char *msg, struct node *router)
{
	struct sockaddr_in their_addr;
	struct hostent *he;
	int count = strlen(msg);

	if ((he=gethostbyname(router->hostname)) == NULL) {
		exit(SOCK_ERROR);
	}

	their_addr.sin_family = AF_INET;
	their_addr.sin_port = htons(router->udp_port);
	their_addr.sin_addr = *((struct in_addr *)he->h_addr);
	memset(their_addr.sin_zero, '\0', sizeof(their_addr.sin_zero));

	if (sendto(udp_sockfd,
		   msg,
		   count,
		   0,
		   (struct sockaddr*)&their_addr,
		   sizeof(their_addr)) < count) {
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
	int ret = recv_msg(udp_sockfd,
			   msg,
			   MAX_RTR_MSG_LEN);
	msg[ret] = '\0';
	return ret;
}

bool send_msg_and_chk_ok(char *msg)
{
	char resp[MAX_MGR_MSG_LEN];
	send_msg_to_manager(msg);

	recv_msg_from_manager(resp);

	return (strcmp(resp,
		       OK_MSG) == 0);
}

void get_addr_from_manager()
{
#define ADDR_STR_LEN 25
	char addr[MAX_MGR_MSG_LEN];

	send_msg_to_manager(HELO_MSG);

	recv_msg_from_manager(addr);

	myaddr = atoi(addr+5);
	printf("My address is:%d\n",myaddr);
}

bool send_udp_details_to_manager(char *hostname,
				char *udpport)
{
	char msg[25];

	sprintf(msg, HOST_MSG "%s %s\n",hostname, udpport);

	return send_msg_and_chk_ok(msg);
}

void add_node_to_fwd_table(int addr,
			   int cost,
			   int next_hop)
{
	int i;
	struct forward_table_entry *tmp;
	int size = dll_size(&forward_table);

	for (i=0;i<size;i++) {
		tmp = dll_at(&forward_table, i);
		if (tmp->addr == addr) {
			if (tmp->cost > cost) {
				tmp->cost = cost;
				tmp->next_hop = next_hop;
			}
			return;
		}
	}

	tmp = malloc(sizeof(*tmp));
	tmp->addr = addr;
	tmp->cost = cost;
	tmp->next_hop = next_hop;
	dll_add_to_tail(&forward_table, tmp);
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
	tmp->addr = atoi(ptr);

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
	dll_add_to_tail(&neigh_list, tmp);

	/* Add the node to forward table */
	add_node_to_fwd_table(tmp->addr,
			      tmp->cost,
			      tmp->addr);
}

struct node *find_dest_entry(int dest)
{
	int i;
        struct node *tmp;
	int size = dll_size(&neigh_list);

	for (i=0;i<size;i++) {
                tmp = dll_at(&neigh_list, i);
		if (tmp->addr == dest) {
			return tmp;
		}
	}
	return NULL;
}

struct node *find_route(int dest)
{
	int i;
	struct forward_table_entry *tmp;
	int size = dll_size(&forward_table);

	for (i=0;i<size;i++) {
		tmp = dll_at(&forward_table,i);
		if (tmp->addr == dest) {
			return find_dest_entry(tmp->next_hop);
		}
	}
	return NULL;
}

void format_and_send_fwd_table(int addr)
{
	char msg[MAX_RTR_MSG_LEN];
	struct forward_table_entry *tmp;
	struct node *router;
	int pos = 6,i;
	int size = dll_size(&forward_table);

	/* Distance vector */
	msg[0] = 3;
	/* Dest */
	msg[1] = (addr >> 8) & 0x0ff;
	msg[2] = addr & 0x0ff;
	/* Src */
	msg[3] = (myaddr >> 8) & 0x0ff;
	msg[4] = myaddr & 0x0ff;

	for (i=0;i<size;i++) {
		tmp = dll_at(&forward_table,i);
		if (tmp->cost != -1) {
			/* 2 bytes address and 1 byte cost */
			msg[pos++] = (tmp->addr >> 8) & 0x0ff;
			msg[pos++] = tmp->addr & 0x0ff;
			if (tmp->addr == addr) {
				msg[pos++] = INF;
			} else {
				msg[pos++] = tmp->cost;
			}
		}
        }

	/* Number of nodes */
	msg[5] = (pos-6)/3;

	router = find_dest_entry(addr);
 	send_msg_to_router(msg,
			   router);
}

void send_forward_table()
{
	struct node *tmp;
	int i;
	int size = dll_size(&neigh_list);

	for (i=0;i<size;i++) {
		tmp = dll_at(&neigh_list, i);
		format_and_send_fwd_table(tmp->addr);
	}
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

	send_forward_table();

	return send_msg_and_chk_ok(READY_MSG);
}

void enable_logging()
{
	char resp[MAX_MGR_MSG_LEN];

	send_msg_to_manager(LOG_ON_MSG "\n");

	recv_msg_from_manager(resp);

	if (!strcmp(resp,
		    LOG_ON_MSG)) {
		printf("Logging on\n");
		logging_enabled = 1;
	}
}

void disable_logging()
{
	char resp[MAX_MGR_MSG_LEN];

	send_msg_to_manager(LOG_OFF_MSG "\n");

	recv_msg_from_manager(resp);

	if (!strcmp(resp,
		    LOG_OFF_MSG)) {
		printf("Logging off\n");
		logging_enabled = 0;
	}
}

void print_neigh_list()
{
	int i;
	struct node *tmp;
	int size = dll_size(&neigh_list);

	printf("********* Neighbour list***********\n");
	printf(" Addr  Hostname   Port  Cost\n");
	for (i=0;i<size;i++) {
		tmp = dll_at(&neigh_list, i);
		printf("%5d ",tmp->addr);
		printf("%10s ",tmp->hostname);
		printf("%5u ",tmp->udp_port);
		printf("%5d\n",tmp->cost);
	}
}

void print_forward_table()
{
	int i;
	struct forward_table_entry *tmp;
	int size = dll_size(&forward_table);

	printf("********Forward Table**********\n");
	printf(" Addr  Cost  Next-Hop\n");
	for (i=0;i<size;i++) {
		tmp = dll_at(&forward_table,i);
		printf("%5d ",tmp->addr);
		printf("%5d ",tmp->cost);
		printf("%7d\n",tmp->next_hop);
	}
}

void update_cost_for_node(int node,
			  int cost)
{
	int i;
	struct node *tmp;
	int size = dll_size(&neigh_list);

	for (i=0;i<size;i++) {
		tmp = dll_at(&neigh_list, i);
		if (tmp->addr == node) {
			tmp->cost = cost;
			break;
		}
	}
}

void update_cost_of_link(char *msg)
{
	int node1, node2, node;
	int cost;
	char resp[MAX_MGR_MSG_LEN];

	node1 = atoi(strtok(msg + strlen(LINK_COST_MSG) + 1, " "));
	node2 = atoi(strtok(NULL, " "));
	cost  = atoi(strtok(NULL, " "));

	node = (node1==myaddr)?node2:node1;
	printf("Update:%d %d %d\n",node1,node2,cost);

	update_cost_for_node(node, cost);
	print_neigh_list();

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

void format_and_send_data(int dest,
			  char *in)
{
	char msg[MAX_RTR_MSG_LEN];
	char log[MAX_MGR_MSG_LEN];
	struct node *router;

	msg[0] = 2;
	msg[1] = in[1];
	msg[2] = in[2];
	msg[3] = (myaddr >> 8) & 0x0ff;
	msg[4] = myaddr & 0x0ff;
	strcpy(msg+5,
	       in+3);

	if (logging_enabled == 0) {
		enable_logging();
	}

	router = find_route(dest);

	sprintf(log, LOG_FWD_MSG "%d %s\n", router->addr, in+3);

	send_msg_and_chk_ok(log);

	send_msg_to_router(msg,
			   router);
}

void handle_router_event()
{
	char log[MAX_MGR_MSG_LEN];
	char msg[MAX_RTR_MSG_LEN];
	int destaddr;

	if (logging_enabled == 0) {
		enable_logging();
	}

	recv_msg_from_router(msg);

	if (msg[0]  == 1) {
		printf("Type 1 message\n");
		destaddr = (msg[1] << 8) + msg[2];
		printf("Destination = %d\n", destaddr);
		printf("msg:%s\n",msg+3);
		format_and_send_data(destaddr,
				     msg);
	} else if (msg[0] == 2) {
		printf("Type 2 message\n");
		destaddr = (msg[1] << 8) + msg[2];
		printf("Destination = %d\n", destaddr);
		printf("Source = %d\n", (msg[3] << 8) + msg[4]);
		printf("msg = %s\n",msg+5);

		sprintf(log, RECV_MSG "%s\n",msg+5);
		send_msg_and_chk_ok(log);
	} else if (msg[0] == 3) {
		printf("Type 3 message\n");
		destaddr = (msg[1] << 8) + msg[2];
		printf("Destination = %d\n", destaddr);
		printf("Source = %d\n", (msg[3] << 8) + msg[4]);
		printf("count = %d\n",msg[5]);
	}
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
	while ((tmp = dll_remove_from_head(&neigh_list))) {
		free(tmp);
	}
	dll_destroy(&neigh_list);
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
	dll_init(&neigh_list);
	/* Initalize head of forwarding table */
	dll_init(&forward_table);

	/* Get neighbour details */
	if (!get_neigh_details_from_manager()) {
		exit(MANAGER_ERROR);
	}

	/* Print node list */
	print_neigh_list();

	/* Print forward table */
	print_forward_table();

	/* Listen for incoming messages / events */
	listen_for_events();

	printf("success\n");
	close(manager_sockfd);
	close(udp_sockfd);

	/* Cleanup */
	cleanup();

	return 0;
}
