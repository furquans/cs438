#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <signal.h>
#include <time.h>

#include "dll.h"
#include "error.h"
#include "router.h"

#define CLOCKID CLOCK_REALTIME
#define SIG SIGUSR1

dll_t neigh_list;
dll_t forward_table;
int myaddr;
int manager_sockfd;
int udp_sockfd;
bool logging_enabled;
bool flag;
char *pending_mgr_msg;

static bool updated = 0, selected = 0;

static timer_t manager_timer, router_timer;

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
	printf("sending msg to manager:%s",msg);
	while (send(manager_sockfd,
		    msg,
		    count,
		    0) < count) {
		printf("send to manager failed\n");
	}
}

void send_msg_to_router(unsigned char *msg,
			int count,
			struct node *router)
{
	struct sockaddr_in their_addr;
	struct hostent *he;

	if ((he=gethostbyname(router->hostname)) == NULL) {
		printf("gethostname failed\n");
		exit(SOCK_ERROR);
	}

	their_addr.sin_family = AF_INET;
	their_addr.sin_port = htons(router->udp_port);
	their_addr.sin_addr = *((struct in_addr *)he->h_addr);
	memset(their_addr.sin_zero, '\0', sizeof(their_addr.sin_zero));

	while (sendto(udp_sockfd,
		      msg,
		      count,
		      0,
		      (struct sockaddr*)&their_addr,
		      sizeof(their_addr)) < count) {
		printf("send to router failed\n");
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
		printf("Recv from failed\n");
		exit(SOCK_ERROR);
	}
	return ret;
}

int recv_msg_from_manager(char *msg)
{
	int ret = recv_msg(manager_sockfd,
			   msg,
			   MAX_MGR_MSG_LEN);
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
	int ret;
	char resp[MAX_MGR_MSG_LEN];
	send_msg_to_manager(msg);

	ret = recv_msg_from_manager(resp);

	resp[ret-1] = '\0';
	return (strcmp(resp,
		       OK_MSG) == 0);
}

void get_addr_from_manager()
{
#define ADDR_STR_LEN 25
	int ret;
	char addr[MAX_MGR_MSG_LEN];

	send_msg_to_manager(HELO_MSG);

	ret = recv_msg_from_manager(addr);

	addr[ret-1] = '\0';
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
	struct forward_table_entry *tmp;

	tmp = malloc(sizeof(*tmp));
	if (tmp == NULL) {
		printf("Mem alloc failed\n");
		exit(1);
	}
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
		printf("malloc failed\n");
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
	if(atoi(ptr) != -1) {
		tmp->cost = atoi(ptr);
	} else {
		tmp->cost = INF;
	}

	tmp->send_update = 0;

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

struct forward_table_entry *find_fwd_table_entry(int dest)
{
	struct forward_table_entry *tmp = NULL;
	int i;
	int size = dll_size(&forward_table);

	for (i=0;i<size;i++) {
		tmp = dll_at(&forward_table,i);
		if (tmp->addr == dest) {
			return tmp;
		}
	}
	return NULL;
}

struct node *find_route(int dest)
{
	struct forward_table_entry *tmp;

	tmp = find_fwd_table_entry(dest);

	if (tmp && (tmp->cost != INF)) {
		return find_dest_entry(tmp->next_hop);
	}

	return NULL;
}

void format_and_send_fwd_table(int addr)
{
	unsigned char msg[MAX_RTR_MSG_LEN];
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
		/* 2 bytes address and 1 byte cost */
		msg[pos++] = (tmp->addr >> 8) & 0x0ff;
		msg[pos++] = tmp->addr & 0x0ff;

		/* Reverse poisoning */
		if (tmp->next_hop == addr) {
			msg[pos++] = INF;
		} else {
			msg[pos++] = tmp->cost;
		}
        }

	/* Number of nodes */
	msg[5] = (pos-6)/3;
	printf("count:%d\n",msg[5]);

	router = find_dest_entry(addr);
	printf("%d:sending message to %d\n",myaddr,addr);
 	send_msg_to_router(msg,
			   pos,
			   router);
}

void send_forward_table_except_node(int node)
{
	struct node *tmp;
	int i;
	int size = dll_size(&neigh_list);

	for (i=0;i<size;i++) {
		tmp = dll_at(&neigh_list, i);
		if ((tmp->cost != INF) &&
		    (tmp->addr != node)) {
			printf("sending to:%d,cost:%d\n",tmp->addr,tmp->cost);
			format_and_send_fwd_table(tmp->addr);			
		}
	}
}

void send_forward_table()
{
	struct node *tmp;
	int i;
	int size = dll_size(&neigh_list);

	for (i=0;i<size;i++) {
		tmp = dll_at(&neigh_list, i);
		if (tmp->cost != INF) {
			printf("sending to:%d,cost:%d\n",tmp->addr,tmp->cost);
			format_and_send_fwd_table(tmp->addr);
		}
	}
}

void start_timer(timer_t timer, int seconds)
{
	struct itimerspec its;

	its.it_value.tv_sec = seconds;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

        if (timer_settime(timer, 0, &its, NULL) == -1) {
		perror("timer_settime");
		exit(1);
	}

}

static void get_neigh_details_from_manager()
{
	char resp[MAX_MGR_MSG_LEN*MAX_NEIGHBOURS];
	int ret = 0;
	char *ptr, *end;

	send_msg_to_manager(NEIGH_MSG);

	do {
		ret += recv_msg_from_manager(&resp[ret]);
		if (strstr(resp, "DONE")) {
			break;
		}
	} while (1);

	resp[ret-1] = '\0';

	printf("Resp: %s\n",resp);

	ptr = resp;
	do {
		end = strchr(ptr, '\n');
		if (end == NULL) {
			break;
		}
		*end = '\0';
		printf("resp:%s\n",ptr);
		add_new_node(ptr);
		ptr = end + 1;
	} while(1);

	send_forward_table();

	pending_mgr_msg = malloc(sizeof(READY_MSG));
	strcpy(pending_mgr_msg,
	       READY_MSG);

	start_timer(manager_timer,
		    2);
}

void enable_logging()
{
	int ret;
	char resp[MAX_MGR_MSG_LEN];

	send_msg_to_manager(LOG_ON_MSG "\n");

	ret = recv_msg_from_manager(resp);

	resp[ret-1] = '\0';

	if (!strcmp(resp,
		    LOG_ON_MSG)) {
		printf("Logging on\n");
		logging_enabled = 1;
	}
	logging_enabled = 1;
}

void disable_logging()
{
	int ret;
	char resp[MAX_MGR_MSG_LEN];

	send_msg_to_manager(LOG_OFF_MSG "\n");

	ret = recv_msg_from_manager(resp);

	resp[ret-1] = '\0';

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

void update_fwd_tbl(int node,
		    int diff_cost)
{
	int i;
	struct forward_table_entry *tmp;
	struct node *dest;
	int size = dll_size(&forward_table);

	for (i=0;i<size;i++) {
		tmp = dll_at(&forward_table,i);
		if (tmp->next_hop == node) {
			dest = find_dest_entry(tmp->addr);
			if (dest) {
				if ((diff_cost == INF) ||
				    (tmp->cost == INF) ||
				    (dest->cost < (tmp->cost+diff_cost))) {
					tmp->cost = dest->cost;
					tmp->next_hop = dest->addr;
				} else {
					tmp->cost += diff_cost;
				}
			} else {
				if (diff_cost == INF) {
					tmp->cost = INF;
				} else {
					tmp->cost += diff_cost;
				}
			}
		}
	}
}

void update_cost_for_node(int node,
			  int cost)
{
	struct node *tmp;
	int diff_cost = INF;

	tmp = find_dest_entry(node);
	if (tmp) {
		if (cost != -1) {
			diff_cost = cost - tmp->cost;
			tmp->cost = cost;
		} else {
			tmp->cost = INF;
		}
	}

	/* Check forwarding table */
	update_fwd_tbl(node, diff_cost);
}

void update_cost_of_link(char *msg)
{
	int node1, node2, node;
	int cost;

	node1 = atoi(strtok(msg + strlen(LINK_COST_MSG) + 1, " "));
	node2 = atoi(strtok(NULL, " "));
	cost  = atoi(strtok(NULL, " "));

	node = (node1==myaddr)?node2:node1;
	printf("Update:%d %d %d\n",node1,node2,cost);

	update_cost_for_node(node, cost);
	print_neigh_list();

	printf("Link cost change, sending fwd table:%d\n",myaddr);
	send_forward_table();

	pending_mgr_msg = malloc(MAX_MGR_MSG_LEN);
	sprintf(pending_mgr_msg, "COST %d OK\n", cost);
	start_timer(manager_timer,
		    2);
	flag = 1;
}

int handle_manager_event()
{
	int ret;
	int ret_val = 0;
	char msg[MAX_MGR_MSG_LEN];

	ret = recv_msg_from_manager(msg);
	msg[ret-1] = '\0';

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

void send_data(int dest,
	       char *msg)
{
	struct node *router;
	char log[MAX_MGR_MSG_LEN];

	if (logging_enabled == 0) {
		enable_logging();
	}

	router = find_route(dest);

	if (router) {

		sprintf(log, LOG_FWD_MSG "%d %s\n", router->addr, msg+5);

		send_msg_and_chk_ok(log);

		send_msg_to_router((unsigned char *)msg,
				   strlen(msg+5)+5,
				   router);
	} else {
		printf("No path to destination %d found. Dropping packet\n", dest);

		sprintf(log, DROP_MSG "%s\n",msg+5);

		send_msg_and_chk_ok(log);
	}
}

void format_and_send_data(int dest,
			  char *in)
{
	char msg[MAX_RTR_MSG_LEN];

	msg[0] = 2;
	msg[1] = in[1];
	msg[2] = in[2];
	msg[3] = (myaddr >> 8) & 0x0ff;
	msg[4] = myaddr & 0x0ff;
	strcpy(msg+5,
	       in+3);

	send_data(dest,
		  msg);
}

struct forward_table_entry* find_entry_in_fwd_table(int dest)
{
	struct forward_table_entry *tmp;
	int i;
	int size = dll_size(&forward_table);

	for (i=0;i<size;i++) {
		tmp = dll_at(&forward_table,i);
		if (tmp->addr == dest)
			return tmp;
	}

	return NULL;
}

void scan_dist_vectors(char *msg)
{
	struct forward_table_entry *tmp;
	unsigned char *ptr;
	int i;
	int hop = (msg[3] << 8) + msg[4];
	struct node *neigh;

	printf("%d:Scanning distance vectors from %d,count:%d\n",myaddr,hop,msg[5]);
	ptr = (unsigned char*)msg + 6;

	neigh = find_dest_entry(hop);

	if (neigh == NULL) {
		printf("neigh not found\n");
		exit(1);
	}

	for (i=0;i<msg[5];i++) {
		int dest = (ptr[0]<<8) + ptr[1];
		unsigned int hop_dist;
		if (dest != myaddr) {
			printf("finding entry in fwd table\n");
			tmp = find_entry_in_fwd_table(dest);
			printf("done\n");
			hop_dist = ptr[2];
			if (hop_dist != INF) {
				hop_dist += neigh->cost;
			}
			if(tmp == NULL){
				if (hop_dist != INF) {
					/* We dont have this entry
					   and our neighbour has a non-INF
					   path to this node */
					printf("creating new forward table entry\n");
					add_node_to_fwd_table(dest,
							      hop_dist,
							      hop);
					updated = 1;
				}
			} else if (tmp->next_hop == hop) {
				/* We have this entry and it is already
				   going through this neighbour */
				struct node *node_tmp;
				printf("updating next hop\n");
				node_tmp = find_dest_entry(dest);
				if ((node_tmp != NULL) && (node_tmp->cost <= hop_dist)) {
					tmp->cost = node_tmp->cost;
					tmp->next_hop = dest;
					updated = 1;
				} else if (tmp->cost != hop_dist){
					tmp->cost = hop_dist;
					updated = 1;
				}
			} else if (tmp->cost > hop_dist) {
				printf("updating hop\n");
				tmp->cost = hop_dist;
				tmp->next_hop = hop;
				updated = 1;
			}  else if ((tmp->cost != INF) &&
				    ((tmp->cost + neigh->cost) < ptr[2])) {
				printf("%d:I can provide a better path to neigh %d\n",myaddr,hop);
				printf("tmp->cost+neigh->cost:%d,ptr[2]:%d\n",tmp->cost+neigh->cost,ptr[2]);
				selected  = 1;
				neigh->send_update = 1;
			}
		}
		ptr += 3;
	}
	print_forward_table();

	if (updated || selected) {
		start_timer(router_timer,
			    1);
	}
}

void handle_router_event()
{
	char log[MAX_MGR_MSG_LEN];
	char msg[MAX_RTR_MSG_LEN];
	int destaddr;

	if (logging_enabled == 0) {
		enable_logging();
	}

	printf("bytes:%d\n",recv_msg_from_router(msg));

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
		if (destaddr != myaddr) {
			send_data(destaddr,
				  msg);
		}
	} else if (msg[0] == 3) {
		printf("Type 3 message\n");
		destaddr = (msg[1] << 8) + msg[2];
		printf("Destination = %d\n", destaddr);
		printf("Source = %d\n", (msg[3] << 8) + msg[4]);
		printf("count = %d\n",msg[5]);
		scan_dist_vectors(msg);
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
			if (FD_ISSET(udp_sockfd, &readset)) {
				/* Some data on UDP port */
				handle_router_event();
			} else if (FD_ISSET(manager_sockfd, &readset)) {
				/* Some data on manager socket */
				if (handle_manager_event() == -1) {
					break;
				}
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

static void timer_handler(int sig,
			  siginfo_t *si,
			  void *uc)
{
	printf("sig:%d,%p",sig,uc);
	if (si->si_value.sival_ptr == &manager_timer) {
		if (pending_mgr_msg) {
			if (strstr (pending_mgr_msg, "READY")) {
				if (!send_msg_and_chk_ok(pending_mgr_msg)) {
					printf("No OK from manager\n");
					exit(MANAGER_ERROR);
				}
			} else {
				send_msg_to_manager(pending_mgr_msg);
			}
			free(pending_mgr_msg);
			pending_mgr_msg = NULL;
		}
	} else if (si->si_value.sival_ptr == &router_timer) {
		if (updated) {
			send_forward_table();
			updated = 0;
			selected = 0;
		}
		if (selected) {
			int i;
			struct node *tmp;
			int size = dll_size(&neigh_list);

			for (i=0; i<size;i++) {
				tmp = dll_at(&neigh_list,i);
				if (tmp->send_update) {
					tmp->send_update = 0;
					format_and_send_fwd_table(tmp->addr);
				}
			}
			selected = 0;
		}
	}
}

void create_timers()
{
	struct sigaction sa;
	struct sigevent sev;

        sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = timer_handler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIG, &sa, NULL);

        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIG;
        sev.sigev_value.sival_ptr = &manager_timer;
        timer_create(CLOCKID, &sev, &manager_timer);

        sev.sigev_value.sival_ptr = &router_timer;
        timer_create(CLOCKID, &sev, &router_timer);
}

int main(int argc, char **argv)
{
	if (argc != 4) {
		printf("Usage: %s <manager hostname> <TCP port of manager> <UDP port of router>\n",argv[0]);
		exit(USAGE_ERROR);
	}

	/* Establish signal handlers */
	create_timers();

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
	get_neigh_details_from_manager();

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
