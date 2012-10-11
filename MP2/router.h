#ifndef __ROUTER_H__
#define __ROUTER_H__

#define HELO_MSG  "HELO\n"
#define READY_MSG "READY\n"
#define NEIGH_MSG "NEIGH?\n"
#define HOST_MSG "HOST "
#define LINK_COST_MSG "LINKCOST"
#define BYE_MSG "BYE\n"
#define END_MSG "END"
#define OK_MSG "OK"
#define LOG_MSG "LOG_ON"

typedef unsigned char bool;

#define MAX_ADDR_LEN 10
#define MAX_HOSTNAME_LEN 20
#define MAX_MGR_MSG_LEN 100
#define MAX_RTR_MSG_LEN 65535

struct node {
	char addr[MAX_ADDR_LEN];
	char hostname[MAX_HOSTNAME_LEN];
	unsigned int udp_port;
	int cost;
};


#endif // __ROUTER_H__
