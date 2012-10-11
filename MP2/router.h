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
#define LOG_ON_MSG "LOG ON"
#define LOG_OFF_MSG "LOG OFF"
#define LOG_FWD_MSG "LOG FWD "
#define RECV_MSG "RECEIVED "

typedef unsigned char bool;

#define MAX_HOSTNAME_LEN 20
#define MAX_MGR_MSG_LEN 100
#define MAX_RTR_MSG_LEN 65535

struct node {
	int addr;
	char hostname[MAX_HOSTNAME_LEN];
	unsigned int udp_port;
	int cost;
};


#endif // __ROUTER_H__
