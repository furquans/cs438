#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "helper.h"

#include <signal.h>
#include <time.h>

#define CLOCKID CLOCK_REALTIME

void make_header(struct packet *p,
		unsigned short src_port,
		unsigned short dst_port,
		unsigned int seq_no,
		unsigned int ack_no,
		unsigned short flags,
		unsigned short length)
{
	p->hdr.src_port=src_port;
	p->hdr.dst_port=dst_port;
	p->hdr.seq_no=seq_no;
	p->hdr.ack_no=ack_no;
	p->hdr.flags=flags;
	p->hdr.length=length;
}

int get_flags(struct packet *p)
{
	return (p->hdr).flags;
}

int create_udp_socket(unsigned short port)
{
        int sockfd;
        int ret;
        struct addrinfo hints, *servinfo, *p;

        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;
	char port_str[6];
	sprintf(port_str,"%u",port);

        if ((ret=getaddrinfo(NULL,port_str,&hints,&servinfo)) != 0) {
                fprintf(stderr,"getaddrinfo error %s:\n",gai_strerror(ret));
                exit(1);
        }

        for(p = servinfo; p != NULL; p = p->ai_next) {
                if ((sockfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == -1) {
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
        freeaddrinfo(servinfo);
        if (p == NULL) {
		perror("bind");
		return -1;
        }
        return sockfd;
}

void show_header(struct packet *p)
{
#ifdef LOG
	printf_log("(%u,%u,%d,%d,%u,%u)\n",(p->hdr).src_port,(p->hdr).dst_port,(p->hdr).seq_no,(p->hdr).ack_no,(p->hdr).flags,(p->hdr).length);
        fflush(stdout);
#else
	p = NULL;
#endif
}


unsigned short get_port(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return ntohs(((struct sockaddr_in*)sa)->sin_port);
    return ntohs(((struct sockaddr_in6*)sa)->sin6_port);
}

int send_to(int sockfd, void *msg, int len, char *dest, unsigned short dst_port)
{
	printf_log("header sent: ");
	show_header((struct packet*)msg);
        struct sockaddr_in to;
        struct hostent *he;

        if ((he=gethostbyname(dest)) == NULL) {
                perror("gethostname\n");
                exit(1);
        }

        to.sin_family = AF_INET;
        to.sin_port = htons(dst_port);
        to.sin_addr = *((struct in_addr *)he->h_addr);
        memset(to.sin_zero, '\0', sizeof(to.sin_zero));

        if(mp3_sendto(sockfd,msg,len,0,(struct sockaddr*)&to,sizeof(to))<len) {
                /* perror("sendto"); */
                /* exit(1); */
        }
        return len;
}

int recv_from(int sockfd, void *buf, int len, char *src, unsigned short *src_port)
{
	int ret;
	struct sockaddr_storage from;
	socklen_t from_len=sizeof from;
	if((ret=recvfrom(sockfd,buf,len,0,(struct sockaddr*)&from,&from_len))<0) 
		return -1;
	printf_log("header received: ");
	show_header((struct packet*)buf);
	inet_ntop(AF_INET,&(((struct sockaddr_in*)&from)->sin_addr),src,INET_ADDRSTRLEN);
	*src_port=get_port((struct sockaddr*)&from);

        return ret;
}

void prepare_for_udp_send(struct sockaddr_in *their_addr,
			  char *name,
			  int port)
{
	struct hostent *he;

	if ((he=gethostbyname(name)) == NULL) {
		printf_log("gethostname failed\n");
		exit(1);
	}

	their_addr->sin_family = AF_INET;
	their_addr->sin_port = htons(port);
	their_addr->sin_addr = *((struct in_addr *)he->h_addr);
	memset(their_addr->sin_zero, '\0', sizeof(their_addr->sin_zero));
}

void send_packet(struct packet *p,
		 int mysockfd,
		 struct sockaddr *their_addr)
{
	int count = sizeof(p->hdr) + p->hdr.length;

	if (mp3_sendto(mysockfd,
		       p,
		       count,
		       0,
		       their_addr,
		       sizeof(*their_addr)) < count) {
		/* printf_log("send to failed\n"); */
		/* exit(1); */
	}
}

void create_rto_timer(timer_t *pkt_timer)
{
	struct sigevent sev;

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGUSR1;
	timer_create(CLOCKID, &sev, pkt_timer);
}

void start_rto_timer(timer_t *pkt_timer,
		     int rto)
{
	struct itimerspec its;

	its.it_value.tv_sec = rto;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

        if (timer_settime(*pkt_timer, 0, &its, NULL) == -1) {
		perror("timer_settime");
		exit(1);
	}
}
