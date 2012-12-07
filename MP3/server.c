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

#include <signal.h>
#include <time.h>

#define MAX_FILENAME_LEN 50
#define SERVER_PORT "5578"
#define CLIENT_PORT 5580
#define MAX_FIN_RESEND 5

#define CLOCKID CLOCK_REALTIME

char filename[MAX_FILENAME_LEN];

#define MAX_THREADS 16

struct pthread_info {
	char used;
	pthread_t server_tid;
};

struct pthread_info server_info[MAX_THREADS];

static __thread int server_sockfd;
static __thread struct sockaddr_in their_addr;
static __thread	struct sockaddr tmp_addr;
static __thread dll_t packet_list;
static __thread int rto = 1;
static __thread timer_t rto_timer;
static __thread int fin_resend_count=0;
static __thread int fin_seq_no;

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

void prepare_for_udp_send(struct sockaddr_in *their_addr,
			  int port)
{
	struct hostent *he;

	if ((he=gethostbyname("localhost")) == NULL) {
		printf("gethostname failed\n");
		exit(1);
	}

	their_addr->sin_family = AF_INET;
	their_addr->sin_port = htons(port);
	their_addr->sin_addr = *((struct in_addr *)he->h_addr);
	memset(their_addr->sin_zero, '\0', sizeof(their_addr->sin_zero));
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
	printf("started rto timer\n");
}

int free_data(unsigned int seq_no,
	      dll_t *packet_list)
{
	int count = 0;
	while(dll_size(packet_list)) {
		struct packet *tmp = dll_at(packet_list,0);
		if (tmp->hdr.seq_no < seq_no) {
			dll_remove_from_head(packet_list);
			free(tmp);
			count++;
		} else {
			break;
		}
	}
	if (dll_size(packet_list)) {
		start_rto_timer(&rto_timer,rto);
	} else {
		timer_delete(rto_timer);
	}

	return count;
}

void send_fin()
{
	struct packet tmp;
	tmp.hdr.flags |= FIN_FLAG;
	tmp.hdr.seq_no = fin_seq_no;
	tmp.hdr.length = 0;
	sendto(server_sockfd,
	       &tmp,
	       sizeof(struct header),
	       0,
	       (struct sockaddr*)&their_addr,
	       sizeof(their_addr));
}

void alarm_handler(int sig)
{
	int size;
	struct itimerspec its;

	printf("In pthread handler:%d\n",sig);
	size = dll_size(&packet_list);
	timer_gettime(rto_timer,&its);

	if ((its.it_value.tv_sec == 0) &&
	    (its.it_value.tv_nsec == 0)) {

		if (size) {
			int count;
			struct packet *tmp = dll_at(&packet_list,0);
			printf("Retransmitting packet with seq number:%d\n",tmp->hdr.seq_no);
			count = sizeof(struct header)+tmp->hdr.length;
			if (sendto(server_sockfd,
				   tmp,
				   count,
				   0,
				   (struct sockaddr*)&their_addr,
				   sizeof(their_addr)) < count) {
				printf("send to failed\n");
				exit(1);
			}
		} else if (fin_sent == 1) {
			if ((fin_rcvd == 0) &&
			    (fin_resend_count < MAX_FIN_RESEND)) {
				fin_resend_count++;
				send_fin();
			} else {
				pthread_exit(NULL);
			}
		}
		start_rto_timer(&rto_timer,rto);
	}
}

void *send_file(void *arg)
{
	FILE *fp;
	char str[MAX_DATA_SIZE];
	int ret;
	int seq_no = 0;
	unsigned int wind_size = 10;
	unsigned int curr_wind = 0;
	fd_set rdfs;
	struct packet resp;
	socklen_t tmp_len;
	unsigned char fin_sent = 0;
	unsigned char fin_rcvd = 0;
	sigset_t set;

	printf("Server:sending file %s to client\n",filename);

	fp = fopen(filename,"r+");

	if (fp == NULL) {
		printf("Error opening file\n");
		exit(1);
	}

	server_sockfd = create_udp_socket(SERVER_PORT);

	if (server_sockfd == -1) {
		printf("Socket error\n");
		exit(1);
	}

	prepare_for_udp_send(&their_addr,
			     CLIENT_PORT);

	sigemptyset(&set);
	sigaddset(&set,SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	signal(SIGUSR2,alarm_handler);

	dll_init(&packet_list);
	create_rto_timer(&rto_timer);
	
	while ((ret = fread(str,
			    sizeof(char),
			    MAX_DATA_SIZE,
			    fp)) != 0) {
		struct packet *tmp;
		int count = sizeof(struct header) + ret;

		tmp = malloc(sizeof(*tmp));
		memcpy(tmp->data,
		       str,
		       ret);
		tmp->hdr.length = ret;
		tmp->hdr.seq_no = seq_no;
		tmp->hdr.flags &= ~(FIN_FLAG);

		if ((unsigned int)ret < MAX_DATA_SIZE) {
			fin_sent = 1;
			printf("sending FIN_FLAG\n");
			tmp->hdr.flags |= FIN_FLAG;
		}
		seq_no += tmp->hdr.length;

		if ((tmp->hdr.seq_no == 0) || (tmp->hdr.seq_no % 336)) {
			if (sendto(server_sockfd,
				   tmp,
				   count,
				   0,
				   (struct sockaddr*)&their_addr,
				   sizeof(their_addr)) < count) {
				printf("send to failed\n");
				exit(1);
			}
		}

		if (dll_size(&packet_list) == 0) {
			start_rto_timer(&rto_timer,rto);
		}

		dll_add_to_tail(&packet_list,tmp);

		curr_wind++;
		printf("curr_wind:%d\n",curr_wind);
		if (fin_sent)
			break;

		while (curr_wind == wind_size) {
			int retval;
			printf("waiting for ack\n");
			FD_ZERO(&rdfs);
			FD_SET(server_sockfd, &rdfs);

			retval = select(server_sockfd+1,&rdfs,NULL,NULL,NULL);

			if (FD_ISSET(server_sockfd,&rdfs)) {
				if (recvfrom(server_sockfd,
					     &resp,
					     sizeof(resp),
					     0,
					     &tmp_addr,
					     &tmp_len) > 0) {
					if (resp.hdr.flags & ACK_FLAG) {
						curr_wind -= free_data(resp.hdr.ack_no,&packet_list);
						printf("received ack,curr_win=%d\n",curr_wind);
					}
				}
			} else {
				printf("error:%d\n",retval);
			}
		}
	}

	if (!fin_sent) {
		send_fin();
	}

	while(dll_size(&packet_list)) {
		int retval;
		FD_ZERO(&rdfs);
		FD_SET(server_sockfd, &rdfs);

		printf("packet waiting for ack\n");
		retval = select(server_sockfd+1,&rdfs,NULL,NULL,NULL);

		if (FD_ISSET(server_sockfd,&rdfs)) {
			if (recvfrom(server_sockfd,
				     &resp,
				     sizeof(resp),
				     0,
				     &tmp_addr,
				     &tmp_len) > 0) {
				if (resp.hdr.flags & FIN_FLAG) {
					printf("Fin received\n");
					fin_rcvd = 1;
				}
				if (resp.hdr.flags & ACK_FLAG) {
					curr_wind -= free_data(resp.hdr.ack_no,&packet_list);
					printf("received ack,curr_win=%d\n",curr_wind);
				}
			}
		} else {
			printf("error:%d\n",retval);
		}
	}

	while (fin_rcvd == 0) {
		int retval;
		FD_ZERO(&rdfs);
		FD_SET(server_sockfd, &rdfs);

		printf("packet waiting for fin\n");
		retval = select(server_sockfd+1,&rdfs,NULL,NULL,NULL);

		if (FD_ISSET(server_sockfd,&rdfs)) {
			if (recvfrom(server_sockfd,
				     &resp,
				     sizeof(resp),
				     0,
				     &tmp_addr,
				     &tmp_len) > 0) {
				if (resp.hdr.flags & FIN_FLAG) {
					fin_rcvd = 1;
					printf("received fin\n");
				}
			}
		} else {
			printf("error:%d\n",retval);
		}		
	}

	dll_destroy(&packet_list);
	printf("Done sending file\n");
	return arg;
}

int get_free_pthread_info(struct pthread_info *server_info)
{
	int i = 0;
	int ret = -1;

	while (i < MAX_THREADS) {
		if (server_info[i].used == 0) {
			server_info[i].used = 1;
			ret = i;
			break;
		}
		i++;
	}

	return ret;
}

void main_handler(int sig,
		  siginfo_t *si,
		  void *uc)
{
	int i;
	printf("Main signal handler:%d %p %p\n",sig,si,uc);

	for (i=0;i<MAX_THREADS;i++) {
		if (server_info[i].used) {
			pthread_kill(server_info[i].server_tid,SIGUSR2);
		}
	}
}

int main(int argc,char **argv)
{
	int index;
	struct sigaction sa;

	if (argc != 2) {
		printf("Usage:%s <filename>\n",argv[0]);
		exit(1);
	}

	strcpy(filename,
	       argv[1]);

	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = main_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGUSR1, &sa, NULL);

	index = get_free_pthread_info(server_info);

	pthread_create(&server_info[index].server_tid,
		       NULL,
		       &send_file,
		       NULL);
	while(1);
}
