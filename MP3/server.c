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

#include "helper.h"
#include "dll.h"

#include <signal.h>
#include <time.h>

#define MAX_FILENAME_LEN 50
#define MAX_RESEND 5
#define MSS 100

char filename[MAX_FILENAME_LEN];

struct sock_packet
{
        struct packet p;
        char hostname[ADDRSTRLEN];
        unsigned short port;
};

static unsigned short listen_port;
static int listenfd;
static dll_t tid_dll;
static unsigned int count = 1;

static __thread int server_sockfd;
static __thread struct sockaddr_in client_addr;
static __thread dll_t packet_list;
static __thread int rto = 2;
static __thread int rto_count = 0;
static __thread timer_t rto_timer;
static __thread int fin_resend_count=0;
static __thread int fin_seq_no;
static __thread unsigned short src_port;
static __thread unsigned short client_port;

static __thread	unsigned char fin_sent = 0;
static __thread	unsigned char fin_rcvd = 0;
static __thread struct packet *handshake_msg;
static __thread int handshake_resend_count = 0;
static __thread long cwind = 1 * MSS;
static __thread long ssthresh = 65535;
static __thread long last_ack = -1;
static __thread unsigned int dup_ack = 0;

#define SLOW_START 1
#define CONG_AVOID 2
#define FAST_RECVR 3

#define SS_STRING "Slow Start"
#define CA_STRING "Cong Avoidance"
#define FR_STRING "Fast Recovery"

static __thread char tcp_state;

int roundup(long n, int m)
{ 
	return (n - (n%m));
}

void print_stats(int tx_rx,
		 int tx_start,
		 int tx_end,
		 int rx_ack,
		 char *phase,
		 int cwind,
		 int ssthresh)
{
	if(tx_rx) {
		printf_output("%10i\t%d:%d(%d)\t%10s\t%s\t%10d\t%10d\n",(int)time(NULL),
			      tx_start,
			      tx_end,
			      tx_end-tx_start,
			      "",
			      phase,
			      cwind,
			      ssthresh);
	} else {
		printf_output("%10i\t%10s\tACK %d\t\t%s\t%10d\t%10d\n",(int)time(NULL),
			      "",
			      rx_ack,
			      phase,
			      cwind,
			      ssthresh);
	}
}

void fast_retransmit()
{
	struct packet *tmp = dll_at(&packet_list,0);

	ssthresh = roundup(cwind/2,MSS);

	if (ssthresh < (2*MSS)) {
		ssthresh = 2*MSS;
	}

	tcp_state = FAST_RECVR;

	printf_log("Retransmitting packet with seq number:%d\n",tmp->hdr.seq_no);
	print_stats(1,
		    tmp->hdr.seq_no,
		    tmp->hdr.seq_no+tmp->hdr.length+sizeof(tmp->hdr),
		    0,
		    "Fast Retransmit",
		    cwind,
		    ssthresh);
	send_packet(tmp,server_sockfd,(struct sockaddr*)&client_addr);
}

int update_cwind()
{
	int ret = 0;
	switch (tcp_state) {
	case SLOW_START:
		if (dup_ack == 3) {
			ret = 1;
		} else if (dup_ack == 0) {
			cwind += MSS;
			if (cwind > ssthresh) {
				tcp_state = CONG_AVOID;
			}
		}
		break;
	case CONG_AVOID:
		if (dup_ack == 3) {
			ret = 1;
		} else if (dup_ack == 0) {
			cwind += (double)MSS * (double)MSS/(double)cwind;
		}
		break;
	case FAST_RECVR:
		if (dup_ack) {
			cwind += MSS;
		} else {
			cwind = ssthresh + MSS;
			tcp_state = CONG_AVOID;
		}
		break;
	}
	return ret;
}

int free_data(unsigned int seq_no,
	      dll_t *packet_list)
{
	int count = 0;

	if (last_ack > seq_no) {
		return 0;
	} else if (last_ack == seq_no) {
		dup_ack++;
	} else {
		dup_ack = 0;
	}

	last_ack = seq_no;

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
	if (dll_size(packet_list) || ((fin_sent == 1) && (fin_rcvd == 0))) {
		start_rto_timer(&rto_timer,rto);
	} else {
		timer_delete(rto_timer);
	}

	return count;
}

void send_fin()
{
	struct packet tmp;

	make_header(&tmp,
		    src_port,
		    client_port,
		    fin_seq_no,
		    0,
		    FIN_FLAG,
		    0);

	send_packet(&tmp,server_sockfd,(struct sockaddr*)&client_addr);
}

void alarm_handler(int sig)
{
	int size;
	struct itimerspec its;

#ifdef LOG
	printf_log("In pthread handler:%d\n",sig);
#else
	sig = 0;
#endif
	size = dll_size(&packet_list);
	timer_gettime(rto_timer,&its);

	if ((its.it_value.tv_sec == 0) &&
	    (its.it_value.tv_nsec == 0)) {

		/* Reset congestion window size to 1 MSS */
		cwind = 1 * MSS;
		tcp_state = SLOW_START;

		if (handshake_msg) {
			if (handshake_resend_count < MAX_RESEND) {
				/* Send handshake msg 2 */
				send_packet(handshake_msg,server_sockfd,(struct sockaddr*)&client_addr);
				/* Increment the count */
				handshake_resend_count++;
			} else {
				printf_log("Handshake failed\n");
				pthread_exit(NULL);
			}

		} else if (size) {
			struct packet *tmp = dll_at(&packet_list,0);
			printf_log("Retransmitting packet with seq number:%d\n",tmp->hdr.seq_no);
			print_stats(1,
				    tmp->hdr.seq_no,
				    tmp->hdr.seq_no+tmp->hdr.length+sizeof(tmp->hdr),
				    0,
				    tcp_state==SLOW_START?SS_STRING:tcp_state==CONG_AVOID?CA_STRING:FR_STRING,
				    cwind,
				    ssthresh);
			send_packet(tmp,server_sockfd,(struct sockaddr*)&client_addr);
			rto_count++;
			if ((rto_count > 5) && (rto < 10)) {
				rto++;
				printf("rto:%d\n",rto);
			}
		} else if (fin_sent == 1) {
			if ((fin_rcvd == 0) &&
			    (fin_resend_count < MAX_RESEND)) {
				fin_resend_count++;
				printf_log("Resending fin:%d\n",fin_resend_count);
				send_fin();
			} else {
				printf_log("Fin resend count exceeded.exiting\n");
				pthread_exit(NULL);
			}
		}
		start_rto_timer(&rto_timer,rto);
	}
}

int wait_for_ack()
{
	int retval;
	fd_set rdfs;
	struct sockaddr tmp_addr;
	socklen_t tmp_len;
	struct packet resp;

	printf_log("waiting for ack\n");
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
				int retrans;
				retval = free_data(resp.hdr.ack_no,&packet_list);
				retrans = update_cwind();
				print_stats(0,
					    0,
					    0,
					    resp.hdr.ack_no,
					    retrans==1?"Fast Retransmit":tcp_state==SLOW_START?SS_STRING:tcp_state==CONG_AVOID?CA_STRING:FR_STRING,
					    cwind,
					    ssthresh);
				if (retrans) {
					fast_retransmit();
				}
				if (rto > 2) {
					rto_count = 0;
					rto--;
				}
				printf_log("ACK %d\n",resp.hdr.ack_no);
			}
			if (resp.hdr.flags & FIN_FLAG) {
				printf_log("FIN received\n");
				fin_rcvd = 1;
			}
		}
	} else {
		printf_log("error:%d\n",retval);
	}

	return retval;
}

/* Send file to client */
void send_file()
{
	FILE *fp;
	char str[MAX_DATA_SIZE];
	int ret;
	int seq_no = 1;
        unsigned int pkt_sent=0,pkt_ackd=0;
        long send_wind = 0;

	printf_log("Server:sending file %s to client\n",filename);
	printf_output("%10s\t%10s\t%10s\t%10s\t%10s\t%10s\t\n","Timestamp", "Send", "Receive", "Phase", "cwnd", "ssthresh");

	/* Open file to send */
	fp = fopen(filename,"r");

	if (fp == NULL) {
		printf_log("Error opening file\n");
		exit(1);
	}

	/* Initialize packet list */
	dll_init(&packet_list);

	tcp_state = SLOW_START;
	
	/* While there is more to send */
	while ((ret = fread(str,
			    sizeof(char),
			    MAX_DATA_SIZE,
			    fp)) != 0) {
		struct packet *tmp;
		unsigned int flags = 0;

		tmp = malloc(sizeof(*tmp));

		/* Prepare header */
		make_header(tmp,
			    src_port,
			    client_port,
			    seq_no,
			    0,
			    flags,
			    ret);

		/* Copy data */
		memcpy(tmp->data,
		       str,
		       ret);

		seq_no += ret+sizeof(tmp->hdr);

		printf_log("seq no:%d\n",tmp->hdr.seq_no);
		/* Send the packet */
		print_stats(1,
			    tmp->hdr.seq_no,
			    tmp->hdr.seq_no+tmp->hdr.length+sizeof(tmp->hdr),
			    0,
			    tcp_state==SLOW_START?SS_STRING:tcp_state==CONG_AVOID?CA_STRING:FR_STRING,
			    cwind,
			    ssthresh);

		send_packet(tmp, server_sockfd, (struct sockaddr*)&client_addr);

		/* Check if we need to restart the rto timer */
		if (dll_size(&packet_list) == 0) {
			printf_log("starting timer\n");
			create_rto_timer(&rto_timer);
			start_rto_timer(&rto_timer,rto);
		}

		/* Add the packet to tail of packet list */
		dll_add_to_tail(&packet_list,tmp);

		/* Increase the count of outstanding packets */
		pkt_sent++;
		send_wind = (pkt_sent - pkt_ackd) * MSS;
		printf_log("send_wind:%ld,cwind:%ld\n",send_wind,cwind);

		/* Wait for window size to open */
		while ((cwind < send_wind) || (cwind - send_wind) < MSS) {
			pkt_ackd += wait_for_ack();
			if (pkt_ackd > pkt_sent) {
				printf_log("Oops..more pkts acked than sent?\n");
				exit(1);
			}
			send_wind = (pkt_sent - pkt_ackd) * MSS;
			printf_log("received ack,send_wind=%ld,cwind=%ld\n",send_wind,cwind);
		}
	}

	fin_seq_no = seq_no;

	/* Wait for ACK of all packets */
	while(dll_size(&packet_list)) {
		pkt_ackd += wait_for_ack();
		printf_log("received ack,send_wind=%ld,cwind=%ld\n",send_wind,cwind);
	}

	/* If we have not yet sent FIN, send it */
	if (!fin_sent) {
		send_fin();
	}

	/* Wait for FIN */
	while (fin_rcvd == 0) {
		wait_for_ack();
	}

	timer_delete(rto_timer);
	dll_destroy(&packet_list);
	printf_log("Done sending file\n");
}

void* udp_accept(void *arg)
{
        struct sock_packet *sp;
        struct packet *p;
	struct packet resp;
	char client_name[ADDRSTRLEN];
	sigset_t set;

	printf_log("udp_accept\n");
	sp= (struct sock_packet*)arg;
	p = &(sp->p);
	client_port = sp->port;
	strcpy(client_name,
	       sp->hostname);

	/* Expecting SYN only */
        if(get_flags(p) != SYN_FLAG){
                printf_log("packet ignored (no SYN)\n");
                fflush(stdout);
                free(sp);
                pthread_exit(NULL);
        }

	printf_log("SYN reeived\n");
	/* Create retransmission timer */
	sigemptyset(&set);
	sigaddset(&set,SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
	signal(SIGUSR2,alarm_handler);
	create_rto_timer(&rto_timer);

	/* Create a port to send file */
        do{
                src_port = listen_port + count;
                server_sockfd = create_udp_socket(src_port);
                count++;
        } while (server_sockfd==-1);

        printf_log("new port: %d\n", src_port);
        fflush(stdout);

	/* Create handshake message 2 */
	handshake_msg = malloc(sizeof(*handshake_msg));

	/* Send SYN-ACK to peer */
	make_header(handshake_msg,
		    src_port,
		    client_port,
		    0,  /* Initial sequence number is 0 */
		    1,
		    SYN_FLAG + ACK_FLAG,
		    0);

	/* Fill up the client address structure */
	prepare_for_udp_send(&client_addr,
			     client_name,
			     client_port);

	/* Send the packet */
	send_packet(handshake_msg,server_sockfd,(struct sockaddr*)&client_addr);

	/* Start retransmission timer */
	start_rto_timer(&rto_timer,rto);

	/* Wait for an ACK from the peer */
	if ((recv_from(server_sockfd,
		       &resp,
		       MAX_PACKET_SIZE,
		       client_name,
		       &client_port) < 0) || (get_flags(&resp) != ACK_FLAG)) {
		printf_log("Unexpected packet.exiting\n");
		exit(1);	
	}

	
	/* Free structures used during handshake */
	printf_log("Handshake complete\n");
	timer_delete(rto_timer);
	free(handshake_msg);
	handshake_msg = NULL;
	free(sp);

	/* Now, send the file */
	send_file();
	return NULL;
}

void udp_listen(int sockfd)
{
        int ret;
        struct sock_packet *sp;
        pthread_t *tid;

        printf_log("listening...\n");
        fflush(stdout);

        while(1){
		sp = malloc(sizeof(*sp));
		tid = malloc(sizeof(*tid));

                if((ret = recv_from(sockfd,
				    &(sp->p),
				    MAX_PACKET_SIZE,
				    sp->hostname,
				    &(sp->port)))>0) {
                        dll_add_to_tail(&tid_dll,tid);
                        pthread_create(tid, NULL, &udp_accept,(void*)sp);
                }
                else{
                        free(sp);
                        free(tid);
                }
        }
}

void main_handler(int sig,
		  siginfo_t *si,
		  void *uc)
{
	int i;
	int size = dll_size(&tid_dll);
	pthread_t *tid;

#ifdef LOG
	printf_log("Main signal handler:%d %p %p\n",sig,si,uc);
#else
	sig = 0;
	si = NULL;
	uc = NULL;
#endif

	for (i=0;i<size;i++) {
		tid = dll_at(&tid_dll,i);
		pthread_kill(*tid,SIGUSR2);
	}
}

int main(int argc,char **argv)
{
	struct sigaction sa;

	if (argc != 3) {
		printf("Usage: %s <server port #> <input file name>\n",argv[0]);
                exit(1);
	}

	strcpy(filename,
	       argv[2]);

	mp3_init();
	dll_init(&tid_dll);

	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = main_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGUSR1, &sa, NULL);

	listen_port = atoi(argv[1]);
        listenfd = create_udp_socket(listen_port);
        udp_listen(listenfd);

        close(listenfd);

        return 0;
}
