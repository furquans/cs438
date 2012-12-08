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
static __thread int rto = 1;
static __thread timer_t rto_timer;
static __thread int fin_resend_count=0;
static __thread int fin_seq_no;
static __thread unsigned short src_port;
static __thread unsigned short client_port;

static __thread	unsigned char fin_sent = 0;
static __thread	unsigned char fin_rcvd = 0;
static __thread struct packet *handshake_msg;
static __thread int handshake_resend_count = 0;

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

	printf("In pthread handler:%d\n",sig);
	size = dll_size(&packet_list);
	timer_gettime(rto_timer,&its);

	if ((its.it_value.tv_sec == 0) &&
	    (its.it_value.tv_nsec == 0)) {
		if (handshake_msg) {
			if (handshake_resend_count < MAX_RESEND) {
				/* Send handshake msg 2 */
				send_packet(handshake_msg,server_sockfd,(struct sockaddr*)&client_addr);
				/* Increment the count */
				handshake_resend_count++;
			} else {
				printf("Handshake failed\n");
				pthread_exit(NULL);
			}

		} else if (size) {
			struct packet *tmp = dll_at(&packet_list,0);
			printf("Retransmitting packet with seq number:%d\n",tmp->hdr.seq_no);
			show_header(tmp);
			send_packet(tmp,server_sockfd,(struct sockaddr*)&client_addr);
		} else if (fin_sent == 1) {
			if ((fin_rcvd == 0) &&
			    (fin_resend_count < MAX_RESEND)) {
				fin_resend_count++;
				printf("Resending fin:%d\n",fin_resend_count);
				send_fin();
			} else {
				printf("Fin resend count exceeded.exiting\n");
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
				show_header(&resp);
				retval = free_data(resp.hdr.ack_no,&packet_list);
			}
			if (resp.hdr.flags & FIN_FLAG) {
				printf("FIN received\n");
				fin_rcvd = 1;
			}
		}
	} else {
		printf("error:%d\n",retval);
	}

	return retval;
}

/* Send file to client */
void send_file()
{
	FILE *fp;
	char str[MAX_DATA_SIZE];
	int ret;
	int seq_no = 0;
	unsigned int wind_size = 5 * MSS;
	unsigned int curr_wind = 0;

	printf("Server:sending file %s to client\n",filename);

	/* Open file to send */
	fp = fopen(filename,"r");

	if (fp == NULL) {
		printf("Error opening file\n");
		exit(1);
	}

	/* Initialize packet list */
	dll_init(&packet_list);
	
	/* While there is more to send */
	while ((ret = fread(str,
			    sizeof(char),
			    MAX_DATA_SIZE,
			    fp)) != 0) {
		struct packet *tmp;
		unsigned int flags = 0;

		tmp = malloc(sizeof(*tmp));

		/* Check if less data than MAX, then send FIN */
		if (ret != MAX_DATA_SIZE) {
			flags |= FIN_FLAG;
			fin_sent = 1;
		}

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

		tmp->hdr.seq_no = seq_no;
		seq_no += ret;

		printf("seq no:%d\n",tmp->hdr.seq_no);
		/* Send the packet */
		if ((tmp->hdr.seq_no == 0) || (tmp->hdr.seq_no % 420))
		send_packet(tmp, server_sockfd, (struct sockaddr*)&client_addr);

		/* Check if we need to restart the rto timer */
		if (dll_size(&packet_list) == 0) {
			printf("starting timer\n");
			create_rto_timer(&rto_timer);
			start_rto_timer(&rto_timer,rto);
		}

		/* Add the packet to tail of packet list */
		dll_add_to_tail(&packet_list,tmp);

		/* Increase the count of outstanding packets */
		curr_wind+=MSS;
		printf("curr_wind:%d,wind_size:%d\n",curr_wind,wind_size);

		/* If fin is sent, just break from here */
		if (fin_sent)
			break;

		/* Wait for window size to open */
		while ((wind_size == curr_wind) || ((wind_size - curr_wind) < MSS)) {
		/* while (curr_wind == wind_size) { */
			wind_size += wait_for_ack() * MSS;
			/* curr_wind -= wait_for_ack(); */
			printf("received ack,curr_win=%d,wind_size=%d\n",curr_wind,wind_size);
		}
	}

	fin_seq_no = seq_no;

	/* If we have not yet sent FIN, send it */
	if (!fin_sent) {
		send_fin();
	}

	/* Wait for ACK of all packets */
	while(dll_size(&packet_list)) {
		wind_size += wait_for_ack() * MSS;
		/* curr_wind -= wait_for_ack(); */
		printf("received ack,curr_win=%d,wind_size=%d\n",curr_wind,wind_size);
	}

	/* Wait for FIN */
	while (fin_rcvd == 0) {
		wait_for_ack();
	}

	timer_delete(rto_timer);
	dll_destroy(&packet_list);
	printf("Done sending file\n");
}

void* udp_accept(void *arg)
{
        struct sock_packet *sp;
        struct packet *p;
	struct packet resp;
	char client_name[ADDRSTRLEN];
	sigset_t set;

	printf("udp_accept\n");
	sp= (struct sock_packet*)arg;
	p = &(sp->p);
	client_port = sp->port;
	strcpy(client_name,
	       sp->hostname);

	/* Expecting SYN only */
        if(get_flags(p) != SYN_FLAG){
                printf("packet ignored (no SYN)\n");
                fflush(stdout);
                free(sp);
                pthread_exit(NULL);
        }

	printf("SYN reeived\n");
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

        printf("new port: %d\n", src_port);
        fflush(stdout);

	/* Create handshake message 2 */
	handshake_msg = malloc(sizeof(*handshake_msg));

	/* Send SYN-ACK to peer */
	make_header(handshake_msg,
		    src_port,
		    client_port,
		    0,  /* Initial sequence number is 0 */
		    0,
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
		printf("Unexpected packet.exiting\n");
		exit(1);	
	}

	
	/* Free structures used during handshake */
	printf("Handshake complete\n");
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

        printf("listening...\n");
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

	printf("Main signal handler:%d %p %p\n",sig,si,uc);

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
