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
#include<signal.h>

#define LOCALPORT 3355

static dll_t packet_list;
static unsigned int expected_seq = 1;

static FILE *fp=NULL;
static unsigned short src_port;

static struct sockaddr_in server_addr;

static timer_t rto_timer;
static struct packet *handshake_msg;
static int client_sockfd = -1;
static unsigned short server_port;

int send_ack()
{
	struct packet *tmp;
	struct packet resp;
	int ret = 0;
	int flags = ACK_FLAG;

	tmp = dll_at(&packet_list,0);

	while (tmp && (tmp->hdr.seq_no == expected_seq)) {
		expected_seq += tmp->hdr.length + sizeof(tmp->hdr);
		fwrite(tmp->data,
		       tmp->hdr.length,
		       1,
		       fp);

		if (tmp->hdr.flags & FIN_FLAG) {
			printf_log("FIN received\n");
			ret = 1;
		}
		dll_remove_from_head(&packet_list);
		free(tmp);
		tmp = dll_at(&packet_list,0);
	}

	if (ret == 1) {
		flags |= FIN_FLAG;
	}
	make_header(&resp,
		    src_port,
		    server_port,
		    0,
		    expected_seq,
		    flags,
		    0);

	send_packet(&resp, client_sockfd, (struct sockaddr*)&server_addr);
	return ret;
}

void add_to_packet_list(struct packet *curr)
{
	int i = 0;
	int size = dll_size(&packet_list);

	if (curr->hdr.seq_no < expected_seq) {
		return;
	}

	while (i < size) {
		struct packet *tmp = dll_at(&packet_list, i);
		if (tmp->hdr.seq_no == curr->hdr.seq_no) {
			return;
		}
		if (tmp->hdr.seq_no > curr->hdr.seq_no) {
			dll_add_at_index(&packet_list,curr,i);
			return;
		}
		i++;
	}
	dll_add_at_index(&packet_list,curr,i);
}

void get_file(char *filename)
{
	struct packet tmp;
	int ret;
	struct sockaddr_in *their_addr;
        socklen_t their_len;

	fp = fopen(filename,"w+");

	if (fp == NULL) {
		printf_log("Error opening file\n");
		exit(1);
	}

	dll_init(&packet_list);
	their_len = sizeof(their_addr);

	while((ret = recvfrom(client_sockfd,
			      &tmp,
			      sizeof(tmp),
			      0,
			      NULL,
			      NULL)) > 0) {
		struct packet *new;
		char str[100];

		show_header(&tmp);
		new = malloc(sizeof(*new));
		*new = tmp;

		printf_log("ret:%d\n",ret);
		memcpy(str,
		       new->data,
		       84);
		str[85]='\0';
		printf_log("str:%s\n",str);
		add_to_packet_list(new);

		if (send_ack() == 1) {
			break;
		}
	}

	dll_destroy(&packet_list);

	fclose(fp);
}

int udp_connect(int sockfd, char *server_name)
{
        int ret;
        unsigned short dst_port=server_port;
	struct packet resp;

	/* Create retransmission timer */
	create_rto_timer(&rto_timer);

	/* Create handshake msg */
	handshake_msg = malloc(sizeof(*handshake_msg));

	/* Send SYN message to server */
	make_header(handshake_msg,
		    src_port,
		    server_port,
		    0,
		    0,
		    SYN_FLAG,
		    0);

	/* Prepare for Sending to peer */
	prepare_for_udp_send(&server_addr,
			     server_name,
			     server_port);

	/* Send the message to server */
	send_packet(handshake_msg,
		    client_sockfd,
		    (struct sockaddr*)&server_addr);

	/* Start retransmission timer */
	start_rto_timer(&rto_timer,10);

	/* Wait for an SYN-ACK from server */
	while ((ret=recv_from(sockfd,
		      &resp,
		      MAX_PACKET_SIZE,
		      server_name,
			      &dst_port)) <0);

	/* Delete the timer */
	timer_delete(rto_timer);

	server_port = dst_port;

	printf_log("server_port:%d\n",server_port);
	show_header(&resp);
	/* Received SYN-ACK. Send ACK */
	if((ret>0) && (get_flags(&resp)==(SYN_FLAG+ACK_FLAG))) {
		printf_log("good! sending ACK...\n");
		fflush(stdout);
		make_header(handshake_msg,
			    src_port,
			    dst_port,
			    1,
			    1,
			    ACK_FLAG,
			    0);
		prepare_for_udp_send(&server_addr,
				     server_name,
				     dst_port);

		send_packet(handshake_msg,
			    client_sockfd,
			    (struct sockaddr*)&server_addr);
	} else {
		printf_log("Problem with SYN-ACK\n");
		exit(1);
	}
	free(handshake_msg);
	return ret;
}

void main_handler(int sig,
                  siginfo_t *si,
                  void *uc)
{
#ifdef LOG
	printf_log("Main signal handler:%d %p %p\n",sig,si,uc);
#else
	sig = 0;
	si = NULL;
	uc = NULL;
#endif

	if (handshake_msg) {
		send_packet(handshake_msg,  client_sockfd, (struct sockaddr*)&server_addr);
		start_rto_timer(&rto_timer,10);
	}
}

int main(int argc,
	 char **argv)
{
	char server_name[ADDRSTRLEN];
	struct sigaction sa;

        if (argc != 4) {
		fprintf(stderr,"Usage: %s <server name> <server port #> <output file name>\n",argv[0]);
		exit(1);
        }

	mp3_init();
        strcpy(server_name,argv[1]);
	server_port=atoi(argv[2]);
        src_port=LOCALPORT;

	/* Initialize signal handler for alarm */
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = main_handler;
        sigemptyset(&sa.sa_mask);
	sigaction(SIGUSR1, &sa, NULL);

	/* Create UDP socket */
	while((client_sockfd = create_udp_socket(src_port)) == -1) {
		src_port++;
	}

	/* Connect to peer */
	udp_connect(client_sockfd,server_name);

	/* Get file */
	get_file(argv[3]);

        close(client_sockfd);

        return 0;

}

