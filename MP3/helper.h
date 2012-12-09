#ifndef __MP3_HELPER_H__
#define __MP3_HELPER_H__

#define SYN_BIT 0
#define FIN_BIT 1
#define ACK_BIT 2

#define SYN_FLAG (1<<SYN_BIT)
#define FIN_FLAG (1<<FIN_BIT)
#define ACK_FLAG (1<<ACK_BIT)

typedef struct _header{
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int seq_no;
	unsigned int ack_no;
	unsigned short flags;
	unsigned short length;
}header;

#define printf_output printf

/* #define LOG */
#ifdef LOG
#define printf_log printf
#else
#define printf_log(...)
#endif

#define MAX_PACKET_SIZE 100
#define HEADER_SIZE sizeof(header)
#define MAX_DATA_SIZE MAX_PACKET_SIZE-HEADER_SIZE
#define ADDRSTRLEN INET_ADDRSTRLEN

struct packet {
	header hdr;
	char data[MAX_DATA_SIZE];
};


void make_header(struct packet *p,
		unsigned short src_port,
		unsigned short dst_port,
		unsigned int seq_no,
		unsigned int ack_no,
		unsigned short flags,
		unsigned short length);
int get_flags(struct packet *p);
void show_header(struct packet *p);
int create_udp_socket(unsigned short port);
unsigned short get_port(struct sockaddr *sa);
int send_to(int sockfd,void *msg,int len,char *dest,unsigned short dest_port);
int recv_from(int sockfd,void *buf,int len,char *src,unsigned short *src_port);
void send_packet(struct packet *,
                 int,
                 struct sockaddr *);
void create_rto_timer(timer_t *);
void start_rto_timer(timer_t *,
		     int);
void prepare_for_udp_send(struct sockaddr_in *,
			  char *,
			  int);
void mp3_init(void);
ssize_t mp3_sendto(int sockfd, void *buff, size_t nbytes, int flags,
		   const struct sockaddr *to, socklen_t addrlen);

#endif
