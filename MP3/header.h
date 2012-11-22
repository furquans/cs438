#ifndef __HEADER_H_
#define __HEADER_H_

#define SYN_BIT 0
#define FIN_BIT 1
#define ACK_BIT 2

#define SYN_FLAG (1<<SYN_BIT)
#define FIN_FLAG (1<<FIN_BIT)
#define ACK_FLAG (1<<ACK_BIT)

struct header {
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int seq_no;
	unsigned int ack_no;
	unsigned short flags;
	unsigned short length;
};

#define MAX_DATA_SIZE (100-sizeof(struct header))

struct packet {
	struct header hdr;
	char data[MAX_DATA_SIZE];
};

#endif
