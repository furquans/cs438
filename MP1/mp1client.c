/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "mp1.h"
#include "dll.h"

#define MAXDATASIZE 1024 // max number of bytes we can get at once 



dll_t l;
pthread_cond_t c;
pthread_mutex_t m;

// get sockaddr, IPv4 or IPv6
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


int ith_bit(void *buf,int i)
{
        int block=i/8;
        uint8_t int8=*((uint8_t*)(buf+block));
        int offset=i-block*8;
        return ((int8<<offset)&(0x80))==0? 0:1;
}

int crc_check(void *buf)
{
	char data[1024];
	memcpy((void*)data,buf,1022);
	bzero((void*)(data+1022),2);
	
	uint16_t checkbits=*((uint16_t*)(buf+1022));
	checkbits=ntohs(checkbits);
	
	int i,curr_bit;
	uint16_t reg=0;
	
	for(i=0;i<1022*8+12;i++){
		curr_bit=ith_bit((void*)data,i);
		reg=(reg<<1)+curr_bit;
		if(ith_bit((void*)(&reg)+1,3)==1)
			reg^=0x080d;
		reg&=0x0fff;
	}
	return (reg==checkbits)? 0:-1;
}

void* mywrite(void *ptr)
{
	FILE *file=(FILE*)ptr;
	void *data;
	int datalength,filepos;
	while(1){
	
		pthread_mutex_lock(&m);
		while(dll_size(&l)==0)
			pthread_cond_wait(&c,&m);
		pthread_mutex_unlock(&m);

		pthread_mutex_lock(&m);
		data=dll_remove_from_head(&l);
		pthread_mutex_unlock(&m);

		datalength=ntohs(*((uint16_t*)data));
		filepos=ntohl(*((uint32_t*)(data+2)));
		if(datalength==0){
			free(data);
			break;
		}
		fseek(file,filepos,SEEK_SET);
		MP1_fwrite(data+6,datalength,1,file);
		free(data);
	}
	return NULL;
}
	
void* myread(void* ptr)
{
	int sockfd=*((int*)ptr);
	int numbytes;
	char *buf=(char*)malloc(MAXDATASIZE);
	bzero(buf,MAXDATASIZE);
	int len;
	while(1){
		len=0;
		while((numbytes=MP1_read(sockfd,buf+len,MAXDATASIZE-len))!=-1){
			len+=numbytes;
			if(numbytes==0||len==MAXDATASIZE)
				break;
		}
		if(numbytes==0&&len<MAXDATASIZE){
			bzero(buf,MAXDATASIZE);
			pthread_mutex_lock(&m);
			dll_add_to_tail(&l,(void*)buf);
			pthread_mutex_unlock(&m);
			pthread_cond_broadcast(&c);
			break;
		}
		if(crc_check(buf)==0){
			pthread_mutex_lock(&m);
			dll_add_to_tail(&l,(void*)buf);
			pthread_mutex_unlock(&m);
			pthread_cond_broadcast(&c);

			buf=(char*)malloc(MAXDATASIZE);
		}
		else
			bzero(buf,MAXDATASIZE);
	}
	close(sockfd);
	return NULL;
}

int main(int argc, char *argv[])
{
	int sockfd;  
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	if (argc != 4) {
	    fprintf(stderr,"usage: %s <hostname> <port #> <output file>\n",argv[0]);
	    exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("client: connect");
			continue;
		}
		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect");
		exit(1);
	}
	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),s, sizeof s);
	
	printf("client: connecting to %s\n",s);
	freeaddrinfo(servinfo); // all done with this structure

	FILE *file=fopen(argv[3],"w");
	if(file==NULL){
		fprintf(stderr,"file %s open error",argv[3]);
		exit(1);
	}
		
	pthread_t read_tid,write_tid;
	dll_init(&l);
	pthread_cond_init(&c,NULL);
	pthread_mutex_init(&m,NULL);

	pthread_create(&read_tid,NULL,&myread,(void*)&sockfd);
	pthread_create(&write_tid,NULL,&mywrite,(void*)file);

	pthread_join(read_tid, NULL);
	pthread_join(write_tid,NULL);

	fclose(file);
	dll_destroy(&l);
	pthread_mutex_destroy(&m);
	pthread_cond_destroy(&c);
	return 0;
}

