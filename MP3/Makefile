CC = gcc
GPP = g++
FLAGS = -g -W -Wall
LIBS = -lpthread -lrt

all: mp3server mp3client

mp3server: mp3.o server.o dll.o helper.o
	@(g++ mp3.o server.o dll.o helper.o -o mp3server -lrt -pthread)

mp3client: mp3.o client.o dll.o helper.o
	@(g++ mp3.o client.o dll.o helper.o -o mp3client -lrt -pthread)

mp3.o: mp3.cc
	@(g++ -c -I /usr/lib/x86_64-redhat-linux5E/include mp3.cc -pthread)

client.o: client.c
	@($(CC) -c  $^ -o $@)

server.o: server.c
	@($(CC) -c  $^ -o $@)

dll.o: dll.c
	@($(CC) -c  $^ -o $@)

helper.o: helper.c
	@($(CC) -c  $^ -o $@)

.PHONY : clean
clean:
	rm -f *.o mp3server mp3client