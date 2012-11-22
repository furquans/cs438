CC = gcc
FLAGS = -g -W -Wall
LIBS = -lpthread

all: server client

server: server.c dll.o header.h
	@(echo "compiling $< ...")
	@($(CC) $(FLAGS) $(LIBS) $^ -o $@)

client: client.c dll.o header.h
	@(echo "compiling $< ...")
	@($(CC) $(FLAGS) $(LIBS) $^ -o $@)

dll.o: dll.c dll.h
	@(echo "compiling $< ...")
	@($(CC) -c $(FLAGS) $< -o $@ $(LIBS))

.PHONY : clean
clean:
	rm -f *.o server client