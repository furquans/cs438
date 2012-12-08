CC = gcc
FLAGS = -g -W -Wall
LIBS = -lpthread -lrt

all: server client

server: server.c dll.o helper
	@(echo "compiling $< ...")
	@($(CC) $(FLAGS) $(LIBS) $^ -o $@)

client: client.c dll.o helper
	@(echo "compiling $< ...")
	@($(CC) $(FLAGS) $(LIBS) $^ -o $@)

helper: helper.c helper.h
	@(echo "compiling $< ...")
	@($(CC) -c $(FLAGS) $< -o $@ $(LIBS))

dll.o: dll.c dll.h
	@(echo "compiling $< ...")
	@($(CC) -c $(FLAGS) $< -o $@ $(LIBS))

.PHONY : clean
clean:
	rm -f *.o server client