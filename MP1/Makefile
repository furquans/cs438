

CC = gcc
FLAGS = -g -W -Wall
LIBS = -lpthread

all: mp1client

mp1client: mp1client.c mp1_base.o dll.o
	$(CC) $(FLAGS) $^ -o $@ $(LIBS)

mp1_base.o: mp1_base.c mp1.h
	$(CC) -c $(FLAGS) $< -o $@ $(LIBS)

dll.o: dll.c dll.h
	$(CC) -c $(FLAGS) $< -o $@ $(LIBS)

.PHONY : clean
clean: 
	rm -f *.o mp1client
