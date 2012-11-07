CC = gcc
FLAGS = -g -W -Wall
LIBS = -lrt

all: router

router: router.c dll.o error.h router.h
	@(echo "compiling $< ...")
	@($(CC) $(FLAGS) $^ -o $@ $(LIBS))

dll.o: dll.c dll.h
	@(echo "compiling $< ...")
	@($(CC) -c $(FLAGS) $< -o $@ $(LIBS))

.PHONY : clean
clean:
	rm -f *.o router