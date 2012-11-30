CC = gcc
FLAGS = -g -W -Wall

all: bonus

bonus: bonus.c list.o
	@(echo "compiling $< ...")
	@($(CC) $(FLAGS) $(LIBS) $^ -o $@)

list.o: list.c list.h
	@(echo "compiling $< ...")
	@($(CC) -c $(FLAGS) $< -o $@ $(LIBS))

.PHONY : clean
clean:
	rm -f *.o bonus
