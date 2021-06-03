CC = gcc
FLAGS = -g -Wall -pedantic 

all : a5
run:
	./test.py tests/ main
a5: main.o
	$(CC) -o $@ $< $(FLAGS)

%.o: %.cpp
	$(CC) -c -o $@ $< $(FLAGS)

clean:
	rm a5 *.o
