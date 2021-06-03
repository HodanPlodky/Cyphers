CC = gcc
FLAGS = -g -Wall -pedantic 

all : rc4
rc4: main.o
	$(CC) -o $@ $< $(FLAGS)

%.o: %.cpp
	$(CC) -c -o $@ $< $(FLAGS)

clean:
	rm rc4 *.o
