CC = gcc -g
FLAGS = -Wall -pedantic -g -O2 

all : md5
md5: main.o
	$(CC) -o $@ $< $(FLAGS)

%.o: %.cpp
	$(CC) -c -o $@ $< $(FLAGS)

clean:
	rm md5 *.o
