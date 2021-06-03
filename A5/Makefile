CC = gcc
FLAGS = -g -Wall -pedantic 

all : main
run:
	./test.py tests/ main
main: main.o
	$(CC) -o $@ $< $(FLAGS)

%.o: %.cpp
	$(CC) -c -o $@ $< $(FLAGS)

clean:
	rm main *.o
