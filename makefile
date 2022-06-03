CC = g++
FLAGS = -pedantic -Wall

main: main.o MiniAES.o 
	$(CC) main.o MiniAES.o -o main $(FLAGS)

MiniAES.o: MiniAES.cpp MiniAES.h
	$(CC) -c MiniAES.cpp $(FLAGS)

main.o: main.cpp
	$(CC) -c main.cpp $(FLAGS)

clean:
	rm *.o main