# the compiler: gcc for C program, define as g++ for C++

# compiler flags:
#  -g     - this flag adds debugging information to the executable file
#  -Wall  - this flag is used to turn on most compiler warnings

# The build target
all: nn nn.o

nn.o: nn.cpp
	g++ -c nn.cpp

nn: nn.o
	g++ -g -Wall -o nn nn.o -std=c++11

clean:
	-rm -f nn *.o

run:
	./nn