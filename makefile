LDLIBS=-lpcap

main: main.cpp
	g++ -std=c++14 $^ -o $@ $(LDLIBS)

clean:
	rm -f main *.o
