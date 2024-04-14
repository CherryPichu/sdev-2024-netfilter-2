LDLIBS += -lpcap

all: nfqnl_test

nfqnl_test.o: nfqnl_test.c
	gcc -c nfqnl_test.c -o nfqnl_test.o 

trim.o: lib/trim.c
	gcc -c lib/trim.c -o trim.o

Search.o : lib/Search.c
	gcc -o Search.o -c lib/Search.c

nfqnl_test: nfqnl_test.o trim.o Search.o
	gcc nfqnl_test.o trim.o Search.o -o nfqnl_test -lnetfilter_queue -lsqlite3

clean:
	rm -f nfqnl_test Search trim *.o