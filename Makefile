all: nfqnl_test


nfqnl_test : nfqnl_test.o
	gcc -o nfqnl_test nfqnl_test.o

nfqnl_test.o : nfqnl_test.c
	gcc -c -o nfqnl_test.o nfqnl_test.c

clean:
	rm -f nfqnl_test.o
