
all:
	gcc -Wall yoursql.c -o yoursql -lpcap

clean:
	rm yoursql
