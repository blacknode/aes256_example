
all: aes

aes: aes256.o main.o b64.o buf.o
	gcc -o aes aes256.o main.o b64.o buf.o

buf.o: buf.c buf.h
	gcc -c buf.c -o buf.o

main.o: main.c aes256.h b64.h buf.h
	gcc -c main.c -o main.o

aes256.o: aes256.c aes256.h
	gcc -c aes256.c -o aes256.o

b64.o: b64.c b64.h
	gcc -c b64.c -o b64.o

clean:
	rm -fr cifrar descifrar aes *.o