
all: aes

aes: aes256.o main.o base64.o
	gcc -o aes aes256.o main.o base64.o

main.o: main.c aes256.h base64.h main.h
	gcc -c main.c -o main.o

aes256.o: aes256.c aes256.h
	gcc -c aes256.c -o aes256.o

base64.o: base64.c base64.h
	gcc -c base64.c -o base64.o

clean:
	rm -fr cifrar descifrar aes *.o