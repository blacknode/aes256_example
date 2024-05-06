CC=gcc
CPPFLAGS = -I/opt/homebrew/Cellar/jansson/2.14/include -I/opt/homebrew/Cellar/pcre2/10.43/include
LIBS = -L/opt/homebrew/Cellar/pcre2/10.43/lib -lpcre2-8

SRC = \
	main.c \
	aes256.c \
	base64.c \
	pcre.c

OBJS = ${SRC:%.c=%.o}

all: aes

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

aes: ${OBJS}
	${CC} ${OBJS} ${LIBS} -o aes

main.o: main.c aes256.h base64.h main.h pcre.h
aes256.o: aes256.c aes256.h
base64.o: base64.c base64.h
pcre.o: pcre.c pcre.h

clean:
	rm -fr cifrar descifrar aes *.o