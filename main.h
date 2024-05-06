#include <stdlib.h>

#define BUFSIZE 512

extern void generate_iv(uint8_t *iv);
extern unsigned int randomnize();
extern size_t calculate_padding(size_t);
extern size_t pkcs7_padding(uint8_t *to, uint8_t *from, size_t len);
extern void encriptar(uint8_t *text, uint8_t *key, uint8_t *iv, size_t len);
extern void desencriptar(uint8_t *buf, uint8_t *key, uint8_t *iv, size_t len);
extern int remove_pkcs7_padding(uint8_t *buf, size_t len);
extern int encriptar_texto(char*, char*);
extern int desencriptar_texto(char*, char*);