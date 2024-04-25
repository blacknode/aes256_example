#include <stdlib.h>

extern void generate_iv(uint8_t *iv);
extern unsigned int randomnize();
extern size_t calculate_padding(size_t);
extern size_t pkcs7_padding(uint8_t *to, uint8_t *from, size_t len);
extern void encriptar(uint8_t *text, uint8_t *key, uint8_t *iv, size_t len);
extern char *desncriptar(uint8_t *text, uint8_t *key);