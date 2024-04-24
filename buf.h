#ifndef BUF_H
#define BUF_H

#include <stdio.h>
#include <stdlib.h>

extern void generate_iv(uint8_t *iv);
extern size_t to_buf(unsigned char *buf, unsigned char *str);
#endif