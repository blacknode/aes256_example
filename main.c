#include "aes256.h"
#include "b64.h"
#include "buf.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <ctype.h>

#define DUMP(s, buf, sz)                \
  {                                     \
    printf("%s: ", s);                  \
    for (int i = 0; i < (sz); i++)      \
      printf("%02x ", (uint8_t)buf[i]); \
    printf("\n");                       \
  }

unsigned int padding_sizes[] = {
    16, 15, 14, 13,
    12, 11, 10, 9,
    8, 7, 6, 5,
    4, 3, 2, 1};

uint8_t padding_blocks[] = {
    0x10,
    0x0f,
    0x0E,
    0x0D,
    0x0C,
    0x0B,
    0x0A,
    0x09,
    0x08,
    0x07,
    0x06,
    0x05,
    0x04,
    0x03,
    0x02,
    0x01,
};

size_t calculate_padding(size_t);

size_t calculate_padding(size_t textlen)
{
  size_t remainder = textlen % AES_BLOCKLEN;
  if (remainder == 0)
  {
    return AES_BLOCKLEN;
  }
  else
  {
    return AES_BLOCKLEN - remainder;
  }
}

int main(int argc, char const *argv[])
{
  if (argc < 3)
    return 0;

  char *text = (char *)argv[1];
  char *key = (char *)argv[2];
  size_t textlen = strlen(text);
  size_t keylen = strlen(key);

  if (!textlen || !keylen)
    return 0;

  printf("Text len: %lu Key len: %lu\n", textlen, keylen);

  textlen = textlen > 496 ? 496 : textlen;
  keylen = keylen > 32 ? 32 : keylen;

  uint8_t m[528] = {0};
  uint8_t k[32] = {0};
  uint8_t iv[16] = {0};

  generate_iv(iv);

  int tpad = calculate_padding(textlen);
  int kpad = calculate_padding(keylen);

  memcpy(k, key, keylen);
  memset(k + keylen, padding_blocks[kpad % AES_BLOCKLEN], kpad);
  keylen += kpad;

  memcpy(m, text, textlen);
  memset(m + textlen, padding_blocks[tpad % AES_BLOCKLEN], tpad);

  textlen += tpad;
  uint8_t *pos = (uint8_t *)strchr((char *)m, 0x0);
  if (pos)
  {
    size_t l = pos - m;
    m[l] = '\0';
    printf("0x0 pos: %lu\n", l);
  }

  printf("text len: %lu\n", textlen);
  DUMP("MSJ", m, textlen);
  DUMP("KEY", k, keylen);
  DUMP("IV", iv, sizeof(iv));

  struct AES_ctx enc_ctx, dec_ctx;
  AES_init_ctx_iv(&enc_ctx, k, iv);
  AES_CBC_encrypt_buffer(&enc_ctx, m, textlen);

  uint8_t mbuf[textlen + 16];
  memcpy(mbuf, m, textlen);
  memcpy(mbuf + textlen, iv, 16);

  char *b64enc = b64_encode(mbuf, sizeof(mbuf));
  uint8_t *b64dec = (uint8_t *)b64_decode(b64enc, strlen(b64enc));
  DUMP("ENC MSJ", mbuf, sizeof(mbuf));
  printf("BASE 64: %s\n", b64enc);
  DUMP("BASE 64 DECODE", b64dec, strlen((char*)b64dec));

  free(b64enc);
  free(b64dec);

  return 0;
}