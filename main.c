#include "aes256.h"
#include "b64.h"
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

static const char convert2y[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '[', ']'};

/** Converts a character to its (base64) numnick value. */
static const unsigned int convert2n[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 62, 0, 63, 0, 0,
    0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

void generate_iv(uint8_t *);

void generate_iv(uint8_t *iv)
{
  srand(time(NULL));
  int s = 0;
  while (s < 16)
    iv[s++] = (uint8_t)convert2y[rand() % 63];
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

  textlen = textlen > 496 ? 496 : textlen;
  keylen = keylen > 32 ? 32 : keylen;

  printf("Text len: %lu Key len: %lu\n", textlen, keylen);

  uint8_t *k = (uint8_t *)malloc(32);
  uint8_t *m = (uint8_t *)malloc(528); // buf + padding + iv
  uint8_t iv[16] = {0};

  if (!k || !m)
    return 0;

  generate_iv(iv);

  int keypad = 32 - keylen;
  int textpad = textlen;
  if ((textpad % AES_BLOCKLEN) == 0)
    textpad += AES_BLOCKLEN;
  else
    textpad = (AES_BLOCKLEN - (textlen % AES_BLOCKLEN)) + AES_BLOCKLEN;

  int pad = textpad;
  uint8_t *kptr = k;
  uint8_t *mptr = m;
  while (*key)
    *k++ = (uint8_t)*key++;
  while (keypad--)
    *k++ = padding_blocks[keylen % AES_BLOCKLEN];
  *k = '\0';
  while (*text)
    *m++ = (uint8_t)*text++;
  while (textpad--)
    *m++ = padding_blocks[textlen % AES_BLOCKLEN];
  int i = 0;
  *m = '\0';

  printf("TOTAL MSJ: %lu\n", textlen);
  textlen += pad; // +16;

  DUMP("MENSAJE", mptr, textlen);
  DUMP("CLAVE", kptr, 32);
  DUMP("IV", iv, 16);

  struct AES_ctx ctx;

  AES_init_ctx_iv(&ctx, kptr, iv);
  AES_CBC_encrypt_buffer(&ctx, mptr, textlen);

  uint8_t mbuf[textlen + 16];
  memset(mbuf, 0, sizeof(mbuf));
  memcpy(mbuf, mptr, textlen);
  memcpy(mbuf + textlen, iv, 16);

  DUMP("MENSAJE ENCRIPTADO", mbuf, textlen + 16);

  char *base64encoded = b64_encode(mbuf, textlen + 16);
  if (!base64encoded)
  {
    free(kptr);
    free(mptr);
    return 0;
  }
  printf("BASE64: %s\n", base64encoded);
  uint8_t *base64decoded = b64_decode(base64encoded, strlen(base64encoded));
  if (!base64decoded)
  {
    free(kptr);
    free(mptr);
  }
  DUMP("BUFFER A DESCIFRAR", base64decoded, (int)strlen((char *)base64decoded));

  int decoded_len = (int)strlen((char *)base64decoded);
  uint8_t iv_from_base64[16] = {0};
  for (int i = 0; i < 16; i++)
    iv_from_base64[i] = base64decoded[(decoded_len - 16) + i];

  base64decoded[(decoded_len - 16)] = '\0';
  DUMP("IV EXTRAIDO", iv_from_base64, 16);

  struct AES_ctx ctx_dec;
  AES_init_ctx_iv(&ctx_dec, kptr, iv_from_base64);
  AES_CBC_decrypt_buffer(&ctx_dec, base64decoded, (decoded_len - 16));

  DUMP("MENSAJE DESCIFRADO", base64decoded, (decoded_len - 16));

  uint8_t result[497] = {0};
  int z = decoded_len - 16;
  int p = 0;
  for (size_t i = 0; i < z; i++)
  {
    if (!isprint(base64decoded[i]))
      continue;
    result[i] = base64decoded[i];
    p++;
  }

  result[p] = '\0';
  printf("Resultado: %s\n", (char *)result);

  free(base64encoded);
  free(base64decoded);
  free(kptr);
  free(mptr);

  return 0;
}