#include "aes256.h"
#include "base64.h"
#include "pcre.h"
#include "main.h"
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
    {                                   \
      printf("%02x ", (uint8_t)buf[i]); \
    }                                   \
    printf("\n");                       \
  }

static const char convert2y[68] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '[', ']', '{', '}'};

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

unsigned int randomnize()
{
  unsigned int number;
  FILE *urandom = fopen("/dev/urandom", "r");
  if (urandom)
  {
    fread(&number, 1, sizeof(number), urandom);
    fclose(urandom);
  }
  return number;
}

void generate_iv(uint8_t *iv)
{
  srand(randomnize());
  for (int i = 0; i < 16; i++)
  {
    int r = rand() % (sizeof(convert2y) - 1);
    char c = convert2y[r];
    c = c == 0 ? 'A' : c;
    iv[i] = (uint8_t)c;
  }
}

size_t calculate_padding(size_t textlen)
{
  size_t remainder = textlen % AES_BLOCKLEN;
  if (remainder == 0)
    return AES_BLOCKLEN;
  return AES_BLOCKLEN - remainder;
}

size_t pkcs7_padding(uint8_t *to, uint8_t *from, size_t len)
{
  size_t padding = calculate_padding(len);
  memcpy(to, from, len);
  memset(to + len, padding_blocks[len % AES_BLOCKLEN], padding);

  return padding;
}

int remove_pkcs7_padding(uint8_t *buf, size_t len)
{
  if (!buf)
    return len;
  int i = 0;
  for (int j = 0; j < len; j++)
  {
    if (isprint(buf[j]))
      i++;
  }
  if (i)
    buf[i] = '\0';

  return i;
}

void encriptar(uint8_t *m, uint8_t *k, uint8_t *iv, size_t len)
{
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, k, iv);
  AES_CBC_encrypt_buffer(&ctx, m, len);
}

void desencriptar(uint8_t *buf, uint8_t *k, uint8_t *iv, size_t len)
{
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, k, iv);
  AES_CBC_decrypt_buffer(&ctx, buf, len);
}

int encriptar_texto(char *textoPlano, char *clave)
{

  printf("Encriptando: \"%s\" usando como clave: \"%s\"\n", textoPlano, clave);

  size_t textlen = strlen(textoPlano);
  size_t keylen = strlen(clave);

  if (!textlen || !keylen)
    return 0;

  textlen = textlen > (BUFSIZE - 16) ? (BUFSIZE - 16) : textlen;
  keylen = keylen > 32 ? 32 : keylen;

  uint8_t m[BUFSIZE];
  uint8_t k[32];
  uint8_t iv[16];

  generate_iv(iv);

  textlen += pkcs7_padding(m, (uint8_t *)textoPlano, textlen);
  keylen += pkcs7_padding(k, (uint8_t *)clave, keylen);

  DUMP("M", m, textlen);

  encriptar(m, k, iv, textlen);

  memcpy(m + textlen, iv, 16);
  size_t size = base64_encode(m, NULL, textlen + 16, 0);
  uint8_t out[size];
  size_t sz = base64_encode(m, out, textlen + 16, 0);

  DUMP("IV", iv, 16);
  DUMP("K", k, keylen);
  DUMP("M", m, textlen + 16);

  char r[sz + 1];
  memset(r, '\0', sz + 1);
  strncpy(r, (char *)out, sz);

  printf("Resultado: %s\n", r);

  return 0;
}

int desencriptar_texto(char *textoCifrado, char *clave)
{
  size_t textlen = strlen(textoCifrado);
  size_t keylen = strlen(clave);

  if (!textlen || !keylen)
    return 0;

  uint8_t *ptr = (uint8_t *)textoCifrado;

  size_t fsize = base64_decode(ptr, NULL, textlen);
  size_t msg_sz = fsize - 16;
  uint8_t f[fsize];
  uint8_t msg[msg_sz];
  uint8_t k[32];
  uint8_t iv[16];

  base64_decode(ptr, f, textlen);

  DUMP("F", f, fsize);
  memcpy(msg, f, msg_sz);
  memcpy(iv, f + msg_sz, 16);

  keylen += pkcs7_padding(k, (uint8_t *)clave, keylen);

  DUMP("M", msg, msg_sz);
  DUMP("IV EXTRACTED", iv, 16);
  DUMP("K", k, keylen);
  desencriptar(msg, k, iv, msg_sz);

  DUMP("MSG", msg, msg_sz);

  remove_pkcs7_padding(msg, msg_sz);

  size_t bufsize = strlen((char*)msg);
  char r[bufsize + 1];

  memset(r, '\0', bufsize + 1);
  strncpy(r, (char *)msg, bufsize);

  

  printf("Resultado: %s %lu\n", r, bufsize);

  return 0;
}

int main(int argc, char const *argv[])
{
  if (argc < 4)
    return 0;

  char *comando = (char *)argv[1];
  char *text = (char *)argv[2];
  char *key = (char *)argv[3];

  if (strcmp(comando, "--encriptar") == 0)
    return encriptar_texto(text, key);
  if (strcmp(comando, "--desencriptar") == 0)
    return desencriptar_texto(text, key);

  // size_t textlen = strlen(text);
  // size_t keylen = strlen(key);

  // if (!textlen || !keylen)
  //   return 0;

  // textlen = textlen > 496 ? 496 : textlen;
  // keylen = keylen > 32 ? 32 : keylen;

  // uint8_t m[528];
  // uint8_t k[32];
  // uint8_t iv[16];

  // generate_iv(iv);

  // int pad_t = pkcs7_padding(m, (uint8_t *)text, textlen);
  // int pad_k = pkcs7_padding(k, (uint8_t *)key, keylen);

  // textlen += pad_t;
  // keylen += pad_k;

  // DUMP("IV", iv, 16);
  // DUMP("A", m, textlen);
  // encriptar(m, k, iv, textlen);

  // // desencriptar
  // DUMP("B", m, textlen);
  // memcpy(m + textlen, iv, 16);
  // textlen += 16;
  // DUMP("C", m, textlen);

  // size_t size = base64_encode(m, NULL, textlen, 0);
  // printf("SIZE: %lu\n", size);
  // uint8_t out[size];
  // base64_encode(m, out, textlen, 0);
  // // out[size] = '\0';
  // // printf("OUT: %s\n", (char *)out);
  // size = strlen((char *)out);
  // size_t fsize = base64_decode(out, NULL, size);
  // uint8_t f[fsize];
  // base64_decode(out, f, size);
  // DUMP("F", f, fsize);

  // uint8_t msg[fsize - 16];
  // uint8_t iv_extracted[16];
  // memcpy(msg, f, fsize - 16);
  // memcpy(iv_extracted, f + (fsize - 16), 16);

  // DUMP("IV EXTRACTED", iv_extracted, 16);
  // DUMP("MSG", msg, fsize - 16);

  // desencriptar(msg, k, iv_extracted, fsize - 16);

  // msg[fsize - 16] = '\0';
  // int i = 0;

  // while ((char)msg[i] != '\0')
  // {
  //   i++;
  // }
  // printf("hasnull in %d - %02x\n", i, msg[i]);

  // int sz = remove_pkcs7_padding(msg, fsize - 16);

  // printf("MSG DECRYPTED: %s LEN: %lu SZ: %d PREV SZ: %lu\n", (char *)msg, strlen((char *)msg), sz, fsize - 16);

  return 0;
}