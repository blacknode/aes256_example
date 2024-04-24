#include "buf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

void generate_iv(uint8_t *iv)
{
  srand(time(NULL));
  for (int i = 0; i < 16; i++)
    iv[i] = (uint8_t)convert2y[rand() % 63];
}

size_t to_buf(unsigned char *buf, unsigned char *str)
{
  int i, j, len;
  uint32_t limb;
  size_t buf_len;

  len = strlen((char *)str);
  buf_len = (len * (6 + 7)) / 8;

  for (i = 0, j = 0, limb = 0; i + 3 < len; i += 4)
  {
    if (str[i] == '=' || str[i + 1] == '=' || str[i + 2] == '=' || str[i + 3] == '=')
    {
      if (str[i] == '=' || str[i + 1] == '=')
      {
        break;
      }

      if (str[i + 2] == '=')
      {
        limb =
            ((uint32_t)convert2n[str[i]] << 6) |
            ((uint32_t)convert2n[str[i + 1]]);
        buf[j] = (unsigned char)(limb >> 4) & 0xff;
        j++;
      }
      else
      {
        limb =
            ((uint32_t)convert2n[str[i]] << 12) |
            ((uint32_t)convert2n[str[i + 1]] << 6) |
            ((uint32_t)convert2n[str[i + 2]]);
        buf[j] = (unsigned char)(limb >> 10) & 0xff;
        buf[j + 1] = (unsigned char)(limb >> 2) & 0xff;
        j += 2;
      }
    }
    else
    {
      limb =
          ((uint32_t)convert2n[str[i]] << 18) |
          ((uint32_t)convert2n[str[i + 1]] << 12) |
          ((uint32_t)convert2n[str[i + 2]] << 6) |
          ((uint32_t)convert2n[str[i + 3]]);

      buf[j] = (unsigned char)(limb >> 16) & 0xff;
      buf[j + 1] = (unsigned char)(limb >> 8) & 0xff;
      buf[j + 2] = (unsigned char)(limb) & 0xff;
      j += 3;
    }
  }

  buf_len = j;

  printf("buflen: %lu j: %d\n", buf_len, j);

  return buf_len;
}