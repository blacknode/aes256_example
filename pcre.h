#ifndef PCRE2_H
#define PCRE2_H

#define PCRE2_CODE_UNIT_WIDTH 8
#include <stdio.h>
#include <string.h>
#include <pcre2.h>

#define RX_EMAIL "^([A-Za-z0-9\\-_\\.]{5,64})@{1}((((g|hot)mail)|outlook|yahoo|icloud)\\.(com|es)|(proton(mail)?\\.(me|com)))$"
#define PCRE_MATCH_OPTS PCRE2_ANCHORED | PCRE2_ENDANCHORED
#define PCRE_COMPILE_OPTS PCRE2_MULTILINE | PCRE2_UTF | PCRE2_CASELESS

typedef struct Regex
{
  int count;
  int offset;
  int err;
  char **matches;
  char errmsg[256];
} Regex;

extern Regex *rx_match(const char *rx, const char *subject);

#endif /* PCRE2_H */