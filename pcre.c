#include "pcre.h"

Regex *rx_match(const char *pattern, const char *to_match)
{
  if (!pattern || !to_match)
    return NULL;

  PCRE2_SIZE err_offset;
  PCRE2_SPTR s = (PCRE2_SPTR)to_match;
  int err;

  pcre2_code *re = pcre2_compile(
      (PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
      PCRE_COMPILE_OPTS, &err, &err_offset,
      NULL);

  Regex *regex = (Regex *)malloc(sizeof(Regex));
  if (!regex)
    return NULL;

  if (re == NULL)
  {
    regex->err = err;
    regex->offset = err_offset;
    regex->count = 0;

    pcre2_get_error_message(err, (PCRE2_UCHAR *)regex->errmsg, sizeof(regex->errmsg));

    return regex;
  }

  pcre2_match_data *data = pcre2_match_data_create_from_pattern(re, NULL);
  int rc = pcre2_match(re, s, (PCRE2_SIZE)strlen((char *)s), 0, PCRE_MATCH_OPTS, data, NULL);

  if (rc < 0)
  {
    switch (rc)
    {
    case PCRE2_ERROR_NOMATCH:
      snprintf((char *)regex->errmsg, 9, "%s", "No match");
      regex->errmsg[9] = '\0';
      break;
    default:
      snprintf((char *)regex->errmsg, 20, "Matching error %d", rc);
      regex->errmsg[20] = '\0';
      break;
    }

    regex->err = rc;
    regex->offset = -1;
    regex->count = 0;

    pcre2_match_data_free(data);
    pcre2_code_free(re);

    return regex;
  }

  PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(data);
  regex->err = 0;
  regex->offset = (int)ovector[0];

  int j = 0;
  char *matches[rc + 1];
  for (int i = 0; i < rc; i++)
  {
    int ms = (ovector[2 * i + 1] - ovector[2 * i]);
    if (ms)
    {
      char *m = (char *)malloc(ms + 1);
      if (!m)
      {
        free(regex);
        break; /** error */
      }
      snprintf(m, ms + 1, "%.*s", (int)ms, (char *)s + ovector[2 * i]);
      matches[j++] = m;
    }
  }

  if (!regex)
  {
    pcre2_match_data_free(data);
    pcre2_code_free(re);
    return NULL;
  }

  regex->count = j;
  matches[j] = 0;
  regex->matches = matches;

  pcre2_match_data_free(data);
  pcre2_code_free(re);

  return regex;
}