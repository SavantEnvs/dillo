/*
 * URL parsing and resolution (src/url.c): every link, redirect Location and form action goes
 * through a_Url_new(url, base). Input: "<url>\n<base url>" (no newline = no base).
 * In dillo the base string is always URL_STR() of an existing DilloUrl (the page or <base href>),
 * itself made by a_Url_new(), which gives it a scheme; the harness builds the base the same way.
 */
#include <string.h>
#include "dlib/dlib.h"
#include "src/prefs.h"
#include "src/url.h"
#include "src/hsts.h"

void fuzz_stubs_reset(void);

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
   char *in = dStrndup((const char *)data, size);
   char *base = strchr(in, '\n');
   DilloUrl *u, *b, *d;

   if (base)
      *base++ = '\0';

   prefs.http_strict_transport_security = TRUE;
   a_Hsts_init(NULL);

   b = base ? a_Url_new(base, NULL) : NULL;
   u = a_Url_new(in, b ? URL_STR(b) : NULL);
   if (u) {
      char *s;
      const char *host = a_Url_hostname(u);
      if (host)
         (void)a_Url_host_type(host);
      s = a_Url_str(u);
      if (s) {
         char *enc = a_Url_encode_hex_str(s);
         dFree(enc);
      }
      d = a_Url_dup(u);
      if (b) {
         (void)a_Url_cmp(u, b);
         (void)a_Url_same_organization(u, b);
      }
      (void)a_Url_cmp(u, d);
      a_Url_free(d);
      a_Url_free(u);
   }
   if (b)
      a_Url_free(b);
   {
      char *dec = a_Url_decode_hex_str(in);
      char *strip = a_Url_string_strip_delimiters(in);
      dFree(dec);
      dFree(strip);
   }

   a_Hsts_freeall();
   dFree(in);
   return 0;
}
