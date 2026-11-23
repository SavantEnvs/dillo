/*
 * HTTP Strict-Transport-Security (src/hsts.c): the Strict-Transport-Security response header
 * parser (a_Hsts_set) and the policy lookup that a_Url_new consults for every URL.
 * Input: "<host>\n<header value>" (or just a header, host example.com); the header is received over https://<host>/.
 */
#include <string.h>
#include "dlib/dlib.h"
#include "src/prefs.h"
#include "src/url.h"
#include "src/hsts.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
   char *in = dStrndup((const char *)data, size);
   char *hdr = strchr(in, '\n');
   const char *host = "example.com";
   Dstr *ustr;
   DilloUrl *url;

   if (hdr) {          /* "<host>\n<header>" */
      *hdr++ = '\0';
      host = in;
   } else {            /* no host line: the whole input is the header */
      hdr = in;
   }

   prefs.http_strict_transport_security = TRUE;
   a_Hsts_init(NULL);

   ustr = dStr_sized_new(64);
   dStr_sprintf(ustr, "https://%s/", host);
   url = a_Url_new(ustr->str, NULL);
   if (url) {
      const char *h = a_Url_hostname(url);
      a_Hsts_set(hdr, url);
      if (h)
         (void)a_Hsts_require_https(h);
      (void)a_Hsts_require_https("sub.example.com");
      a_Url_free(url);
   }
   dStr_free(ustr, 1);
   a_Hsts_freeall();
   dFree(in);
   return 0;
}
