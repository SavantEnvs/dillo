/*
 * The response-header and content helpers the cache runs on every HTTP response (src/misc.c,
 * src/misc.h): Content-Type parsing, Content-Disposition parsing, MIME sniffing of the body and
 * the declared-vs-detected type check. The whole input is used as the header value and as the
 * body to sniff.
 */
#include <string.h>
#include "dlib/dlib.h"
#include "src/misc.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
   char *str = dStrndup((const char *)data, size);
   char *major = NULL, *minor = NULL, *charset = NULL;
   char *type = NULL, *filename = NULL;
   const char *detected = NULL;

   a_Misc_parse_content_type(str, &major, &minor, &charset);
   dFree(major); dFree(minor); dFree(charset);

   a_Misc_parse_content_disposition(str, &type, &filename);
   dFree(type); dFree(filename);

   (void)a_Misc_get_content_type_from_data(str, size, &detected);
   if (detected) {
      (void)a_Misc_content_type_check(str, detected);
      (void)a_Misc_content_type_cmp(str, detected);
   }

   dFree(str);
   return 0;
}
