/*
 * HTTP body decoding as the cache applies it to a response (src/decode.c): Transfer-Encoding
 * (chunked), then Content-Encoding (gzip / x-gzip / deflate / br), then charset conversion to
 * UTF-8 (iconv). Input: "<transfer-encoding>\n<content-encoding>\n<charset>\n<body>"; an empty
 * line means the header is absent. The body arrives in two network reads (split at the middle).
 */
#include <string.h>
#include "dlib/dlib.h"
#include "src/decode.h"

static const char *next_line(const char **p, const char *end, char *out, size_t outsz)
{
   const char *nl = memchr(*p, '\n', end - *p);
   size_t n;
   if (!nl)
      return NULL;
   n = nl - *p;
   if (n >= outsz)
      n = outsz - 1;
   memcpy(out, *p, n);
   out[n] = '\0';
   *p = nl + 1;
   return out;
}

static Dstr *run_stage(Decode *dc, Dstr *in)
{
   Dstr *out;
   if (!dc)
      return in;
   out = a_Decode_process(dc, in->str, in->len);
   dStr_free(in, 1);
   return out ? out : dStr_new("");
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
   const char *p = (const char *)data, *end = p + size;
   char te[64] = "", ce[64] = "", cs[64] = "";
   DecodeTransfer *tdc;
   Decode *cdc, *sdc;
   size_t half;

   if (!next_line(&p, end, te, sizeof te) || !next_line(&p, end, ce, sizeof ce) ||
       !next_line(&p, end, cs, sizeof cs)) {
      /* No header block: the whole input is a chunked body. */
      p = (const char *)data;
      strcpy(te, "chunked");
      ce[0] = cs[0] = '\0';
   }

   tdc = a_Decode_transfer_init(te[0] ? te : NULL);
   cdc = ce[0] ? a_Decode_content_init(ce) : NULL;
   sdc = cs[0] ? a_Decode_charset_init(cs) : NULL;

   half = (end - p) / 2;
   for (int i = 0; i < 2; i++) {
      const char *chunk = i == 0 ? p : p + half;
      int len = i == 0 ? (int)half : (int)(end - p - half);
      Dstr *d;
      if (tdc) {
         d = a_Decode_transfer_process(tdc, chunk, len);
         if (!d)
            d = dStr_new("");
      } else {
         d = dStr_sized_new(len + 1);
         dStr_append_l(d, chunk, len);
      }
      d = run_stage(cdc, d);
      d = run_stage(sdc, d);
      dStr_free(d, 1);
   }
   if (tdc) {
      (void)a_Decode_transfer_finished(tdc);
      a_Decode_transfer_free(tdc);
   }
   if (cdc)
      a_Decode_free(cdc);
   if (sdc)
      a_Decode_free(sdc);
   return 0;
}
