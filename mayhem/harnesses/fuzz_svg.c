/*
 * SVG images as dillo decodes them: the image cache hands the whole document to the SVG decoder
 * (a_Svg_new + a_Svg_callback CA_Send/CA_Close, src/svg.c), which parses it with the vendored
 * nanosvg and rasterizes it. Cache buffers are Dstr-backed and therefore NUL-terminated.
 */
#include <string.h>
#include "dlib/dlib.h"
#include "src/image.hh"
#include "src/cache.h"
#include "src/url.h"
#include "src/dsvg.h"

void fuzz_stubs_reset(void);

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
   DilloImage image;
   CacheClient_t client;
   DilloUrl *url = a_Url_new("http://example.com/image.svg", NULL);
   char *buf = dStrndup((const char *)data, size);   /* NUL-terminated copy, like the cache */

   memset(&image, 0, sizeof(image));
   image.dpi = 96.0;
   image.bg_color = 0xffffff;
   image.fg_color = 0x000000;

   memset(&client, 0, sizeof(client));
   client.Buf = buf;
   client.BufSize = size;
   client.CbData = a_Svg_new(&image, url, 1);
   a_Svg_callback(CA_Send, &client);
   a_Svg_callback(CA_Close, &client);   /* frees the decoder */

   dFree(buf);
   a_Url_free(url);
   fuzz_stubs_reset();
   return 0;
}
