/*
 * GIF images as dillo decodes them (src/gif.c, dillo's own block parser + LZW decoder). The image
 * cache calls the decoder each time more data arrives, with Buf = everything received so far, so
 * the input is delivered the same way: at 1/3, 2/3 and the full length, then CA_Close.
 */
#include <string.h>
#include "dlib/dlib.h"
#include "src/image.hh"
#include "src/cache.h"
#include "src/url.h"
#include "src/dgif.h"

void fuzz_stubs_reset(void);

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
   DilloImage image;
   CacheClient_t client;
   DilloUrl *url = a_Url_new("http://example.com/image.gif", NULL);
   char *buf = dStrndup((const char *)data, size);
   size_t steps[3] = { size / 3, 2 * size / 3, size };

   memset(&image, 0, sizeof(image));
   image.dpi = 96.0;
   image.bg_color = 0xffffff;

   memset(&client, 0, sizeof(client));
   client.Buf = buf;
   client.CbData = a_Gif_new(&image, url, 1);
   for (int i = 0; i < 3; i++) {
      if (steps[i] == 0 || (i > 0 && steps[i] == steps[i - 1]))
         continue;
      client.BufSize = steps[i];
      a_Gif_callback(CA_Send, &client);
   }
   a_Gif_callback(CA_Close, &client);   /* frees the decoder */

   dFree(buf);
   a_Url_free(url);
   fuzz_stubs_reset();
   return 0;
}
