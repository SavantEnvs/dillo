/*
 * Shared driver for dillo's raster image decoders (src/png.c, src/jpeg.c, src/webp.c, like
 * fuzz_gif.c for src/gif.c). The image cache calls a decoder each time more data arrives, with
 * Buf = everything received so far, so the input is delivered the same way: at 1/3, 2/3 and the
 * full length, then CA_Close (which frees the decoder). The a_Dicache_* stand-ins in stubs.c read
 * every row a decoder hands over, as the real a_Imgbuf_update() does. fuzz_capi_flags is what
 * a_Capi_get_flags() reports for the image URL: not CAPI_Completed while data is still arriving.
 */
#include <string.h>
#include "dlib/dlib.h"
#include "src/image.hh"
#include "src/cache.h"
#include "src/url.h"
#include "src/capi.h"

void fuzz_stubs_reset(void);
extern int fuzz_capi_flags;

typedef void *(*fuzz_img_new_t)(DilloImage *, DilloUrl *, int);
typedef void (*fuzz_img_cb_t)(int, void *);

static int fuzz_image_feed(const unsigned char *data, size_t size, const char *urlstr,
                           fuzz_img_new_t img_new, fuzz_img_cb_t img_cb)
{
   DilloImage image;
   CacheClient_t client;
   DilloUrl *url = a_Url_new(urlstr, NULL);
   char *buf = dStrndup((const char *)data, size);
   size_t steps[3] = { size / 3, 2 * size / 3, size };

   memset(&image, 0, sizeof(image));
   image.dpi = 96.0;
   image.bg_color = 0xffffff;

   memset(&client, 0, sizeof(client));
   client.Buf = buf;
   client.CbData = img_new(&image, url, 1);
   fuzz_capi_flags = 0;
   for (int i = 0; i < 3; i++) {
      if (steps[i] == 0 || (i > 0 && steps[i] == steps[i - 1]))
         continue;
      if (i == 2)
         fuzz_capi_flags = CAPI_Completed;   /* last chunk: the cache entry is complete */
      client.BufSize = steps[i];
      img_cb(CA_Send, &client);
   }
   img_cb(CA_Close, &client);

   dFree(buf);
   a_Url_free(url);
   fuzz_stubs_reset();
   fuzz_capi_flags = 0;
   return 0;
}
