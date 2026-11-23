/*
 * Stand-ins for the parts of the browser the fuzzed parsers call back into but that need the full
 * FLTK UI (image cache, widget image buffers, TLS state). They keep exactly the state the real
 * dicache keeps per image (size, pixel type, colour map) and READ every row a decoder hands over,
 * the way the real a_Imgbuf_update() does, so an out-of-bounds row/colour-map read is still caught.
 * Everything is reset per input by fuzz_stubs_reset().
 */
#include <string.h>
#include "dlib/dlib.h"
#include "src/prefs.h"
#include "src/url.h"
#include "src/image.hh"
#include "src/cache.h"
#include "src/dicache.h"

DilloPrefs prefs;   /* the real one lives in prefs.c with the dillorc parser; zero = defaults off */

static struct {
   int set;
   uint_t width, height;
   DilloImgType type;
   uchar_t *cmap;
} img;
static volatile unsigned fuzz_sink;

void fuzz_stubs_reset(void)
{
   dFree(img.cmap);
   memset(&img, 0, sizeof(img));
}

void a_Dicache_set_parms(DilloUrl *url, int version, DilloImage *Image,
                         uint_t width, uint_t height, DilloImgType type,
                         double gamma)
{
   (void)url; (void)version; (void)gamma;
   if (Image == NULL || !width || !height || img.set)
      return;
   img.set = 1;
   img.width = width;
   img.height = height;
   img.type = type;
}

void a_Dicache_set_cmap(DilloUrl *url, int version, int bg_color,
                        const uchar_t *cmap, uint_t num_colors,
                        int num_colors_max, int bg_index)
{
   (void)url; (void)version;
   dFree(img.cmap);
   img.cmap = dNew0(uchar_t, 3 * num_colors_max);
   memcpy(img.cmap, cmap, 3 * num_colors);
   if (bg_index >= 0 && (uint_t)bg_index < num_colors) {
      img.cmap[bg_index * 3]     = (bg_color >> 16) & 0xff;
      img.cmap[bg_index * 3 + 1] = (bg_color >> 8) & 0xff;
      img.cmap[bg_index * 3 + 2] = (bg_color) & 0xff;
   }
}

void a_Dicache_new_scan(const DilloUrl *url, int version)
{
   (void)url; (void)version;
}

void a_Dicache_write(DilloUrl *url, int version, const uchar_t *buf, uint_t Y)
{
   unsigned s = 0;
   (void)url; (void)version;
   if (!img.set || Y >= img.height)
      return;
   for (uint_t x = 0; x < img.width; x++) {
      switch (img.type) {
      case DILLO_IMG_TYPE_INDEXED:
         s += buf[x];
         if (img.cmap)
            s += img.cmap[buf[x] * 3] + img.cmap[buf[x] * 3 + 2];
         break;
      case DILLO_IMG_TYPE_RGB:
         s += buf[3 * x] + buf[3 * x + 2];
         break;
      case DILLO_IMG_TYPE_CMYK_INV:
         s += buf[4 * x] + buf[4 * x + 3];
         break;
      default:
         s += buf[x];
      }
   }
   fuzz_sink += s;
}

void a_Dicache_close(DilloUrl *url, int version, CacheClient_t *Client)
{
   (void)url; (void)version; (void)Client;
}

/* dillo is configured --disable-tls; HSTS only accepts a header over a certificate-clean
 * connection, which is what a real https response would be. */
int a_Tls_certificate_is_clean(const DilloUrl *url)
{
   (void)url;
   return 1;
}

/* What the cache reports for an image URL (jpeg.c asks whether the entry is complete before it
 * picks progressive display); set by image_feed.h per chunk. */
int fuzz_capi_flags;
int a_Capi_get_flags(const DilloUrl *Url)
{
   (void)Url;
   return fuzz_capi_flags;
}
