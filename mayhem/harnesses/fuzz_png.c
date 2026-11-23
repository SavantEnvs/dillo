/*
 * PNG images as dillo decodes them: src/png.c, dillo's incremental glue over libpng (row/scanline
 * setup, the line buffer it writes each decoded row into, colour-type conversion), driven the way
 * the image cache drives it (see image_feed.h).
 */
#include "image_feed.h"
#include "src/dpng.h"

/* dpng.h declares the callback with a CacheClient_t * (the others take void *). */
static void png_cb(int op, void *data)
{
   a_Png_callback(op, data);
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
   return fuzz_image_feed(data, size, "http://example.com/image.png", a_Png_new, png_cb);
}
