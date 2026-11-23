/*
 * WEBP images as dillo decodes them: src/webp.c, dillo's incremental glue over libwebp (row/scanline
 * setup, the line buffer it writes each decoded row into, colour-type conversion), driven the way
 * the image cache drives it (see image_feed.h).
 */
#include "image_feed.h"
#include "src/dwebp.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
   return fuzz_image_feed(data, size, "http://example.com/image.webp", a_Webp_new, a_Webp_callback);
}
