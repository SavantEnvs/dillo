/*
 * JPEG images as dillo decodes them: src/jpeg.c, dillo's incremental glue over libjpeg (row/scanline
 * setup, the line buffer it writes each decoded row into, colour-type conversion), driven the way
 * the image cache drives it (see image_feed.h).
 */
#include "image_feed.h"
#include "src/djpeg.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
   return fuzz_image_feed(data, size, "http://example.com/image.jpeg", a_Jpeg_new, a_Jpeg_callback);
}
