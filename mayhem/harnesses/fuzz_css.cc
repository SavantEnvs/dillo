/*
 * CSS as dillo reads it: author style sheets (<style> elements and linked .css files) go through
 * CssParser::parse into a CssContext, and style="" attributes through
 * CssParser::parseDeclarationBlock (src/cssparser.cc, src/css.cc). html == NULL as for a sheet
 * that is not attached to a document, which only skips fetching @import targets.
 * The base URL is created once and never modified.
 */
#include <stdint.h>
#include <stddef.h>
#include "dlib/dlib.h"
#include "src/url.h"
#include "src/css.hh"
#include "src/cssparser.hh"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   static DilloUrl *base = a_Url_new("http://example.com/style/main.css", NULL);
   char *buf = dStrndup((const char *)data, size);   /* NUL-terminated, like the cache's Dstr */

   CssContext *ctx = new CssContext();
   CssParser::parse(NULL, base, ctx, buf, (int)size, CSS_ORIGIN_AUTHOR);
   delete ctx;

   CssPropertyList *props = new CssPropertyList(true);
   CssPropertyList *important = new CssPropertyList(true);
   CssParser::parseDeclarationBlock(base, buf, (int)size, props, important);
   delete props;
   delete important;

   dFree(buf);
   return 0;
}
