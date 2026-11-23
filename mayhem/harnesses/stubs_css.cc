/*
 * The three html.cc entry points the CSS parser calls. Linking html.cc would pull in the whole
 * browser UI (FLTK windows, forms, tables), which needs a display, so they are stood in for here:
 *  - a_Html_tag_index: element name -> index for type selectors. Selectors are only stored, never
 *    matched (no document), so any stable index works; unknown names give -1 as in html.cc.
 *  - a_Html_url_new: what html.cc does minus its diagnostics: a_Url_new(url, base).
 *  - a_Html_load_stylesheet: @import fetches nothing in the harness.
 */
#include <string.h>
#include "dlib/dlib.h"
#include "src/url.h"

struct DilloHtml;

static const char *const fuzz_tags[] = {
   "html", "head", "body", "p", "a", "div", "span", "h1", "h2", "img", "table", "tr", "td",
   "ul", "ol", "li", "pre", "form", "input", "style", "link", "em", "strong", "code",
};

int a_Html_tag_index(const char *tag)
{
   for (size_t i = 0; i < sizeof(fuzz_tags) / sizeof(fuzz_tags[0]); i++)
      if (dStrAsciiCasecmp(tag, fuzz_tags[i]) == 0)
         return (int)i;
   return -1;
}

DilloUrl *a_Html_url_new(DilloHtml *html, const char *url_str, const char *base_url,
                         int use_base_url)
{
   (void)html;
   if (!url_str || !use_base_url)
      return NULL;
   return a_Url_new(url_str, base_url);
}

void a_Html_load_stylesheet(DilloHtml *html, DilloUrl *url)
{
   (void)html; (void)url;
}
