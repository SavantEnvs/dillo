/*
 * Known-answer checks for the dillo code the fuzz targets reach (URL resolution, HSTS, HTTP body
 * decoding, Content-Type parsing), built with dillo's normal flags. Prints one "ok <name>" or
 * "not ok <name>: got ..." line per check; mayhem/test.sh counts them.
 */
#include <stdio.h>
#include <string.h>
#include "dlib/dlib.h"
#include "src/prefs.h"
#include "src/url.h"
#include "src/hsts.h"
#include "src/misc.h"
#include "src/decode.h"

DilloPrefs prefs;
int a_Tls_certificate_is_clean(const DilloUrl *url) { (void)url; return 1; }

static void check(const char *name, const char *got, const char *want)
{
   if (got && strcmp(got, want) == 0)
      printf("ok %s\n", name);
   else
      printf("not ok %s: got '%s' want '%s'\n", name, got ? got : "(null)", want);
}

static void url_case(const char *name, const char *u, const char *base, const char *want)
{
   DilloUrl *url = a_Url_new(u, base);
   check(name, url ? URL_STR(url) : NULL, want);
   if (url)
      a_Url_free(url);
}

int main(void)
{
   prefs.http_strict_transport_security = TRUE;
   a_Hsts_init(NULL);

   url_case("url_relative", "../img/a.png", "http://example.com/dir/sub/page.html",
            "http://example.com/dir/img/a.png");
   url_case("url_dotsegments", "../c/d", "http://example.com/a/b/x", "http://example.com/a/c/d");
   url_case("url_query", "?q=1", "http://example.com/p/x.html", "http://example.com/p/x.html?q=1");
   url_case("url_netpath", "//cdn.example.net/x", "https://example.com/", "https://cdn.example.net/x");
   {
      char *d = a_Url_decode_hex_str("a%20b%41");
      check("url_decode_hex", d, "a bA");
      dFree(d);
   }
   {
      DilloUrl *u = a_Url_new("https://secure.example.org/", NULL);
      a_Hsts_set("max-age=31536000; includeSubDomains", u);
      a_Url_free(u);
      check("hsts_subdomain", a_Hsts_require_https("a.secure.example.org") ? "yes" : "no", "yes");
      check("hsts_other", a_Hsts_require_https("example.org") ? "yes" : "no", "no");
      url_case("hsts_upgrade", "http://www.secure.example.org/x", NULL, "https://www.secure.example.org/x");
   }
   {
      char *maj = NULL, *min = NULL, *cs = NULL;
      a_Misc_parse_content_type("Text/HTML; charset=\"ISO-8859-1\"", &maj, &min, &cs);
      check("ctype_major", maj, "Text");
      check("ctype_minor", min, "HTML");
      check("ctype_charset", cs, "ISO-8859-1");
      dFree(maj); dFree(min); dFree(cs);
   }
   {
      const char *t = NULL;
      a_Misc_get_content_type_from_data("GIF89a\x01\x00", 8, &t);
      check("sniff_gif", t, "image/gif");
      a_Misc_get_content_type_from_data("<!DOCTYPE html><p>", 18, &t);
      check("sniff_html", t, "text/html");
   }
   {
      DecodeTransfer *dc = a_Decode_transfer_init("chunked");
      Dstr *a = a_Decode_transfer_process(dc, "5\r\nhel", 6);
      Dstr *b = a_Decode_transfer_process(dc, "lo\r\n6;x=y\r\n world\r\n0\r\n\r\n", 26);
      Dstr *all = dStr_new(a->str);
      dStr_append(all, b->str);
      check("chunked_body", all->str, "hello world");
      check("chunked_finished", a_Decode_transfer_finished(dc) ? "yes" : "no", "yes");
      dStr_free(a, 1); dStr_free(b, 1); dStr_free(all, 1);
      a_Decode_transfer_free(dc);
   }
   {
      Decode *dc = a_Decode_charset_init("ISO-8859-1");
      Dstr *o = a_Decode_process(dc, "caf\xe9", 4);
      check("charset_latin1", o ? o->str : NULL, "caf\xc3\xa9");
      if (o) dStr_free(o, 1);
      a_Decode_free(dc);
   }
   a_Hsts_freeall();
   return 0;
}
