/*
 * HTTP responses as the cache receives them (src/cache.c): a_Cache_process_dbuf() is what the IO
 * layer calls with every block read from a server connection. It collects the header
 * (Cache_get_header: \r stripping, line unfolding), parses it (Cache_parse_header ->
 * Cache_parse_field / Cache_parse_multiple_fields for Location, WWW-Authenticate, Warning,
 * Connection, Strict-Transport-Security, Transfer-Encoding, Content-Length, Content-Encoding,
 * Content-Type, Content-Disposition), resolves a redirect against the request URL, then runs the
 * body through the transfer (chunked) and content (gzip/deflate/brotli) decoders and the content
 * type sniffer.
 *
 * Input: the raw response bytes from https://example.com/dir/page, delivered as two reads (first
 * half, rest) and then the connection close, as the IO layer does. No client is waiting on the
 * entry, so no page is rendered. cache.c is included so the harness can create and remove the
 * entry itself; the entry, its decoders and the HSTS store are freed after each input.
 */
#include "src/cache.c"

/*
 * Browser-UI and client side of the cache (windows, navigation, dicache, timers, cookies dpi).
 * They are only reached for a client waiting on the entry, and this harness enqueues none; the
 * stand-ins do nothing. AboutSplash (src/IO/about.c) is only used by a_Cache_init().
 */
const char *AboutSplash = "";
int a_Auth_do_auth(Dlist *auth_string, const DilloUrl *url) { (void)auth_string; (void)url; return 0; }
void a_Bw_close_client(BrowserWindow *bw, int key) { (void)bw; (void)key; }
int a_Bw_remove_client(BrowserWindow *bw, int key) { (void)bw; (void)key; return 0; }
void a_Capi_conn_abort_by_url(const DilloUrl *url) { (void)url; }
void a_Cookies_set(Dlist *cookies, const DilloUrl *url, const char *date) { (void)cookies; (void)url; (void)date; }
void a_Dicache_cleanup(void) {}
DICacheEntry *a_Dicache_get_entry(const DilloUrl *url, int version) { (void)url; (void)version; return NULL; }
void a_Dicache_invalidate_entry(const DilloUrl *url) { (void)url; }
Dstr *a_Dicache_stats(void) { return dStr_new(""); }
void a_Dicache_unref(const DilloUrl *url, int version) { (void)url; (void)version; }
void a_Nav_cancel_expect_if_eq(BrowserWindow *bw, const DilloUrl *url) { (void)bw; (void)url; }
void a_Nav_push(BrowserWindow *bw, const DilloUrl *url, const DilloUrl *req) { (void)bw; (void)url; (void)req; }
void a_Nav_reload(BrowserWindow *bw) { (void)bw; }
void a_Timeout_add(float t, TimeoutCb_t cb, void *cbdata) { (void)t; (void)cb; (void)cbdata; }
void a_Timeout_remove(void) {}
void a_UIcmd_save_link(BrowserWindow *bw, const DilloUrl *url, char *fn) { (void)bw; (void)url; (void)fn; }
void a_UIcmd_set_msg(BrowserWindow *bw, const char *format, ...) { (void)bw; (void)format; }
void a_UIcmd_set_page_prog(BrowserWindow *bw, size_t nbytes, int cmd) { (void)bw; (void)nbytes; (void)cmd; }
int a_Web_dispatch_by_type(const char *Type, DilloWeb *web, CA_Callback_t *Call, void **Data)
{ (void)Type; (void)web; (void)Call; (void)Data; return -1; }
void a_Web_free(DilloWeb *web) { (void)web; }

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
   static int inited;
   DilloUrl *url;
   CacheEntry_t *entry;
   size_t half = size / 2;

   if (!inited) {
      ClientQueue = dList_new(32);
      DelayedQueue = dList_new(32);
      CachedURLs = dList_new(256);
      inited = 1;
   }
   prefs.http_strict_transport_security = TRUE;
   a_Hsts_init(NULL);

   url = a_Url_new("https://example.com/dir/page", NULL);
   entry = Cache_entry_add(url);
   if (half)
      a_Cache_process_dbuf(IORead, (const char *)data, half, url);
   if (Cache_entry_search(url) && size > half)
      a_Cache_process_dbuf(IORead, (const char *)data + half, size - half, url);
   if ((entry = Cache_entry_search(url))) {
      a_Cache_process_dbuf(IOClose, NULL, 0, url);
      Cache_entry_remove(entry, NULL);
   }
   a_Url_free(url);
   a_Hsts_freeall();
   return 0;
}
