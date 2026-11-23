/*
 * The cookies dpi server (dpi/cookies.c) as the browser drives it: for a response carrying
 * Set-Cookie, the browser sends a dpip "set_cookie" command (cookie, request host and path, and
 * the response's Date header), and before each request a "get_cookie" command; the server's
 * srv_parse_tok() dispatches them to Cookies_set()/Cookies_get() (Set-Cookie and date parsing,
 * domain/path validation, the cookie jar).
 *
 * Input: "<host>\n<path>\n<Date header>\n<Set-Cookie value>\n<Set-Cookie value>...": the request
 * URL's host and path, the response's Date header, then one line per Set-Cookie header (each one
 * is its own set_cookie command, as in src/cookies.c a_Cookies_set). Missing host/path/date lines
 * take defaults; no Set-Cookie lines means a request that only asks for cookies.
 *
 * The dpi's main() only adds the socket loop, so it is renamed away; the client is treated as
 * already authenticated (status 1). State: $HOME is a private temp dir made once with a
 * cookiesrc of "DEFAULT ACCEPT"; the jar is loaded, used and freed per input, and cookies.txt is
 * emptied after each input, so no cookie carries over to the next one.
 */
#define main cookies_dpi_main
#include "dpi/cookies.c"
#undef main

static char fuzz_home[512];
static char fuzz_jar[600];
static Dsh *fuzz_sh;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
   const char *tmp = getenv("TMPDIR");
   char path[600];
   FILE *f;
   (void)argc; (void)argv;

   snprintf(fuzz_home, sizeof fuzz_home, "%s/dillo-cookies-XXXXXX", tmp && *tmp ? tmp : "/tmp");
   if (!mkdtemp(fuzz_home))
      abort();
   setenv("HOME", fuzz_home, 1);
   snprintf(path, sizeof path, "%s/.dillo", fuzz_home);
   mkdir(path, 0700);
   snprintf(path, sizeof path, "%s/.dillo/cookiesrc", fuzz_home);
   if (!(f = fopen(path, "w")))
      abort();
   fputs("DEFAULT ACCEPT\n", f);
   fclose(f);
   snprintf(fuzz_jar, sizeof fuzz_jar, "%s/.dillo/cookies.txt", fuzz_home);
   fuzz_sh = a_Dpip_dsh_new(-1, open("/dev/null", O_WRONLY), 8 * 1024);
   return 0;
}

static char *field(char **p, const char *def)
{
   char *s = *p, *nl;
   if (!s)
      return dStrdup(def);
   nl = strchr(s, '\n');
   if (nl) {
      *nl = '\0';
      *p = nl + 1;
   } else {
      *p = NULL;
   }
   return dStrdup(s);
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
   char *in = dStrndup((const char *)data, size), *p = in;
   char *host = field(&p, "www.example.com");
   char *path = field(&p, "/dir/page.html");
   char *date = field(&p, "Mon, 23 Nov 2026 12:00:00 GMT");
   ClientInfo client = { fuzz_sh, 1 };
   char *tag;

   Cookies_init();

   while (p) {
      char *cookie = field(&p, "");
      tag = a_Dpip_build_cmd("cmd=%s cookie=%s host=%s path=%s date=%s",
                             "set_cookie", cookie, host, path, date);
      srv_parse_tok(fuzz_sh, &client, tag);
      dFree(tag);
      dFree(cookie);
   }

   tag = a_Dpip_build_cmd("cmd=%s scheme=%s host=%s path=%s",
                          "get_cookie", "https", host, path);
   srv_parse_tok(fuzz_sh, &client, tag);
   dFree(tag);

   Cookies_save_and_free();
   if (truncate(fuzz_jar, 0) != 0)
      abort();

   dFree(date); dFree(host); dFree(path); dFree(in);
   return 0;
}
