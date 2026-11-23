/*
 * HTTP authentication (src/auth.c, src/digest.c): on a 401 the cache hands every
 * WWW-Authenticate header value to a_Auth_do_auth(), which parses Basic and Digest challenges
 * (realm, nonce, opaque, qop, algorithm, domain, stale), asks the user for credentials and stores
 * the realm; each following request gets its Authorization header from a_Auth_get_auth_str()
 * (Digest response computation with md5).
 *
 * Input: "<request path>\n<WWW-Authenticate value>\n<WWW-Authenticate value>...", for
 * http://example.com<request path>. An empty line ends one 401 response and starts the next:
 * each group of values is one response, handed to a_Auth_do_auth() in turn (as the cache does
 * for successive 401s to the same URL), so realms stored by one response are seen by the next.
 *
 * The credentials dialog (FLTK) is stood in for by a_Dialog_user_password below, which behaves
 * as the real one (src/dialog.cc) does when the user presses OK: it calls cb with a fixed user
 * name and password and returns 1. auth.c is included so the harness can empty its realm store
 * (auth_hosts) after each input: no realm carries over to the next input.
 */
#include "src/auth.c"

int a_Dialog_user_password(const char *title, const char *msg, UserPasswordCB cb, void *vp)
{
   /* Writable, like the dialog's own input buffers: auth.c shreds the password after use. */
   char user[] = "fuzzuser", pass[] = "fuzzpass";
   (void)title; (void)msg;
   cb(user, pass, vp);
   return 1;   /* OK pressed */
}

static void fuzz_auth_reset(void)
{
   AuthHost_t *host;
   while ((host = dList_nth_data(auth_hosts, 0))) {
      AuthRealm_t *realm;
      while ((realm = dList_nth_data(host->realms, 0))) {
         dList_remove(host->realms, realm);
         Auth_realm_delete(realm);
      }
      dList_free(host->realms);
      dFree(host->scheme);
      dFree(host->authority);
      dList_remove(auth_hosts, host);
      dFree(host);
   }
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
   static int inited;
   char *in = dStrndup((const char *)data, size), *p = in, *nl;
   Dlist *challenges = dList_new(4);
   Dstr *ustr = dStr_new("http://example.com");
   DilloUrl *url;

   if (!inited) {
      a_Auth_init();
      inited = 1;
   }

   nl = strchr(p, '\n');
   if (nl)
      *nl = '\0';
   dStr_append(ustr, p);

   url = a_Url_new(ustr->str, NULL);
   while (nl) {
      p = nl + 1;
      nl = strchr(p, '\n');
      if (nl)
         *nl = '\0';
      if (*p)
         dList_append(challenges, p);
      if ((!*p || !nl) && dList_length(challenges) > 0) {
         /* end of one 401 response */
         if (url && a_Auth_do_auth(challenges, url)) {
            const char *req = URL_PATH(url);
            char *a = a_Auth_get_auth_str(url, req);
            char *b = a_Auth_get_auth_str(url, req);   /* second request: Digest nc=2 */
            dFree(a);
            dFree(b);
         }
         while (dList_length(challenges) > 0)
            dList_remove_fast(challenges, dList_nth_data(challenges, 0));
      }
   }
   if (url)
      a_Url_free(url);
   fuzz_auth_reset();
   dList_free(challenges);
   dStr_free(ustr, 1);
   dFree(in);
   return 0;
}
