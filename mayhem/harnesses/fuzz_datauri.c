/*
 * data: URIs (dpi/datauri.c). When a page links or embeds a data: URL the browser sends the
 * datauri dpi a dpip "open_url" command carrying it; the dpi parses the command, decodes the
 * media type and the base64 or %-escaped payload, and sends the page back. The harness builds
 * that command from the input with the browser's own encoder (a_Dpip_build_cmd) and runs the
 * dpi's main() body after authentication; the reply goes to /dev/null.
 * The dpi's main() reads from its socket, so it is renamed away.
 */
#include <fcntl.h>
#define main datauri_dpi_main
#include "dpi/datauri.c"
#undef main

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
   (void)argc; (void)argv;
   sh = a_Dpip_dsh_new(-1, open("/dev/null", O_WRONLY), 8 * 1024);
   return 0;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
   char *in = dStrndup((const char *)data, size);
   char *dpip_tag = a_Dpip_build_cmd("cmd=%s url=%s", "open_url", in);
   char *cmd = a_Dpip_get_attr(dpip_tag, "cmd");
   char *url = a_Dpip_get_attr(dpip_tag, "url");

   if (cmd && url) {
      size_t data_size = 0;
      char *mime_type = datauri_get_mime(url);
      unsigned char *body = datauri_get_data(url, &data_size);

      if (mime_type && body)
         send_decoded_data(url, mime_type, body, data_size);
      else
         send_failure_message(url, mime_type, body, data_size);
      dFree(body);
      dFree(mime_type);
   }
   dFree(url);
   dFree(cmd);
   dFree(dpip_tag);
   dFree(in);
   return 0;
}
