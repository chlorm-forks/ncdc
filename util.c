/* ncdc - NCurses Direct Connect client

  Copyright (c) 2011 Yoran Heling

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/


#include "ncdc.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <glib/gstdio.h>
#include <sys/file.h>


#if INTERFACE

// Get a string from a glib log level
#define loglevel_to_str(level) (\
  (level) & G_LOG_LEVEL_ERROR    ? "ERROR"    :\
  (level) & G_LOG_LEVEL_CRITICAL ? "CRITICAL" :\
  (level) & G_LOG_LEVEL_WARNING  ? "WARNING"  :\
  (level) & G_LOG_LEVEL_MESSAGE  ? "message"  :\
  (level) & G_LOG_LEVEL_INFO     ? "info"     : "debug")

// number of columns of a gunichar
#define gunichar_width(x) (g_unichar_iswide(x) ? 2 : g_unichar_iszerowidth(x) ? 0 : 1)


#endif





// Configuration handling


// global vars
const char *conf_dir;
GKeyFile *conf_file;


#if INTERFACE

#define conf_hub_get(type, name, key) (\
  g_key_file_has_key(conf_file, name, (key), NULL)\
    ? g_key_file_get_##type(conf_file, name, (key), NULL)\
    : g_key_file_get_##type(conf_file, "global", (key), NULL))

#define conf_autorefresh() (\
  !g_key_file_has_key(conf_file, "global", "autorefresh", NULL) ? 60\
    : g_key_file_get_integer(conf_file, "global", "autorefresh", NULL))

#endif


void conf_init() {
  // get location of the configuration directory
  conf_dir = g_getenv("NCDC_DIR");
  if(!conf_dir)
    conf_dir = g_build_filename(g_get_home_dir(), ".ncdc", NULL);

  // try to create it (ignoring errors if it already exists)
  g_mkdir(conf_dir, 0700);
  if(g_access(conf_dir, F_OK | R_OK | X_OK | W_OK) < 0)
    g_error("Directory '%s' does not exist or is not writable.", conf_dir);

  // we should also have a logs/ subdirectory
  char *logs = g_build_filename(conf_dir, "logs", NULL);
  g_mkdir(logs, 0777);
  if(g_access(conf_dir, F_OK | R_OK | X_OK | W_OK) < 0)
    g_error("Directory '%s' does not exist or is not writable.", logs);
  g_free(logs);

  // make sure that there is no other ncdc instance working with the same config directory
  char *lock_file = g_build_filename(conf_dir, "lock", NULL);
  int lock_fd = g_open(lock_file, O_WRONLY|O_CREAT, 0600);
  if(lock_fd < 0 || flock(lock_fd, LOCK_EX|LOCK_NB))
    g_error("Unable to open lock file. Is another instance of ncdc running with the same configuration directory?");
  g_free(lock_file);
  // Don't close the above file. Keep it open and let the OS close it (and free
  // the lock) when ncdc is closed, was killed or has crashed.

  // load config file (or create it)
  conf_file = g_key_file_new();
  char *cf = g_build_filename(conf_dir, "config.ini", NULL);
  GError *err = NULL;
  if(g_file_test(cf, G_FILE_TEST_EXISTS)) {
    if(!g_key_file_load_from_file(conf_file, cf, G_KEY_FILE_KEEP_COMMENTS, &err))
      g_error("Could not load '%s': %s", cf, err->message);
  }
  // always set the initial comment
  g_key_file_set_comment(conf_file, NULL, NULL,
    "This file is automatically managed by ncdc.\n"
    "While you could edit it yourself, doing so is highly discouraged.\n"
    "It is better to use the respective commands to change something.\n"
    "Warning: Editing this file while ncdc is running may result in your changes getting lost!", NULL);
  // make sure a nick is set
  if(!g_key_file_has_key(conf_file, "global", "nick", NULL)) {
    char *nick = g_strdup_printf("ncdc_%d", g_random_int_range(1, 9999));
    g_key_file_set_string(conf_file, "global", "nick", nick);
    g_free(nick);
  }
  conf_save();
  g_free(cf);
}


void conf_save() {
  char *dat = g_key_file_to_data(conf_file, NULL, NULL);
  char *cf = g_build_filename(conf_dir, "config.ini", NULL);
  FILE *f = fopen(cf, "w");
  if(!f || fputs(dat, f) < 0 || fclose(f))
    g_critical("Cannot save config file '%s': %s", cf, g_strerror(errno));
  g_free(dat);
  g_free(cf);
}





/* A best-effort character conversion function.
 *
 * If, for whatever reason, a character could not be converted, a question mark
 * will be inserted instead. Unlike g_convert_with_fallback(), this function
 * does not fail on invalid byte sequences in the input string, either. Those
 * will simply be replaced with question marks as well.
 *
 * The character sets in 'to' and 'from' are assumed to form a valid conversion
 * according to your iconv implementation.
 *
 * Modifying this function to not require glib, but instead use the iconv and
 * memory allocation functions provided by your system, should be trivial.
 *
 * This function does not correctly handle character sets that may use zeroes
 * in the middle of a string (e.g. UTF-16).
 *
 * This function may not represent best practice with respect to character set
 * conversion, nor has it been thoroughly tested.
 */
char *str_convert(const char *to, const char *from, const char *str) {
  GIConv cd = g_iconv_open(to, from);
  if(cd == (GIConv)-1) {
    g_critical("No conversion from '%s' to '%s': %s", from, to, g_strerror(errno));
    return g_strdup("<encoding-error>");
  }
  gsize inlen = strlen(str);
  gsize outlen = inlen+96;
  gsize outsize = inlen+100;
  char *inbuf = (char *)str;
  char *dest = g_malloc(outsize);
  char *outbuf = dest;
  while(inlen > 0) {
    gsize r = g_iconv(cd, &inbuf, &inlen, &outbuf, &outlen);
    if(r != (gsize)-1)
      continue;
    if(errno == E2BIG) {
      gsize used = outsize - outlen - 4;
      outlen += outsize;
      outsize += outsize;
      dest = g_realloc(dest, outsize);
      outbuf = dest + used;
    } else if(errno == EILSEQ || errno == EINVAL) {
      // skip this byte from the input
      inbuf++;
      inlen--;
      // Only output question mark if we happen to have enough space, otherwise
      // it's too much of a hassle...  (In most (all?) cases we do have enough
      // space, otherwise we'd have gotten E2BIG anyway)
      if(outlen >= 1) {
        *outbuf = '?';
        outbuf++;
        outlen--;
      }
    } else
      g_assert_not_reached();
  }
  memset(outbuf, 0, 4);
  g_iconv_close(cd);
  return dest;
}


// Test that conversion is possible from UTF-8 to fmt and backwards.  Not a
// very comprehensive test, but ensures str_convert() can do its job.
// The reason for this test is to make sure the conversion *exists*,
// whether it makes sense or not can't easily be determined. Note that my
// code currently can't handle zeroes in encoded strings, which is why this
// is also tested (though, again, not comprehensive. But at least it does
// not allow UTF-16)
// Returns FALSE if the encoding can't be used, optionally setting err when it
// has something useful to say.
gboolean str_convert_check(const char *fmt, GError **err) {
  GError *l_err = NULL;
  gsize read, written, written2;
  char *enc = g_convert("abc", -1, "UTF-8", fmt, &read, &written, &l_err);
  if(l_err) {
    g_propagate_error(err, l_err);
    return FALSE;
  } else if(!enc || read != 3 || strlen(enc) != written) {
    g_free(enc);
    return FALSE;
  } else {
    char *dec = g_convert(enc, written, fmt, "UTF-8", &read, &written2, &l_err);
    g_free(enc);
    if(l_err) {
      g_propagate_error(err, l_err);
      return FALSE;
    } else if(!dec || read != written || written2 != 3 || strcmp(dec, "abc") != 0) {
      g_free(dec);
      return FALSE;
    } else {
      g_free(dec);
      return TRUE;
    }
  }
}


// Number of columns required to represent the UTF-8 string.
int str_columns(const char *str) {
  int w = 0;
  while(*str) {
    w += gunichar_width(g_utf8_get_char(str));
    str = g_utf8_next_char(str);
  }
  return w;
}


// returns the byte offset to the last character in str (UTF-8) that does not
// fit within col columns.
int str_offset_from_columns(const char *str, int col) {
  const char *ostr = str;
  int w = 0;
  while(*str && w < col) {
    w += gunichar_width(g_utf8_get_char(str));
    str = g_utf8_next_char(str);
  }
  return str-ostr;
}


// Stolen from ncdu (with small modifications)
// Result is stored in an internal buffer.
char *str_formatsize(guint64 size) {
  static char dat[11]; /* "xxx.xx MiB" */
  double r = size;
  char c = ' ';
  if(r < 1000.0f)      { }
  else if(r < 1023e3f) { c = 'k'; r/=1024.0f; }
  else if(r < 1023e6f) { c = 'M'; r/=1048576.0f; }
  else if(r < 1023e9f) { c = 'G'; r/=1073741824.0f; }
  else if(r < 1023e12f){ c = 'T'; r/=1099511627776.0f; }
  else                 { c = 'P'; r/=1125899906842624.0f; }
  sprintf(dat, "%6.2f %c%cB", r, c, c == ' ' ? ' ' : 'i');
  return dat;
}


// Prefixes all strings in the array-of-strings with a string, obtained by
// concatenating all arguments together. Last argument must be NULL.
void strv_prefix(char **arr, const char *str, ...) {
  // create the prefix
  va_list va;
  va_start(va, str);
  char *prefix = g_strdup(str);
  const char *c;
  while((c = va_arg(va, const char *))) {
    char *o = prefix;
    prefix = g_strconcat(prefix, c, NULL);
    g_free(o);
  }
  va_end(va);
  // add the prefix to every string
  char **a;
  for(a=arr; *a; a++) {
    char *o = *a;
    *a = g_strconcat(prefix, *a, NULL);
    g_free(o);
  }
  g_free(prefix);
}



// Split a two-argument string into the two arguments.  The first argument
// should be shell-escaped, the second shouldn't. The string should be
// writable. *first should be free()'d, *second refers to a location in str.
void str_arg2_split(char *str, char **first, char **second) {
  GError *err = NULL;
  while(*str == ' ')
    str++;
  char *sep = str;
  gboolean bs = FALSE;
  *first = *second = NULL;
  do {
    if(err)
      g_error_free(err);
    err = NULL;
    sep = strchr(sep+1, ' ');
    if(sep && *(sep-1) == '\\')
      bs = TRUE;
    else {
      if(sep)
        *sep = 0;
      *first = g_shell_unquote(str, &err);
      if(sep)
        *sep = ' ';
      bs = FALSE;
    }
  } while(sep && (err || bs));
  if(sep && sep != str) {
    *second = sep+1;
    while(**second == ' ')
      (*second)++;
  }
}



// like realpath(), but also expands ~
char *path_expand(const char *path) {
  char *p = path[0] == '~' ? g_build_filename(g_get_home_dir(), path+1, NULL) : g_strdup(path);
  char *r = realpath(p, NULL);
  g_free(p);
  return r;
}



// String pointer comparison, for use with qsort() on string arrays.
int cmpstringp(const void *p1, const void *p2) {
  return strcmp(* (char * const *) p1, * (char * const *) p2);
}

// Expand and auto-complete a filesystem path
void path_suggest(char *opath, char **sug) {
  char *path = g_strdup(opath);
  char *name, *dir = NULL;

  // special-case ~ and .
  if((path[0] == '~' || path[0] == '.') && (path[1] == 0 || (path[1] == '/' && path[2] == 0))) {
    name = path_expand(path);
    sug[0] = g_strconcat(name, "/", NULL);
    g_free(name);
    goto path_suggest_f;
  }

  char *sep = strrchr(path, '/');
  if(sep) {
    *sep = 0;
    name = sep+1;
    dir = path_expand(path[0] ? path : "/");
    if(!dir)
      goto path_suggest_f;
  } else {
    name = path;
    dir = path_expand(".");
  }
  GError *err = NULL;
  GDir *d = g_dir_open(dir, 0, &err);
  if(!d) {
    g_error_free(err);
    goto path_suggest_f;
  }

  const char *n;
  int i = 0, len = strlen(name);
  while(i<20 && (n = g_dir_read_name(d))) {
    if(strcmp(n, ".") == 0 || strcmp(n, "..") == 0)
      continue;
    char *fn = g_build_filename(dir, n, NULL);
    if(strncmp(n, name, len) == 0 && strlen(n) != len)
      sug[i++] = g_file_test(fn, G_FILE_TEST_IS_DIR) ? g_strconcat(fn, "/", NULL) : g_strdup(fn);
    g_free(fn);
  }
  g_dir_close(d);
  qsort(sug, i, sizeof(char *), cmpstringp);

path_suggest_f:
  g_free(path);
  if(dir)
    free(dir);
}




// from[24] (binary) -> to[39] (ascii - no padding zero will be added)
void base32_encode(const char *from, char *to) {
  static char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  int i, bits = 0, idx = 0, value = 0;
  for(i=0; i<24; i++) {
    value = (value << 8) | (unsigned char)from[i];
    bits += 8;
    while(bits > 5) {
      to[idx++] = alphabet[(value >> (bits-5)) & 0x1F];
      bits -= 5;
    }
  }
  if(bits > 0)
    to[idx++] = alphabet[(value << (5-bits)) & 0x1F];
}


// from[39] (ascii) -> to[24] (binary)
void base32_decode(const char *from, char *to) {
  int i, bits = 0, idx = 0, value = 0;
  for(i=0; i<39; i++) {
    value = (value << 5) | (from[i] <= '9' ? (26+(from[i]-'2')) : from[i]-'A');
    bits += 5;
    while(bits > 8) {
      to[idx++] = (value >> (bits-8)) & 0xFF;
      bits -= 8;
    }
  }
}





// Transfer / hashing rate calculation

/* How to use this:
 * From main thread:
 *   struct ratecalc thing;
 *   ratecalc_init(&thing, numsamples);
 *   ratecalc_register(&thing);
 * From any thread (usually some worker thread):
 *   ratecalc_add(&thing, bytes);
 * From main thread:
 *   rate = ratecalc_get(&thing);
 *   ratecalc_reset(&thing);
 *   ratecalc_unregister(&thing);
 *
 * ratecalc_calc() should be called with a regular interval
 */

#if INTERFACE

struct ratecalc {
  int counter;
  int samples[10];
  char num;
  char got;
  char isreg;
};

#define ratecalc_add(rc, b) g_atomic_int_add(&((rc)->counter), b)

#define ratecalc_reset(rc) do {\
    g_atomic_int_set(&((rc)->counter), 0);\
    (rc)->got = 0;\
  } while(0)

#define ratecalc_init(rc, n) do {\
    (rc)->num = n;\
    ratecalc_reset(rc);\
  } while(0)

#define ratecalc_register(rc) do { if(!(rc)->isreg) {\
    ratecalc_list = g_slist_prepend(ratecalc_list, rc);\
    (rc)->isreg = 1;\
  } } while(0)

#define ratecalc_unregister(rc) do {\
    ratecalc_list = g_slist_remove(ratecalc_list, rc);\
    (rc)->isreg = 0;\
  } while(0)

#endif

GSList *ratecalc_list = NULL;
static int ratecalc_ms[10];


int ratecalc_get(struct ratecalc *rc) {
  int i;
  guint64 r = 0, ms = 0;
  for(i=0; i<rc->got; i++) {
    ms += ratecalc_ms[i];
    r += rc->samples[i];
  }
  return (r*1000) / (ms?ms:1000);
}


void ratecalc_calc() {
  // fix time
  static GTimer *tm = NULL;
  if(!tm) {
    tm = g_timer_new();
    return;
  }
  double el = g_timer_elapsed(tm, NULL);
  g_timer_start(tm);
  memmove(ratecalc_ms+1, ratecalc_ms, 9*4);
  ratecalc_ms[0] = el * 1000.0;

  // sample and reset the counters
  GSList *n;
  for(n=ratecalc_list; n; n=n->next) {
    struct ratecalc *rc = n->data;
    memmove(rc->samples+1, rc->samples, MIN(rc->got, rc->num-1)*4);
    do {
      rc->samples[0] = g_atomic_int_get(&(rc->counter));
    } while(!g_atomic_int_compare_and_exchange(&(rc->counter), rc->samples[0], 0));
    rc->got = MIN(rc->got+1, rc->num);
  }
}





/* High-level connection handling for message-based protocols. With some binary
 * transfer stuff mixed in.
 *
 * Implements the following:
 * - Async connecting to a hostname/ip + port
 * - Async message sending (end-of-message char is added automatically)
 * - Async message receiving ("message" = all bytes until end-of-message char)
 * TODO: Use ratecalc for in and output
 *
 * Does not use the GIOStream interface, since that is inefficient and has too
 * many limitations to be useful.
 */

#if INTERFACE

// actions that can fail
#define NETERR_CONN 0
#define NETERR_RECV 1
#define NETERR_SEND 2

struct net {
  GSocketConnection *conn;
  GSocket *sock;
  // input/output buffers
  GString *in, *out;
  GCancellable *cancel; // used to cancel a connect operation
  guint in_src, out_src;
  // receive callback
  void (*cb_rcv)(struct net *, char *);
  // on-connect callback
  void (*cb_con)(struct net *);
  // Error callback. In the case of an error while connecting, cb_con will not
  // be called. Second argument is NETERR_* action. The GError does not have to
  // be freed. Will not be called in the case of G_IO_ERROR_CANCELLED.
  void (*cb_err)(struct net *, int, GError *);
  // message termination character
  char eom[2];
  // some pointer for use by the user
  void *handle;
};


// g_socket_create_source() has a cancellable argument. But I can't tell from
// the documentation that it does exactly what I want it to do, so let's just
// use g_source_remove() manually.
#define net_cancel(n) do {\
    if((n)->in_src) {\
      g_source_remove((n)->in_src);\
      (n)->in_src = 0;\
    }\
    if((n)->out_src) {\
      g_source_remove((n)->out_src);\
      (n)->out_src = 0;\
    }\
    g_cancellable_cancel((n)->cancel);\
    g_object_unref((n)->cancel);\
    (n)->cancel = g_cancellable_new();\
  } while(0)


// does this function block?
#define net_disconnect(n) do {\
    if((n)->conn) {\
      net_cancel(n);\
      g_object_unref((n)->conn);\
      (n)->conn = NULL;\
    }\
  } while(0)


// Should not be called while connected.
#define net_free(n) do {\
    g_object_unref((n)->cancel);\
    g_string_free((n)->out, TRUE);\
    g_string_free((n)->in, TRUE);\
    g_free(n);\
  } while(0)

#endif


static void net_consume_input(struct net *n) {
  char *str = n->in->str;
  char *sep;
  gssize consumed = 0;

  // TODO: set a maximum length on a single message to prevent unbounded buffer growth
  while((sep = strchr(str, n->eom[0]))) {
    consumed += 1 + sep - str;
    *sep = 0;
    g_debug("%s< %s", net_remoteaddr(n), str);
    if(str[0])
      n->cb_rcv(n, str);
    str = sep+1;
  }
  if(consumed)
    g_string_erase(n->in, 0, consumed);
}


// catches and handles any errors from g_socket_receive or g_socket_send in a
// input/output handler.
#define net_handle_ioerr(n, src, ret, err, action) do {\
    if(err && err->code == G_IO_ERROR_WOULD_BLOCK) {\
      g_error_free(err);\
      return TRUE;\
    }\
    if(err) {\
      n->cb_err(n, action, err);\
      g_error_free(err);\
      src = 0;\
      return FALSE;\
    }\
    if(ret == 0) {\
      g_set_error_literal(&err, 1, 0, "Remote disconnected.");\
      n->cb_err(n, action, err);\
      g_error_free(err);\
      src = 0;\
      return FALSE;\
    }\
  } while(0)


static gboolean net_handle_input(GSocket *sock, GIOCondition cond, gpointer dat) {
  struct net *n = dat;

  // make sure enough space is available in the input buffer (ugly hack, GString has no simple grow function)
  if(n->in->allocated_len - n->in->len < 1024) {
    gsize oldlen = n->in->len;
    g_string_set_size(n->in, n->in->len+1024);
    n->in->len = oldlen;
  }

  GError *err = NULL;
  gssize read = g_socket_receive(n->sock, n->in->str + n->in->len, n->in->allocated_len - n->in->len, NULL, &err);
  net_handle_ioerr(n, n->in_src, read, err, NETERR_RECV);
  n->in->len += read;
  n->in->str[n->in->len] = 0;
  net_consume_input(n);
  return TRUE;
}


static gboolean net_handle_output(GSocket *sock, GIOCondition cond, gpointer dat) {
  struct net *n = dat;

  GError *err = NULL;
  gssize written = g_socket_send(n->sock, n->out->str, n->out->len, NULL, &err);
  net_handle_ioerr(n, n->out_src, written, err, NETERR_SEND);
  g_string_erase(n->out, 0, written);
  if(n->out->len > 0)
    return TRUE;
  n->out_src = 0;
  return FALSE;
}


static void net_handle_connect(GObject *src, GAsyncResult *res, gpointer dat) {
  struct net *n = dat;

  GError *err = NULL;
  GSocketConnection *conn = g_socket_client_connect_to_host_finish(G_SOCKET_CLIENT(src), res, &err);

  if(!conn) {
    if(err->code != G_IO_ERROR_CANCELLED)
      n->cb_err(n, NETERR_CONN, err);
    g_error_free(err);
  } else {
    n->conn = conn;
    n->sock = g_socket_connection_get_socket(n->conn);
    g_socket_set_blocking(n->sock, FALSE);
    GSource *src = g_socket_create_source(n->sock, G_IO_IN, NULL);
    g_source_set_callback(src, (GSourceFunc)net_handle_input, n, NULL);
    n->in_src = g_source_attach(src, NULL);
    g_source_unref(src);
    n->cb_con(n);
  }
}


void net_connect(struct net *n, const char *addr, unsigned short defport, void (*cb)(struct net *)) {
  n->cb_con = cb;

  GSocketClient *sc = g_socket_client_new();
  g_socket_client_connect_to_host_async(sc, addr, defport, n->cancel, net_handle_connect, n);
  g_object_unref(sc);
}


char *net_remoteaddr(struct net *n) {
  static char a[100];
  if(!n->conn)
    return "(not connected)";

  GInetSocketAddress *addr = G_INET_SOCKET_ADDRESS(g_socket_connection_get_remote_address(n->conn, NULL));
  g_assert(addr);
  char *ip = g_inet_address_to_string(g_inet_socket_address_get_address(addr));
  sprintf(a, "%s:%d", ip, g_inet_socket_address_get_port(addr));
  g_free(ip);
  g_object_unref(addr);
  return a;
}


struct net *net_create(char term, void *han, void (*rfunc)(struct net *, char *), void (*errfunc)(struct net *, int, GError *)) {
  struct net *n = g_new0(struct net, 1);
  n->in  = g_string_sized_new(1024);
  n->out = g_string_sized_new(1024);
  n->cancel = g_cancellable_new();
  n->eom[0] = term;
  n->handle = han;
  n->cb_rcv = rfunc;
  n->cb_err = errfunc;
  return n;
}


void net_send_raw(struct net *n, const char *msg, int len) {
  if(!n->conn)
    return;
  g_string_append_len(n->out, msg, len);
  if(!n->out_src) {
    GSource *src = g_socket_create_source(n->sock, G_IO_OUT, NULL);
    g_source_set_callback(src, (GSourceFunc)net_handle_output, n, NULL);
    n->out_src = g_source_attach(src, NULL);
    g_source_unref(src);
  }
}


void net_send(struct net *n, const char *msg) {
  g_debug("%s> %s", net_remoteaddr(n), msg);
  net_send_raw(n, msg, strlen(msg));
  net_send_raw(n, n->eom, 1);
}


void net_sendf(struct net *n, const char *fmt, ...) {
  va_list va;
  va_start(va, fmt);
  char *str = g_strdup_vprintf(fmt, va);
  va_end(va);
  net_send(n, str);
  g_free(str);
}


// TODO: !!THIS IMPLEMENTATION IS NOT SUPPOSED TO BE USED FOR LARGE FILES!!
// TODO: Error handling and large file support
// Should probably call sendfile() in a separate thread or so.
void net_sendfile(struct net *n, const char *path, guint64 offset, guint64 length) {
  FILE *f = fopen(path, "r");
  g_assert(f);
  fseek(f, offset, SEEK_SET);
  char *buf = g_malloc(length);
  int len = fread(buf, 1, length, f);
  fclose(f);
  net_send_raw(n, buf, len);
  g_free(buf);
}

