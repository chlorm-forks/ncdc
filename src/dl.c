/* ncdc - NCurses Direct Connect client

  Copyright (c) 2011-2014 Yoran Heling

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
#include "dl.h"


#if INTERFACE

struct dl_user_dl_t {
  dl_t *dl;
  dl_user_t *u;
  char error;               // DLE_*
  char *error_msg;
};


#define DLU_NCO  0 // Not connected, ready for connection
#define DLU_EXP  1 // Expecting a dl connection
#define DLU_IDL  2 // dl connected, idle
#define DLU_REQ  3 // dl connected, download requested
#define DLU_ACT  4 // dl connected, downloading
#define DLU_WAI  5 // Not connected, waiting for reconnect timeout

struct dl_user_t {
  int state;            // DLU_*
  int timeout;          // source id of the timeout function in DLU_WAI
  guint64 uid;
  cc_t *cc;             // Always when state = IDL, REQ or ACT, may be set or NULL in EXP
  GSequence *queue;     // list of dl_user_dl_t, ordered by dl_user_dl_sort()
  dl_user_dl_t *active; // when state = DLU_ACT/REQ, the dud that is being downloaded (NULL if it had been removed from the queue while downloading)
  gboolean selected : 1;
  // Back-off timer. 'failures' is increased by one (up to DL_MAXBACKOFF) when
  // a user is selected and reset to 0 when in the ACT state. 'periods' is set
  // to 2^failures when a user is unselected, and decreased by one at the start
  // of each period. A user is not selected when 'periods > 0'.
  guint32 backoff_periods : 7;
  guint32 backoff_failures : 4;
};

/* State machine for dl_user.state:
 *
 *          10  /-----\
 *        .<--- | WAI | <---------------------------------------------.
 *       /      \-----/     |             |             |             |
 *       |                2 |           4 |           6 |           8 |
 *       v                  |             |             |             |
 *    /-----\  1         /-----\  3    /-----\  5    /-----\  7    /-----\
 * -> | NCO | ---------> | EXP | ----> | IDL | ----> | REQ | ----> | ACT |
 *    \-----/            \-----/       \-----/       \-----/       \-----/
 *                                        \                         9 /
 *                                         `<------------------------'
 *
 *  1. We're requesting a connect
 *  2. No reply, connection timed out or we lost the $Download game on NMDC
 *  3. Successful connection and handshake
 *  4. Idle timeout / user disconnect
 *  5. We're requesting a download (CGET)
 *  6. Idle timeout / user disconnect / no slots free
 *  7. Start of download (CSND)
 *  8. Idle timeout / user disconnect / download aborted / error while downloading
 *  9. Download (segment) finished
 * 10. Reconnect timeout expired
 */



// Note: The following numbers are also stored in the database. Keep this in
// mind when changing or extending. (Both DLP_ and DLE_)

#define DLP_ERR   -65 // disabled due to (permanent) error
#define DLP_OFF   -64 // disabled by user
#define DLP_VLOW   -2
#define DLP_LOW    -1
#define DLP_MED     0
#define DLP_HIGH    1
#define DLP_VHIGH   2


#define DLE_NONE    0 // No error
#define DLE_INVTTHL 1 // TTHL data does not match the file root
#define DLE_NOFILE  2 // User does not have the file at all
#define DLE_IO_INC  3 // I/O error with incoming file
#define DLE_IO_DEST 4 // I/O error when moving to destination file/dir
#define DLE_HASH    5 // Hash check failed


struct dl_t {
  gboolean islist : 1;
  gboolean hastthl : 1;
  gboolean flopen : 1;   // For lists: Whether to open a browse tab after completed download
  gboolean flmatch : 1;  // For lists: Whether to match queue after completed download
  gboolean hassize : 1;  // For lists: Whether the size of the file list is known and validated
  gboolean allbusy : 1;  // When no more unallocated blocks are available (maintained by dlfile.c)
  signed char prio;      // DLP_*
  char error;            // DLE_*
  unsigned char active_threads; // number of active downloading threads (maintained by dlfile.c)
  int incfd;             // file descriptor for this file in <incoming_dir> (maintained by dlfile.c)
  char *error_msg;       // if error != DLE_NONE
  char *flsel;           // path to file/dir to select for filelists
  ui_tab_t *flpar;       // parent of the file list browser tab for filelists (might be a dangling pointer!)
  char hash[24];         // TTH for files, tiger(uid) for filelists
  GPtrArray *u;          // list of users who have this file (GSequenceIter pointers into dl_user.queue)
  guint64 size;          // total size of the file
  guint64 have;          // what we have so far
  guint64 hash_block;    // number of bytes that each block represents
  char *inc;             // path to the incomplete file (<incoming_dir>/<base32-hash>)
  char *dest;            // destination path
  GSequenceIter *iter;   // used by ui_dl
  GSList *threads;       // maintained by dlfile.c
  guint8 *bitmap;        // Only used if hastthl, maintained by dlfile.c
  guint bitmap_src;      // timeout source for flushing the bitmap, maintained by dlfile.c
  /* Maintained by dlfile.c, protects dl_t.{have,bitmap,bitmap_src} and
   * dlfile_thread_t.{allocated,avail,chunk}.
   * Some other fields are shared, too, but those are never modified while a
   * downloading thread is active and thus do not need synchronisation.  These
   * include dl_t.{size,islist,hash,hash_block,incfd} and possibly more.
   * TODO: dl.have isn't always protected yet! */
  GStaticMutex lock;
};

#endif


// Minimum filesize for which we request TTHL data. If a file is smaller than
// this, the TTHL data would simply add more overhead than it is worth.
#define DL_MINTTHLSIZE (2048*1024)
// Minimum TTHL block size we're interested in. If we get better granularity
// than this, blocks will be combined to reduce the TTHL data.
#define DL_MINBLOCKSIZE (1024*1024)

// This should probably be a setting
#define DL_PERIODLENGTH 60

// Maximum time that a repeatedly unavailable user will stay in the back-off
// queue.  Actual time is measured in (1<<DL_MAXBACKOFF)*DL_PERIODLENGTH
// seconds.  A value of MAXBACKOFF of 6 and a PERIODLENGTH of 60 thus gives a
// maximum backoff of 64 minutes.
#define DL_MAXBACKOFF 6

// How long a user stays in the WAI state
#define DL_RECONNTIMEOUT 10


// Download queue.
// Key = dl->hash, Value = dl_t
GHashTable *dl_queue = NULL;


// uid -> dl_user lookup table.
static GHashTable *queue_users = NULL;
// uid -> dl_user lookup table for users that have (u->selected || u->active)
static GHashTable *queue_busy = NULL;

static void dl_queue_sync();


// Utility function that returns an error string for DLE_* errors.
char *dl_strerror(char err, const char *sub) {
  static char buf[200];
  char *par =
    err == DLE_NONE    ? "No error" :
    err == DLE_INVTTHL ? "TTHL data does not match TTH root" :
    err == DLE_NOFILE  ? "File not available from this user" :
    err == DLE_IO_INC  ? "Error writing to temporary file" :
    err == DLE_IO_DEST ? "Error moving file to destination" :
    err == DLE_HASH    ? "Hash error" : "Unknown error";
  if(sub)
    g_snprintf(buf, 200, "%s: %s", par, sub);
  else
    g_snprintf(buf, 200, "%s.", par);
  return buf;
}





// dl_user_t related functions

static gboolean dl_user_waitdone(gpointer dat);


// Determine whether a dl_user_dl struct can be considered as "enabled".
#define dl_user_dl_enabled(dud) (\
    !dud->error && dud->dl->prio > DLP_OFF\
    && ((!dud->dl->size && dud->dl->islist) || dud->dl->size != dud->dl->have)\
  )


// Sort function for dl_user_dl structs. Items with a higher priority are
// sorted before items with a lower priority. Never returns 0, so the order is
// always predictable even if all items have the same priority. This function
// is used both for sorting the queue of a single user, and to sort users
// itself on their highest-priority file.
// TODO: Give priority to small files (those that can be downloaded using a minislot)
static gint dl_user_dl_sort(gconstpointer a, gconstpointer b, gpointer dat) {
  const dl_user_dl_t *x = a;
  const dl_user_dl_t *y = b;
  const dl_t *dx = x->dl;
  const dl_t *dy = y->dl;
  return
      // Disabled? Always last
      dl_user_dl_enabled(x) && !dl_user_dl_enabled(y) ? -1 : !dl_user_dl_enabled(x) && dl_user_dl_enabled(y) ? 1
      // File lists get higher priority than normal files
    : dx->islist && !dy->islist ? -1 : !dx->islist && dy->islist ? 1
      // Higher priority files get higher priority than lower priority ones (duh)
    : dx->prio > dy->prio ? -1 : dx->prio < dy->prio ? 1
      // For equal priority: download in alphabetical order
    : strcmp(dx->dest, dy->dest);
}


// Frees a dl_user_dl struct
static void dl_user_dl_free(gpointer x) {
  g_free(((dl_user_dl_t *)x)->error_msg);
  g_slice_free(dl_user_dl_t, x);
}


// Get the highest-priority file in the users' queue that is not already being
// downloaded. This function can be assumed to be relatively fast, in most
// cases the first iteration will be enough, in the worst case it at most
// <download_slots> iterations.
// Returns NULL if there is no dl item in the queue that is enabled and not
// being downloaded.
static dl_user_dl_t *dl_user_getdl(const dl_user_t *du) {
  GSequenceIter *i = g_sequence_get_begin_iter(du->queue);
  for(; !g_sequence_iter_is_end(i); i=g_sequence_iter_next(i)) {
    dl_user_dl_t *dud = g_sequence_get(i);
    if(dl_user_dl_enabled(dud) && !dud->dl->allbusy)
      return dud;
  }
  return NULL;
}


// Change the state of a user, use state=-1 when something is removed from
// du->queue.
static void dl_user_setstate(dl_user_t *du, int state) {
  // Handle reconnect timeout
  // x -> WAI
  if(state >= 0 && du->state != DLU_WAI && state == DLU_WAI)
    du->timeout = g_timeout_add_seconds_full(G_PRIORITY_LOW, DL_RECONNTIMEOUT, dl_user_waitdone, du, NULL);
  // WAI -> X
  else if(state >= 0 && du->state == DLU_WAI && state != DLU_WAI)
    g_source_remove(du->timeout);

  // ACT -> x
  if(state >= 0 && du->state == DLU_ACT && state != DLU_ACT && du->active)
    du->active = NULL;

  // Set state
  //g_debug("dlu:%"G_GINT64_MODIFIER"x: %d -> %d (active = %s)", du->uid, du->state, state, du->active ? "true":"false");
  if(state >= 0)
    du->state = state;

  if(!du->selected && state != DLU_ACT)
    g_hash_table_remove(queue_busy, &du->uid);

  if(state == DLU_ACT)
    du->backoff_failures = 0;

  // Check whether there is any value in keeping this dl_user struct in memory
  if(du->state == DLU_NCO && !g_sequence_get_length(du->queue)) {
    g_hash_table_remove(queue_users, &du->uid);
    g_sequence_free(du->queue);
    g_slice_free(dl_user_t, du);
    return;
  }

  dl_queue_sync();
}


static gboolean dl_user_waitdone(gpointer dat) {
  dl_user_t *du = dat;
  g_return_val_if_fail(du->state == DLU_WAI, FALSE);
  dl_user_setstate(du, DLU_NCO);
  return FALSE;
}


// When called with NULL, this means that a connection attempt failed or we
// somehow disconnected from the user.
// Otherwise, it means that the cc connection with the user went into the IDLE
// state, either after the handshake or after a completed download.
void dl_user_cc(guint64 uid, cc_t *cc) {
  g_debug("dl:%016"G_GINT64_MODIFIER"x: cc = %s", uid, cc?"true":"false");
  dl_user_t *du = g_hash_table_lookup(queue_users, &uid);
  if(!du)
    return;
  g_return_if_fail(!cc || du->state == DLU_NCO || du->state == DLU_EXP || du->state == DLU_ACT || du->state == DLU_REQ);
  du->cc = cc;
  dl_user_setstate(du, cc ? DLU_IDL : DLU_WAI);
}


// Called from cc.c when we receive a CSND, to indicate that we can move to DLU_ACT
void dl_user_active(guint64 uid) {
  dl_user_t *du = g_hash_table_lookup(queue_users, &uid);
  if(du)
    dl_user_setstate(du, DLU_ACT);
}


// Adds a user to a dl item, making sure to create the user if it's not in the
// queue yet. For internal use only, does not save the changes to the database.
static void dl_user_add(dl_t *dl, guint64 uid, char error, const char *error_msg) {
  g_return_if_fail(!dl->islist || dl->u->len == 0);

  // get or create dl_user struct
  dl_user_t *du = g_hash_table_lookup(queue_users, &uid);
  if(!du) {
    du = g_slice_new0(dl_user_t);
    du->state = DLU_NCO;
    du->uid = uid;
    du->queue = g_sequence_new(dl_user_dl_free);
    g_hash_table_insert(queue_users, &du->uid, du);
  }

  // create and fill dl_user_dl struct
  dl_user_dl_t *dud = g_slice_new0(dl_user_dl_t);
  dud->dl = dl;
  dud->u = du;
  dud->error = error;
  dud->error_msg = error_msg ? g_strdup(error_msg) : NULL;

  // Add to du->queue and dl->u
  g_ptr_array_add(dl->u, g_sequence_insert_sorted(du->queue, dud, dl_user_dl_sort, NULL));
  uit_dl_dud_listchange(dud, UITDL_ADD);
}


// Remove a user (dl->u[i]) from a dl item, making sure to also remove it from
// du->queue and possibly free the dl_user item if it's no longer useful. As
// above, for internal use only. Does not save the changes to the database.
static void dl_user_rm(dl_t *dl, int i) {
  GSequenceIter *dudi = g_ptr_array_index(dl->u, i);
  dl_user_dl_t *dud = g_sequence_get(dudi);
  dl_user_t *du = dud->u;

  // Make sure to disconnect the user if we happened to be actively downloading
  // the file from this user.
  if(du->active == dud) {
    cc_disconnect(du->cc, TRUE);
    du->active = NULL;
  }

  uit_dl_dud_listchange(dud, UITDL_DEL);
  g_sequence_remove(dudi); // dl_user_dl_free() will be called implicitly
  g_ptr_array_remove_index_fast(dl->u, i);
  dl_user_setstate(du, -1);
}




// Keeping the actual active downloads in sync with ->selected

static gboolean dl_queue_sync_defer; // whether a new sync is queued


static void dl_queue_sync_reqdl(dl_user_t *du) {
  dl_user_dl_t *dud = dl_user_getdl(du);
  // TODO: This should not prevent a download from starting if there is still
  // another user with (!selected && active)
  if(!dud)
    return;
  dl_t *dl = dud->dl;
  g_debug("dl:%016"G_GINT64_MODIFIER"x: using connection for %s", du->uid, dl->dest);

  // Update state and connect
  du->active = dud;
  dl_user_setstate(du, DLU_REQ);
  cc_download(du->cc, dl);
}


static void dl_queue_sync_reqconn(dl_user_t *du) {
  hub_user_t *u = g_hash_table_lookup(hub_uids, &du->uid);
  if(!u || !u->hub->nick_valid)
    return;
  g_debug("dl:%016"G_GINT64_MODIFIER"x: trying to open a connection", du->uid);
  dl_user_setstate(du, DLU_EXP);
  hub_opencc(u->hub, u);
}


static gboolean dl_queue_sync_do(gpointer dat) {
  dl_user_t *du;
  GHashTableIter iter;
  g_hash_table_iter_init(&iter, queue_busy);
  while(g_hash_table_iter_next(&iter, NULL, (gpointer *)&du)) {
    if(!du->selected)
      continue;

    // Connected but not downloading? Request a new download.
    if(du->state == DLU_IDL)
      dl_queue_sync_reqdl(du);
    // Not even connected? Try a connect.
    else if(du->state == DLU_NCO)
      dl_queue_sync_reqconn(du);
  }

  // TODO: Disconnect excessive download connections

  dl_queue_sync_defer = FALSE;
  return FALSE;
}


static void dl_queue_sync() {
  if(!dl_queue_sync_defer)
    g_idle_add(dl_queue_sync_do, NULL);
  dl_queue_sync_defer = TRUE;
}




// Updating ->selected

static int dl_queue_select_src; // timeout source for the next period


static gboolean dl_queue_select_istarget(dl_user_t *du) {
  if(du->backoff_periods)
    return FALSE;

  // TODO: dl_user_getdl() fails if all files from this user are already being
  // downloaded. When selecting new peers this shouldn't matter, we'll likely
  // disconnect the existing users anyway.
  // (Note that making the dlfile segment allocation smaller will likely
  // prevent this from being a problem in many cases, but it's not a complete
  // solution)
  if(!dl_user_getdl(du))
    return FALSE;

  // User must be online and we must be logged in to the hub.
  hub_user_t *u = g_hash_table_lookup(hub_uids, &du->uid);
  if(!u || !u->hub->nick_valid)
    return FALSE;

  // TODO: Exclude unavailable users with a backoff timer

  // If the above holds, we're safe
  return TRUE;
}


static gboolean dl_queue_select_do(gpointer dat) {
  int freeslots = var_get_int(0, VAR_download_slots);

  // Pass through the list of users and,
  // - Unselect currently selected users
  // - Decrease the backoff_periods by one
  dl_user_t *du;
  GHashTableIter iter;
  g_hash_table_iter_init(&iter, queue_users);
  while(g_hash_table_iter_next(&iter, NULL, (gpointer *)&du)) {
    if(du->selected) {
      du->selected = FALSE;
      du->backoff_periods = 1U << du->backoff_failures;
      if(!du->active)
        g_hash_table_remove(queue_busy, &du->uid);
    }
    if(du->backoff_periods)
      du->backoff_periods--;
  }

  // Current implementation just selects the first $freeslots users in the hash
  // table.
  g_hash_table_iter_init(&iter, queue_users);
  while(freeslots > 0 && g_hash_table_iter_next(&iter, NULL, (gpointer *)&du)) {
    if(!dl_queue_select_istarget(du))
      continue;
    freeslots--;
    du->selected = TRUE;
    du->backoff_failures = MIN(du->backoff_failures+1, DL_MAXBACKOFF);
    g_hash_table_insert(queue_busy, &du->uid, du);
  }

  // TODO: If there are less candidate users in the queue than our number of
  // download slots, we could add some users with backoff_periods>0 to the list
  // of candidates. If we do that, however, we need to be careful not to
  // increase its backoff_failures count if it fails again, otherwise the
  // backoff timer may increase a bit too fast for that user.

  // TODO: In the naive implementation, users with (!du->selected &&
  // du->active) should be disconnected here.
  // In the improved implementation, some users need to be disconnected here,
  // too, if we are downloading from more users than what has been selected.

  dl_queue_sync();
  if(dat)
    return TRUE;
  dl_queue_select_src = g_timeout_add_seconds(DL_PERIODLENGTH, dl_queue_select_do, dl_queue_select_do);
  return FALSE;
}


static void dl_queue_select() {
  // If we're already downloading, do nothing. A new period will be started soon anyway.
  if(g_hash_table_size(queue_busy))
    return;
  // Otherwise, start the new period after a short timeout.
  g_source_remove(dl_queue_select_src);
  dl_queue_select_src = g_timeout_add(500, dl_queue_select_do, NULL);
}


static void dl_queue_select_init() {
  dl_queue_select_src = g_timeout_add_seconds(DL_PERIODLENGTH, dl_queue_select_do, dl_queue_select_do);
}





// Adding stuff to the download queue

// Adds a dl item to the queue. dl->inc will be determined and opened here.
// dl->hastthl will be set if the file is small enough to not need TTHL data.
// dl->u is also created here.
static void dl_queue_insert(dl_t *dl, gboolean init) {
  // Set dl->hastthl for files smaller than MINTTHLSIZE.
  if(!dl->islist && !dl->hastthl && dl->size <= DL_MINTTHLSIZE) {
    dl->hastthl = TRUE;
    dl->hash_block = DL_MINTTHLSIZE;
  }
  // figure out dl->inc
  char hash[40] = {};
  base32_encode(dl->hash, hash);
  dl->inc = g_build_filename(var_get(0, VAR_incoming_dir), hash, NULL);
  // create dl->u
  dl->u = g_ptr_array_new();
  // insert in the global queue
  g_hash_table_insert(dl_queue, dl->hash, dl);
  uit_dl_listchange(dl, UITDL_ADD);

  // insert in the database
  if(!dl->islist && !init)
    db_dl_insert(dl->hash, dl->size, dl->dest, dl->prio, dl->error, dl->error_msg);

  // start download, if possible
  if(!init)
    dl_queue_select();
}


// Add the file list of some user to the queue
void dl_queue_addlist(hub_user_t *u, const char *sel, ui_tab_t *parent, gboolean open, gboolean match) {
  g_return_if_fail(u && u->hasinfo);
  dl_t *dl = g_slice_new0(dl_t);
  dl->islist = TRUE;
  g_static_mutex_init(&dl->lock);
  if(sel)
    dl->flsel = g_strdup(sel);
  dl->flpar = parent;
  dl->flopen = open;
  dl->flmatch = match;
  // figure out dl->hash
  tiger_ctx_t tg;
  tiger_init(&tg);
  tiger_update(&tg, (char *)&u->uid, 8);
  tiger_final(&tg, dl->hash);
  dl_t *dup = g_hash_table_lookup(dl_queue, dl->hash);
  if(dup) {
    if(open)
      dup->flopen = TRUE;
    if(match)
      dup->flmatch = TRUE;
    g_warning("dl:%016"G_GINT64_MODIFIER"x: files.xml.bz2 already in the queue, updating flags.", u->uid);
    g_slice_free(dl_t, dl);
    return;
  }
  // figure out dl->dest
  char *fn = g_strdup_printf("%016"G_GINT64_MODIFIER"x.xml.bz2", u->uid);
  dl->dest = g_build_filename(db_dir, "fl", fn, NULL);
  g_free(fn);
  // insert & start
  g_debug("dl:%016"G_GINT64_MODIFIER"x: queueing files.xml.bz2", u->uid);
  dl_queue_insert(dl, FALSE);
  dl_user_add(dl, u->uid, 0, NULL);
}


// Add a regular file to the queue. If there is another file in the queue with
// the same filename, something else will be chosen instead.
// Returns true if it was added, false if it was already in the queue.
static gboolean dl_queue_addfile(guint64 uid, char *hash, guint64 size, char *fn) {
  if(g_hash_table_lookup(dl_queue, hash))
    return FALSE;
  dl_t *dl = g_slice_new0(dl_t);
  g_static_mutex_init(&dl->lock);
  memcpy(dl->hash, hash, 24);
  dl->size = size;
  // Figure out dl->dest
  dl->dest = g_build_filename(var_get(0, VAR_download_dir), fn, NULL);
  // and add to the queue
  g_debug("dl:%016"G_GINT64_MODIFIER"x: queueing %s", uid, fn);
  dl_queue_insert(dl, FALSE);
  dl_user_add(dl, uid, 0, NULL);
  db_dl_adduser(dl->hash, uid, 0, NULL);
  return TRUE;
}


// Recursively adds a file or directory to the queue. *excl will only be
// checked for files in subdirectories, if *fl is a file it will always be
// added.
void dl_queue_add_fl(guint64 uid, fl_list_t *fl, char *base, GRegex *excl) {
  // check excl
  if(base && excl && g_regex_match(excl, fl->name, 0, NULL)) {
    ui_mf(NULL, 0, "Ignoring `%s': excluded by regex.", fl->name);
    return;
  }

  char *name = base ? g_build_filename(base, fl->name, NULL) : g_strdup(fl->name);
  if(fl->isfile) {
    if(!dl_queue_addfile(uid, fl->tth, fl->size, name))
      ui_mf(NULL, 0, "Ignoring `%s': already queued.", name);
  } else {
    int i;
    for(i=0; i<fl->sub->len; i++)
      dl_queue_add_fl(uid, g_ptr_array_index(fl->sub, i), name, excl);
  }
  if(!base)
    ui_mf(NULL, 0, "%s added to queue.", name);
  g_free(name);
}


// Add a search result to the queue. (Only for files)
void dl_queue_add_res(search_r_t *r) {
  char *name = strrchr(r->file, '/');
  if(name)
    name++;
  else
    name = r->file;
  if(dl_queue_addfile(r->uid, r->tth, r->size, name))
    ui_mf(NULL, 0, "%s added to queue.", name);
  else
    ui_m(NULL, 0, "Already queued.");
}


// Add a user to a dl item, if the file is in the queue and the user hasn't
// been added yet. Returns:
//  -1  Not found in queue
//   0  Found, but user already queued
//   1  Found and user added to the queue
int dl_queue_matchfile(guint64 uid, char *tth) {
  dl_t *dl = g_hash_table_lookup(dl_queue, tth);
  if(!dl)
    return -1;
  int i;
  for(i=0; i<dl->u->len; i++)
    if(((dl_user_dl_t *)g_sequence_get(g_ptr_array_index(dl->u, i)))->u->uid == uid)
      return 0;
  dl_user_add(dl, uid, 0, NULL);
  db_dl_adduser(dl->hash, uid, 0, NULL);
  dl_queue_select();
  return 1;
}


// Recursively walks through the file list and adds the user to matching dl
// items. Returns the number of items found, and the number of items for which
// the user was added is stored in *added (should be initialized to zero).
int dl_queue_match_fl(guint64 uid, fl_list_t *fl, int *added) {
  if(fl->isfile && fl->hastth) {
    int r = dl_queue_matchfile(uid, fl->tth);
    if(r == 1)
      (*added)++;
    return r >= 0 ? 1 : 0;

  } else {
    int n = 0;
    int i;
    for(i=0; i<fl->sub->len; i++)
      n += dl_queue_match_fl(uid, g_ptr_array_index(fl->sub, i), added);
    return n;
  }
}





// Removing stuff from the queue and changing priorities

// removes an item from the queue
void dl_queue_rm(dl_t *dl) {
  // remove from the user info (this will also force a disconnect if the item
  // is being downloaded.)
  while(dl->u->len > 0)
    dl_user_rm(dl, 0);
  // remove from dl list
  if(g_hash_table_lookup(dl_queue, dl->hash)) {
    uit_dl_listchange(dl, UITDL_DEL);
    g_hash_table_remove(dl_queue, dl->hash);
  }

  // Don't do anything else if there is still an active downloading thread.
  // Wait until all threads stop this function is called again to actually free
  // and remove the stuff.
  if(dl->active_threads)
    return;

  // remove from the database
  if(!dl->islist)
    db_dl_rm(dl->hash);
  // free and remove dl struct
  // and free
  dlfile_rm(dl);
  g_ptr_array_unref(dl->u);
  g_free(dl->inc);
  g_free(dl->flsel);
  g_free(dl->dest);
  g_free(dl->error_msg);
  g_slice_free(dl_t, dl);
}


void dl_queue_setprio(dl_t *dl, signed char prio) {
  gboolean enabled = dl->prio <= DLP_OFF && prio > DLP_OFF;
  dl->prio = prio;
  db_dl_setstatus(dl->hash, dl->prio, dl->error, dl->error_msg);
  // Make sure the dl_user.queue lists are still in the correct order
  int i;
  for(i=0; i<dl->u->len; i++)
    g_sequence_sort_changed(g_ptr_array_index(dl->u, i), dl_user_dl_sort, NULL);
  // Start the download if it is enabled
  if(enabled)
    dl_queue_select();
  /* TODO: Disconnect active users if the dl item is disabled */
}


void dl_queue_seterr(dl_t *dl, char e, const char *sub) {
  dl->error = e;
  g_free(dl->error_msg);
  dl->error_msg = sub ? g_strdup(sub) : NULL;
  dl_queue_setprio(dl, DLP_ERR);
  g_debug("Download of `%s' failed: %s", dl->dest, dl_strerror(e, sub));
  ui_mf(uit_main_tab, 0, "Download of `%s' failed: %s", dl->dest, dl_strerror(e, sub));
}


// Set a user-specific error. If tth = NULL, the error will be set for all
// files in the queue.
void dl_queue_setuerr(guint64 uid, char *tth, char e, const char *emsg) {
  dl_t *dl = tth ? g_hash_table_lookup(dl_queue, tth) : NULL;
  dl_user_t *du = g_hash_table_lookup(queue_users, &uid);
  if(!du || (tth && !dl))
    return;

  g_debug("%016"G_GINT64_MODIFIER"x: Setting download error for `%s' to: %s", uid, dl?dl->dest:"all", dl_strerror(e, emsg));

  // from a single dl item
  if(dl) {
    int i;
    for(i=0; i<dl->u->len; i++) {
      GSequenceIter *iter = g_ptr_array_index(dl->u, i);
      dl_user_dl_t *dud = g_sequence_get(iter);
      if(dud->u == du) {
        dud->error = e;
        g_free(dud->error_msg);
        dud->error_msg = emsg ? g_strdup(emsg) : NULL;
        g_sequence_sort_changed(iter, dl_user_dl_sort, NULL);
        break;
      }
    }

  // for all dl items
  } else {
    GSequenceIter *i = g_sequence_get_begin_iter(du->queue);
    for(; !g_sequence_iter_is_end(i); i=g_sequence_iter_next(i)) {
      dl_user_dl_t *dud = g_sequence_get(i);
      dud->error = e;
      g_free(dud->error_msg);
      dud->error_msg = emsg ? g_strdup(emsg) : NULL;
    }
    // Do the sort after looping through all items - looping through the list
    // while changing the ordering may cause problems.
    g_sequence_sort(du->queue, dl_user_dl_sort, NULL);
  }

  // update DB
  db_dl_setuerr(uid, tth, e, emsg);

  dl_queue_select();
}


// Remove a user from the queue for a certain file. If tth = NULL, the user
// will be removed from the queue entirely.
void dl_queue_rmuser(guint64 uid, char *tth) {
  dl_t *dl = tth ? g_hash_table_lookup(dl_queue, tth) : NULL;
  dl_user_t *du = g_hash_table_lookup(queue_users, &uid);
  if(!du || (tth && !dl))
    return;

  // from a single dl item
  if(dl) {
    int i;
    for(i=0; i<dl->u->len; i++) {
      if(((dl_user_dl_t *)g_sequence_get(g_ptr_array_index(dl->u, i)))->u == du) {
        dl_user_rm(dl, i);
        break;
      }
    }
    if(dl->islist && !dl->u->len)
      dl_queue_rm(dl);

  // from all dl items (may be fairly slow)
  } else {
    // The loop is written in this way because after calling dl_user_rm():
    // 1. The current GSequenceIter is freed.
    // 2. The entire du struct and the GSequence may have been freed as well,
    //    if there were no other items left in its queue.
    GSequenceIter *n, *i = g_sequence_get_begin_iter(du->queue);
    gboolean run = !g_sequence_iter_is_end(i);
    while(run) {
      n = g_sequence_iter_next(i);
      run = !g_sequence_iter_is_end(n);
      dl_t *dl = ((dl_user_dl_t *)g_sequence_get(i))->dl;
      int j;
      for(j=0; j<dl->u->len; j++) {
        if(g_ptr_array_index(dl->u, j) == i) {
          dl_user_rm(dl, j);
          break;
        }
      }
      if(dl->islist && !dl->u->len)
        dl_queue_rm(dl);
      i = n;
    }
  }

  // Remove from the database
  db_dl_rmuser(uid, tth);
}





// Managing of active downloads

// Called when we've got a complete file
void dl_finished(dl_t *dl) {
  g_debug("dl: download of `%s' finished, removing from queue", dl->dest);

  // open the file list
  if(dl->islist && dl->prio != DLP_ERR) {
    g_return_if_fail(dl->u->len == 1);
    // Ugly hack: make sure to not select the browse tab, if one is opened
    GList *cur = ui_tab_cur;
    uit_fl_queue(((dl_user_dl_t *)g_sequence_get(g_ptr_array_index(dl->u, 0)))->u->uid,
        FALSE, dl->flsel, dl->flpar, dl->flopen, dl->flmatch);
    ui_tab_cur = cur;
  }

  dl_queue_rm(dl);
}


// Called when we've received TTHL data. The *tthl data may be modified
// in-place.
void dl_settthl(guint64 uid, char *tth, char *tthl, int len) {
  dl_t *dl = g_hash_table_lookup(dl_queue, tth);
  dl_user_t *du = g_hash_table_lookup(queue_users, &uid);
  if(!dl || !du)
    return;
  g_return_if_fail(du->state == DLU_ACT);
  g_return_if_fail(!dl->islist);
  // We accidentally downloaded the TTHL from multiple users. Just discard this data.
  if(dl->hastthl)
    return;

  g_debug("dl:%016"G_GINT64_MODIFIER"x: Received TTHL data for %s (len = %d, bs = %"G_GUINT64_FORMAT")", uid, dl->dest, len, tth_blocksize(dl->size, len/24));

  // Validate correctness with the root hash
  char root[24];
  tth_root(tthl, len/24, root);
  if(memcmp(root, dl->hash, 24) != 0) {
    g_warning("dl:%016"G_GINT64_MODIFIER"x: Incorrect TTHL for %s.", uid, dl->dest);
    dl_queue_setuerr(uid, tth, DLE_INVTTHL, NULL);
    return;
  }

  // If the blocksize is smaller than MINBLOCKSIZE, combine blocks.
  guint64 bs = tth_blocksize(dl->size, len/24);
  unsigned int cl = 1; // number of blocks to combine into a single block
  while(bs < DL_MINBLOCKSIZE) {
    bs <<= 2;
    cl <<= 2;
  }
  int newlen = tth_num_blocks(dl->size, bs)*24;
  int i;
  // Shrink the TTHL data in-place.
  for(i=0; cl>1 && i<newlen/24; i++)
    tth_root(tthl+(i*cl*24), MIN(cl, (len/24)-(i*cl)), tthl+(i*24));
  if(len != newlen)
    g_debug("dl:%016"G_GINT64_MODIFIER"x: Shrunk TTHL data for %s (len = %d, bs = %"G_GUINT64_FORMAT")", uid, dl->dest, newlen, bs);

  db_dl_settthl(tth, tthl, newlen);
  dl->hastthl = TRUE;
  dl->hash_block = bs;
}





// Loading/initializing the download queue on startup


// Creates and inserts a dl_t item from the database in the queue
void dl_load_dl(const char *tth, guint64 size, const char *dest, signed char prio, char error, const char *error_msg, int tthllen) {
  g_return_if_fail(dest);

  dl_t *dl = g_slice_new0(dl_t);
  g_static_mutex_init(&dl->lock);
  memcpy(dl->hash, tth, 24);
  dl->size = size;
  dl->prio = prio;
  dl->error = error;
  dl->error_msg = error_msg ? g_strdup(error_msg) : NULL;
  dl->dest = g_strdup(dest);

  if(dl->size < DL_MINTTHLSIZE) {
    dl->hastthl = TRUE;
    dl->hash_block = DL_MINTTHLSIZE;
  } else if(tthllen) {
    dl->hastthl = TRUE;
    dl->hash_block = tth_blocksize(dl->size, tthllen/24);
  }

  dl_queue_insert(dl, TRUE);
}


// Creates and adds a dl_user_t/dl_user_dl from the database in the queue
void dl_load_dlu(const char *tth, guint64 uid, char error, const char *error_msg) {
  dl_t *dl = g_hash_table_lookup(dl_queue, tth);
  g_return_if_fail(dl);
  dl_user_add(dl, uid, error, error_msg);
}


void dl_init_global() {
  queue_users = g_hash_table_new(g_int64_hash, g_int64_equal);
  queue_busy = g_hash_table_new(g_int64_hash, g_int64_equal);
  dl_queue = g_hash_table_new(g_int_hash, tiger_hash_equal);
  // load stuff from the database
  db_dl_getdls(dl_load_dl);
  db_dl_getdlus(dl_load_dlu);
  // load/check the data we've already downloaded
  dl_t *dl;
  GHashTableIter iter;
  g_hash_table_iter_init(&iter, dl_queue);
  while(g_hash_table_iter_next(&iter, NULL, (gpointer *)&dl))
    dlfile_load(dl);
  // start period timer
  dl_queue_select_init();
  // Delete old filelists
  dl_fl_clean(NULL);
}


void dl_close_global() {
  // Delete incomplete file lists. They won't be completed anyway.
  GHashTableIter iter;
  dl_t *dl;
  g_hash_table_iter_init(&iter, dl_queue);
  while(g_hash_table_iter_next(&iter, NULL, (gpointer *)&dl))
    if(dl->islist)
      unlink(dl->inc);
  // Delete old filelists
  dl_fl_clean(NULL);
}






// Various cleanup/gc utilities

// Removes old filelists from /fl/. Can be run from a timer.
gboolean dl_fl_clean(gpointer dat) {
  char *dir = g_build_filename(db_dir, "fl", NULL);
  GDir *d = g_dir_open(dir, 0, NULL);
  if(!d) {
    g_free(dir);
    return TRUE;
  }

  const char *n;
  time_t ref = time(NULL) - var_get_int(0, VAR_filelist_maxage);
  while((n = g_dir_read_name(d))) {
    if(strcmp(n, ".") == 0 || strcmp(n, "..") == 0)
      continue;
    char *fn = g_build_filename(dir, n, NULL);
    struct stat st;
    if(stat(fn, &st) >= 0 && st.st_mtime < ref)
      unlink(fn);
    g_free(fn);
  }
  g_dir_close(d);
  g_free(dir);
  return TRUE;
}


// Removes unused files in <incoming_dir>.
void dl_inc_clean() {
  char *dir = var_get(0, VAR_incoming_dir);
  GDir *d = g_dir_open(dir, 0, NULL);
  if(!d)
    return;

  const char *n;
  char hash[24];
  while((n = g_dir_read_name(d))) {
    // Only consider files that we have created, which always happen to have a
    // base32-encoded hash as filename.
    if(!istth(n))
      continue;
    base32_decode(n, hash);
    if(g_hash_table_lookup(dl_queue, hash))
      continue;
    // not in the queue? delete.
    char *fn = g_build_filename(dir, n, NULL);
    unlink(fn);
    g_free(fn);
  }
  g_dir_close(d);
}

