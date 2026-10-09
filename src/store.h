#ifndef STORE_H
#define STORE_H
#include <stddef.h>
#include <stdint.h>
#include "util.h"

#define MSG_MAX_BYTES 1000
#define HISTORY_LIMIT 50
#define PREVIEW_BYTES 120

/* One row of the chat list. with == "" is the group room (always entry 0). */
typedef struct {
    char     with[USERNAME_MAX + 1];
    char     last_from[USERNAME_MAX + 1];
    char     last_text[PREVIEW_BYTES + 1];   /* truncated preview */
    char     last_status[10];                /* "sent"/"delivered"/"read" when `me` sent the last DM, else "" */
    uint64_t last_id;                        /* 0 = no messages */
    int64_t  last_ts;
    unsigned unread;
    uint64_t last_in_id;                     /* newest DM from `with` to me (0 if none) */
    uint64_t delivered;                      /* delivered watermark with -> me */
    uint64_t rd;                             /* read watermark (for the group: my own) */
    int      last_deleted;                   /* last message was deleted for everyone */
} conv_summary_t;

/* Persistent message log (<datadir>/messages.log) + receipt log (<datadir>/receipts.log, compacted on start).
   `to` is "" for the group room. Message ids are 1,2,3... in log order (assigned at load time,
   so the log format is unchanged and old logs keep working). */
int  store_init(const char *datadir);
void store_shutdown(void);
/* reply != 0: this message quotes message `reply` (the caller checks store_reply_ok first). */
int  store_add(const char *from, const char *to, const char *text, int64_t ts_ms, uint64_t reply, uint64_t *id_out);

/* May `me` reply to message `reply` inside the conversation with `with` ("" = group)?
   (it must exist, be in that conversation, and not be deleted) */
int  store_reply_ok(const char *me, const char *with, uint64_t reply);
/* Append {"id","from","text"(<=80 bytes),"deleted"} describing a quoted message. */
void store_reply_json(sb_t *out, uint64_t id);

/* Delete a message for everyone. Only its sender may. The text is wiped from memory and scrubbed from
   messages.log (the line stays, so ids don't shift). to_out receives the recipient ("" = group).
   Returns 0 ok, -1 no such message (or already deleted), -2 not yours. */
int  store_delete(const char *user, uint64_t id, char to_out[USERNAME_MAX + 1]);

/* Newest message id of from->to (from == "" : newest group message). 0 if none. */
uint64_t store_last_id(const char *from, const char *to);

/* Append a JSON array of up to `max` messages of one conversation, oldest first.
   with == "" : group room. Otherwise: direct messages between `me` and `with`.
   before != 0 : only messages with id < before. *more = 1 if older messages exist.
   Own DMs carry a "status" field (sent / delivered / read). */
void store_history_json(sb_t *out, const char *me, const char *with, int max, uint64_t before, int *more);

/* Receipt watermarks. "All DMs from `from` to `to` with id <= W are delivered / read."
   For the group room use from == "", to == <reader>: only the read watermark is used.
   Both return 1 if the watermark moved forward. Reading implies delivered. */
int  store_mark_delivered(const char *from, const char *to, uint64_t upto);
int  store_mark_read(const char *from, const char *to, uint64_t upto);
void store_receipts(const char *from, const char *to, uint64_t *delivered, uint64_t *read);

/* Unread messages for `me` in a conversation (with == "" : group; own messages never count). */
unsigned store_unread(const char *me, const char *with);

/* Build the chat list for `me`: entry 0 is the group room, then every DM partner.
   Returns the entry count; *out is malloc'd (caller frees) or NULL on failure (returns 0). */
size_t store_summaries(const char *me, conv_summary_t **out);

/* Last time (ms since epoch) a user's final connection closed; 0 = unknown. */
int64_t store_last_seen(const char *user);
void    store_set_last_seen(const char *user, int64_t ts_ms);
#endif
