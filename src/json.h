#ifndef JSON_H
#define JSON_H
#include <stddef.h>

/* Minimal strict JSON object reader. Extracts selected top-level *string*
   fields from an object; everything else is validated and skipped. */
typedef struct {
    const char *key;   /* field name to look for */
    char       *out;   /* destination buffer */
    size_t      cap;   /* size of out (including NUL) */
    int         found; /* set to 1 if present as a string */
} json_field_t;

#define JSON_OK         0
#define JSON_MALFORMED -1
#define JSON_TOO_LONG  -2   /* a requested string didn't fit in its buffer */

/* Parse object in s[0..n). Duplicate requested keys are rejected. */
int json_parse_fields(const char *s, size_t n, json_field_t *fields, size_t nfields);
#endif
