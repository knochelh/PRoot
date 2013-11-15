/* 
 *  This software is delivered under the terms of the MIT License
 *
 *  Copyright (c) 2009-2012 STMicroelectronics Inc.
 *
 *  Permission is hereby granted, free of charge, to any person
 *  obtaining a copy of this software and associated documentation
 *  files (the "Software"), to deal in the Software without
 *  restriction, including without limitation the rights to use,
 *  copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the
 *  Software is furnished to do so, subject to the following
 *  conditions:
 *
 *  The above copyright notice and this permission notice shall be
 *  included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *  OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *  HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *  OTHER DEALINGS IN THE SOFTWARE. 
 */

/*
 * This module defines types and methods for a generic hash table
 * implementation.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "cec_lib.h"

/*
 * Identifier.
 */
#define LIBCEC_LIBNAME "libcec"
#define LIBCEC_VERSION "1.0.0"
const char cec_version_string[] = LIBCEC_LIBNAME" version "LIBCEC_VERSION;

/*
 * Definition of some useful attributes.
 */
#ifndef RESTRICT
#ifdef __GNUC__
#define RESTRICT __restrict__
#else
#define RESTRICT
#endif
#endif

#ifndef HIDDEN
#if defined(__GNUC__) && __GNU_MAJOR__ >= 3 
#define HIDDEN __attribute__((visibility("hidden")))
#else
#define HIDDEN
#endif
#endif

#ifndef INTERNAL
#if defined(__GNUC__) && __GNU_MAJOR__ >= 3 
#define INTERNAL __attribute__((visibility("internal")))
#else
#define INTERNAL
#endif
#endif

#ifndef INLINE
#ifdef __GNUC__
#define INLINE __inline__
#else
#define INLINE
#endif
#endif

#ifndef UINT32_FMT
#define UINT32_FMT "u"
#endif

/*
 * Logging facilities.
 *
 * Logger levels are: 
 * FATAL = 0, ERROR = 1, WARN = 2, INFO = 3, INFO2 = 4, INFO3 = 5
 *
 */
#define FATAL(...) { if (logger_attributes.la_level >= 0) \
      logger_log(0,__VA_ARGS__); }
#define ERROR(...) { if (logger_attributes.la_level >= 1) \
      logger_log(1,__VA_ARGS__); }
#define WARN(...) { if (logger_attributes.la_level >= 2) \
      logger_log(2,__VA_ARGS__); }
#define INFO(...) { if (logger_attributes.la_level >= 3) \
      logger_log(3,__VA_ARGS__); }
#define INFO2(...) { if (logger_attributes.la_level >= 4) \
      logger_log(4,__VA_ARGS__); }
#define INFO3(...) { if (logger_attributes.la_level >= 5) \
      logger_log(5,__VA_ARGS__); }
#define FILE_OR_STDERR(file) ((file) == NULL? stderr: (file))

typedef struct {
  int la_level;
  FILE *la_logfile; /* Defaults to stderr if NULL. */
} logger_attributes_t;
logger_attributes_t logger_attributes = { 2, NULL };

INTERNAL void
logger_log(int level, const char *str, ...)
{
  static const char *prefix[] = { "FATAL", "ERROR", "WARNING", "INFO",
				  "INFO2", "INFO3" };
  va_list l;
  FILE *logfile = FILE_OR_STDERR(logger_attributes.la_logfile);
  va_start(l, str);
  fprintf(logfile, "%s: ", prefix[level]);
  vfprintf(logfile, str, l);
  va_end(l);
  fprintf(logfile, "\n");
}

#ifdef TEST
INTERNAL void
logger_unittest(FILE *filein, FILE *fileout)
{
  /* Set except_continue attribute, for coverage of assertion functions. */
  logger_attributes_t default_logger_attributes = logger_attributes;
  logger_attributes.la_logfile = fileout;
  FATAL("Just a message for the unittest");
  ERROR("Just a message for the unittest");
  WARN("Just a message for the unittest");
  INFO("Just a message for the unittest");
  INFO2("Just a message for the unittest");
  INFO3("Just a message for the unittest");
  logger_attributes.la_level = 5;
  WARN("Just a message for the unittest");
  INFO("Just a message for the unittest");
  INFO2("Just a message for the unittest");
  INFO3("Just a message for the unittest");
  logger_attributes = default_logger_attributes;
}
#endif

/*
 * Use this macro for assertions/preconds/postcond, disabled in debug mode.
 */
#ifdef NDEBUG
#define ASSERT(exp) (void)0
#else
#define ASSERT(exp) except_ensure(exp, #exp, __FILE__, __LINE__)
#endif

/*
 * Use this macro for fatal errors that must be reported, 
 * bad malloc, exceptions for instance. Always active.
 */
#define ENSURE(exp) except_ensure(exp, #exp, __FILE__, __LINE__)

/*
 * Helper function for error macros.
 */
typedef struct {
  void (*ea_abort)(void);
} except_attributes_t;
except_attributes_t except_attributes = { &abort };

INTERNAL void
except_ensure(int exp, const char *str, const char *file, int line)
{
  if (!exp) {
    FATAL("at %s:%d: assertion failed: %s", file, line, str);
    except_attributes.ea_abort();
  }
}

INTERNAL void
except_continue(void)
{
  WARN("Ignoring previous assertion, continuing.");
}

#ifdef TEST
INTERNAL void
except_unittest(FILE *filein, FILE *fileout)
{
  /* Set except_continue attribute, for coverage of assertion functions. */
  except_attributes_t default_except_attributes = except_attributes;
  logger_attributes_t default_logger_attributes = logger_attributes;
  except_attributes.ea_abort = &except_continue;
  logger_attributes.la_logfile = fileout;
  fprintf(fileout, "Next line is a unit test output, not an actual errors\n");
  ENSURE(1 == 1);
  ENSURE(0 == 1);
  except_attributes = default_except_attributes;
  logger_attributes = default_logger_attributes;
}
#endif

/*
 * Allocation functions, specify type and number of elements to allocate.
 */
#define ALLOC_N(type,num) (type *)malloc((num)*sizeof(type))
#define CALLOC_N(type,num) (type *)calloc(num, sizeof(type))
#define REALLOC_N(type,ptr,num) (type *)realloc((ptr), (num)*sizeof(type))
#define STRDUP(str) strdup(str)
#define FREE(ptr) free((void *)ptr)

/*************************************************************
 * Utilitary functions
 *************************************************************/
void
cec_free_element(void *value)
{
  FREE(value);
}

/*************************************************************
 * Hash implementation.
 *************************************************************/

uint32_t
cec_hash_string(void *value)
{
  const char *str = (const char *)value;
  uint32_t hash = 0;
  while (*str++) {
    hash += (uint32_t)*str;
  }
  return hash;
}

int
cec_compare_strings(void *value1, void *value2)
{
  return strcmp((const char *)value1, (const char *)value2) == 0;
}

void
cec_dump_string(void *value, FILE *file)
{
  fprintf(file, "%s", (const char *)value);
}

typedef struct {
  void *the_value;
} cec_hash_element_t;

typedef struct {
  uint32_t thk_key;
} cec_hash_key_t;

typedef struct {
  cec_hash_element_t the_element;
  cec_hash_key_t the_key;
  int32_t the_next;
} cec_hash_entry_t;
#define CEC_HASH_ENTRY_EMPTY 0
#define CEC_HASH_ENTRY_NOLINK -1

struct cec_hash_s {
  cec_hash_entry_t *th_hash;
  uint32_t th_hash_size;
  uint32_t th_hash_count;
  cec_hash_element_f th_hash_func;
  cec_compare_element_f th_compare_func;
  cec_free_element_f th_free_func;
};

typedef struct {
  uint32_t tha_hash_grow_size;
} cec_hash_attributes_t;
cec_hash_attributes_t cec_hash_attributes = {10003};

void
cec_hash_ctor(cec_hash_t * RESTRICT hash, cec_hash_element_f hash_func, cec_compare_element_f compare_func, cec_free_element_f free_func)
{
  hash->th_hash_size = cec_hash_attributes.tha_hash_grow_size;
  hash->th_hash_count = 0;
  hash->th_hash = CALLOC_N(cec_hash_entry_t, hash->th_hash_size);
  hash->th_hash_func = hash_func;
  hash->th_compare_func = compare_func;
  hash->th_free_func = free_func;
}

cec_hash_t *
cec_hash_new(cec_hash_element_f hash_func, cec_compare_element_f compare_func, cec_free_element_f free_func)
{
  cec_hash_t *hash;
  hash = ALLOC_N(cec_hash_t, 1);
  cec_hash_ctor(hash, hash_func, compare_func, free_func);
  return hash;
}

void
cec_hash_dtor(cec_hash_t * RESTRICT hash)
{
  cec_hash_foreach_element(hash, (cec_apply_element_f)hash->th_free_func, NULL);
  FREE(hash->th_hash);
}

void
cec_hash_del(cec_hash_t * RESTRICT hash)
{
  cec_hash_dtor(hash);
  FREE(hash);
}

INTERNAL uint32_t
cec_hash_compute_hash(cec_hash_t * RESTRICT hash, void *value)
{
  return hash->th_hash_func(value);
}

INTERNAL int
cec_hash_compare_elements(cec_hash_t * RESTRICT hash, void *value1, void *value2)
{
  return hash->th_compare_func(value1, value2);
}

INTERNAL int cec_hash_add_element(cec_hash_t * RESTRICT hash, void *value);

INTERNAL void
cec_hash_grow_hash(cec_hash_t * RESTRICT hash)
{
  int i;
  cec_hash_t new_hash;
  /* Add one to keep value odd. */
  new_hash.th_hash_size = hash->th_hash_size * 2 + 1; 
  new_hash.th_hash_count = 0;
  new_hash.th_hash = CALLOC_N(cec_hash_entry_t, new_hash.th_hash_size);
  new_hash.th_hash_func = hash->th_hash_func;
  new_hash.th_compare_func = hash->th_compare_func;
  new_hash.th_free_func = hash->th_free_func;
  for (i = 0; i < hash->th_hash_size; i++) {
    if (hash->th_hash[i].the_next != CEC_HASH_ENTRY_EMPTY) {
      cec_hash_add_element(&new_hash, 
			   hash->th_hash[i].the_element.the_value);
    }
  }
  FREE(hash->th_hash);
  hash->th_hash = new_hash.th_hash;
  hash->th_hash_size = new_hash.th_hash_size;
  hash->th_hash_count = new_hash.th_hash_count;
}

INTERNAL int
cec_hash_get_entry(cec_hash_t * RESTRICT hash, void *value, uint32_t *entry_ptr)
{
  uint32_t key;
  uint32_t entry;
  int found = 0;

  key = cec_hash_compute_hash(hash, value);
  entry = key % hash->th_hash_size;
  if (hash->th_hash[entry].the_next != CEC_HASH_ENTRY_EMPTY) {
    if (cec_hash_compare_elements(hash, hash->th_hash[entry].the_element.the_value, value)) {
      found = 1;
    } else {
      while (hash->th_hash[entry].the_next != CEC_HASH_ENTRY_NOLINK) {
	entry += hash->th_hash[entry].the_next;
	if (cec_hash_compare_elements(hash, hash->th_hash[entry].the_element.the_value, value)) {
	  found = 1;
	  break;
	}
      }
    }	
  }
  if (entry_ptr != NULL) 
    *entry_ptr = entry;
  
  return found;
}

int
cec_hash_add_element(cec_hash_t * RESTRICT hash, void *value)
{
  uint32_t entry, next_entry;
  int32_t i;
  if (cec_hash_get_entry(hash, value, &entry))
    return 0;

  for (i = 0, next_entry = entry; i < hash->th_hash_size; i++, next_entry = (next_entry + 1) % hash->th_hash_size) {
    if (hash->th_hash[next_entry].the_next == CEC_HASH_ENTRY_EMPTY) 
      break;
  }
  if (hash->th_hash[next_entry].the_next != CEC_HASH_ENTRY_EMPTY ||
      3*hash->th_hash_count  > 2*hash->th_hash_size /* Hash if full at 2/3 of size. */) {
    cec_hash_grow_hash(hash);
    return cec_hash_add_element(hash, value);
  }
  if (next_entry != entry) {
    hash->th_hash[entry].the_next = next_entry - entry;
  }
  hash->th_hash[next_entry].the_element.the_value = value;
  hash->th_hash[next_entry].the_next = CEC_HASH_ENTRY_NOLINK;
  hash->th_hash_count++;
  return 1;
}

int
cec_hash_has_element(cec_hash_t * RESTRICT hash, void *value)
{
  return cec_hash_get_entry(hash, value, NULL);
}

void
cec_hash_foreach_element(const cec_hash_t * RESTRICT hash, cec_apply_element_f func, void *private)
{
  int i;
  for (i = 0; i < hash->th_hash_size; i++)
    if (hash->th_hash[i].the_next != CEC_HASH_ENTRY_EMPTY)
      func(hash->th_hash[i].the_element.the_value, private);
}

void
cec_hash_dump(const cec_hash_t * RESTRICT hash, FILE *file, const char *prefix, cec_dump_element_f func)
{
  int i;
  char *edge_prefix;
  file = FILE_OR_STDERR(file);
  if (hash == NULL) {
    fprintf(file, "%s!!None\n", prefix);
    return;
  }
  edge_prefix = ALLOC_N(char, strlen(prefix) + 10 + 1);
  sprintf(edge_prefix, "%s      ", prefix);
  fprintf(file, "%sth_hash_size: %"UINT32_FMT"\n", prefix, hash->th_hash_size);
  fprintf(file, "%sth_hash_count: %"UINT32_FMT"\n", prefix, hash->th_hash_count);
  if (hash->th_hash_count == 0) {
    fprintf(file, "%sth_elements: []\n", prefix);
  } else {
    fprintf(file, "%sth_elements:\n", prefix);
    for (i = 0; i < hash->th_hash_size; i++) {
      if (hash->th_hash[i].the_next != CEC_HASH_ENTRY_EMPTY) {
	fprintf(file, "%s    ", prefix);
	func(hash->th_hash[i].the_element.the_value, file);
	fprintf(file, "\n");
      }
    }
  }
  FREE(edge_prefix);
}

#ifdef TEST

INTERNAL void
cec_hash_unittest(FILE *filein, FILE *fileout)
{
  cec_hash_t *hash;

  fprintf(fileout, "hash null:\n");
  cec_hash_dump(NULL, fileout, "  ", &cec_dump_string);
  hash = cec_hash_new(&cec_hash_string, &cec_compare_strings, &cec_free_element);
  fprintf(fileout, "hash empty:\n");
  cec_hash_dump(hash, fileout, "  ", &cec_dump_string);
  cec_hash_add_element(hash, STRDUP("a string"));
  cec_hash_add_element(hash, STRDUP("astring"));
  cec_hash_add_element(hash, STRDUP("bstring"));
  cec_hash_add_element(hash, STRDUP("cstring"));
  cec_hash_add_element(hash, STRDUP("dstring"));
  cec_hash_add_element(hash, STRDUP(""));
  fprintf(fileout, "hash dump:\n");
  cec_hash_dump(hash, fileout, "  ", &cec_dump_string);
  
  if (cec_hash_has_element(hash, ""))
    fprintf(fileout, "has element ''\n");

  if (!cec_hash_has_element(hash, "a"))
    fprintf(fileout, "does not have element 'a'\n");

  fprintf(fileout, "hash foreach dump:\n");
  cec_hash_foreach_element(hash, (cec_apply_element_f)&cec_dump_string, fileout);
  fprintf(fileout, "\n");
  cec_hash_del(hash);
}
#endif

#ifdef TEST
int
main(int argc, char *argv[])
{
  /* Force some attributes to be low for better coverage. */
  cec_hash_attributes.tha_hash_grow_size = 2;
  
  logger_unittest(stdin, stdout);
  except_unittest(stdin, stdout);
  cec_hash_unittest(stdin, stdout);
  return 0;
}
#endif
