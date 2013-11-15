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

#ifndef __CEC_LIB_H__
#define __CEC_LIB_H__

#include <stdint.h>
#include <stdio.h>

#ifndef RESTRICT
#ifdef __GNUC__
#define RESTRICT __restrict__
#else
#define RESTRICT
#endif
#endif

struct cec_hash_s;
typedef struct cec_hash_s cec_hash_t;

typedef void (*cec_apply_element_f)(void *value, void *private);
typedef uint32_t (*cec_hash_element_f)(void *value);
typedef int (*cec_compare_element_f)(void *value1, void *value2);
typedef void (*cec_dump_element_f)(void *value, FILE *file);
typedef void (*cec_free_element_f)(void *value);

extern void cec_free_element(void *element);
extern uint32_t cec_hash_string(void *value);
extern int cec_compare_strings(void *value1, void *value2);
extern void cec_dump_string(void *value, FILE *file);

extern void cec_hash_ctor(cec_hash_t * RESTRICT hash, cec_hash_element_f hash_func, cec_compare_element_f compare_func, cec_free_element_f free_func);
extern cec_hash_t *cec_hash_new(cec_hash_element_f hash_func, cec_compare_element_f compare_func, cec_free_element_f free_func);
extern void cec_hash_dtor(cec_hash_t * RESTRICT hash);
extern void cec_hash_del(cec_hash_t * RESTRICT hash);
extern int cec_hash_add_element(cec_hash_t * RESTRICT hash, void *value);
extern int cec_hash_has_element(cec_hash_t * RESTRICT hash, void *value);
extern void cec_hash_foreach_element(const cec_hash_t * RESTRICT hash, cec_apply_element_f func, void *private);
extern void cec_hash_dump(const cec_hash_t * RESTRICT hash, FILE *file, const char *prefix, cec_dump_element_f func);

#endif /* __CEC_LIB_H__ */
