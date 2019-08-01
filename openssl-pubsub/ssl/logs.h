/** 
 * @file logs.h
 * @author Hyunwoo Lee
 * @date 21 Feb 2018
 * @brief This file is to define log messages
 */

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>

#define SUCCESS 1
#define FAILURE -1

#ifdef DEBUG
int log_idx;
#define psdebug(format, ...) \
  fprintf(stderr, "[tls-ps] %s:%s:%d " format "\n", __FILE__, __func__, __LINE__, ## __VA_ARGS__)
#else
#define psdebug(format, ...)
#endif /* DEBUG */

#ifdef DEBUG
#define psprint(msg, buf, start, end, interval) \
  fprintf(stderr, "[tls-ps] %s: %s (%d bytes) \n", __func__, msg, end - start); \
  for (log_idx=start; log_idx<end; log_idx++) \
  { \
    fprintf(stderr, "%02X ", buf[log_idx]); \
    if (log_idx % interval == (interval - 1)) \
      fprintf(stderr, "\n"); \
  } \
  fprintf(stderr, "\n");
#else
#define psprint(msg, buf, start, end, interval) 
#endif /* DEBUG */

#ifdef FINFO
#define fstart(format, ...) \
  fprintf(stderr, "[tls-ps] Start: %s:%s : " format "\n", __FILE__, __func__, ## __VA_ARGS__)
#define fend(format, ...) \
  fprintf(stderr, "[tls-ps] End: %s:%s : " format "\n", __FILE__, __func__, ## __VA_ARGS__)
#define ferr() \
  fprintf(stderr, "[tls-ps] Error: %s:%s:%d\n", __FILE__, __func__, __LINE__)
#else
#define fstart(format, ...)
#define fend(format, ...)
#define ferr()
#endif /* FINFO */

#ifdef MEASURE
#define mtime(format, ...) \
  fprintf(stderr, "[Time] " format "\n", ## __VA_ARGS__)
#else
#define mtime(format, ...)
#endif /* MEASURE */

unsigned long get_current_microseconds();

#endif /* __MB_LOG__ */
