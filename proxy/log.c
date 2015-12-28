/*
 * SSLsplit - transparent and scalable SSL/TLS interception
 * Copyright (c) 2009-2014, Daniel Roethlisberger <daniel@roe.ch>
 * All rights reserved.
 * http://www.roe.ch/SSLsplit
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "log.h"

#include "attrib.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

/*
 * Centralized logging code multiplexing thread access to the logger based
 * logging in separate threads.  Some log types are switchable to different
 * backends, such as syslog and stderr.
 */

/*
 * Error log.
 * Switchable between stderr and syslog.
 * Uses logger thread.
 */

static int err_mode = LOG_ERR_MODE_STDERR;

static ssize_t log_err_writecb(UNUSED void *fh, const void *buf, size_t sz)
{
    switch (err_mode) {
    case LOG_ERR_MODE_STDERR:
        return fwrite(buf, sz - 1, 1, stderr);
    case LOG_ERR_MODE_SYSLOG:
        syslog(LOG_ERR, "%s", (const char *)buf);
        return 0;
    }
    return -1;
}

int log_err_printf(const char *fmt, ...)
{
    va_list ap;
    char *buf;
    int rv;

    va_start(ap, fmt);
    rv = vasprintf(&buf, fmt, ap);
    va_end(ap);
    if (rv < 0) return -1;
    log_err_writecb(NULL, (unsigned char *)buf, strlen(buf) + 1);
    free(buf);
    return 0;
}

void log_err_mode(int mode) { err_mode = mode; }
/*
 * Debug log.  Redirects logging to error log.
 * Switchable between error log or no logging.
 * Uses the error log logger thread.
 */

static int dbg_mode = LOG_DBG_MODE_NONE;

int log_dbg_write_free(void *buf, size_t sz)
{
    if (dbg_mode == LOG_DBG_MODE_NONE) return 0;

    log_err_writecb(NULL, buf, sz);
    free(buf);
    return 0;
}

int log_dbg_print_free(char *s) { return log_dbg_write_free(s, strlen(s) + 1); }
int log_dbg_printf(const char *fmt, ...)
{
    va_list ap;
    char *buf;
    int rv;

    if (dbg_mode == LOG_DBG_MODE_NONE) return 0;

    va_start(ap, fmt);
    rv = vasprintf(&buf, fmt, ap);
    va_end(ap);
    if (rv < 0) return -1;
    return log_dbg_print_free(buf);
}

void log_dbg_mode(int mode) { dbg_mode = mode; }
/* vim: set noet ft=c: */
