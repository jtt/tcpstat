/**
 * @file defs.h
 * @brief  File holding all system wide defines for the software.
 * @author Jukka Taimisto
 *
 * Copyright (c) 2005, J. Taimisto
 * All rights reserved.
 *  
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: 
 *
 *     - Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer.
 *     - Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     - Neither the name of the author nor the names of its
 *       contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.  
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: defs.h 144 2007-11-05 22:50:43Z jtt $
 */

#ifndef _DEFS_H_
#define _DEFS_H_

#define VERSION "0.1"

/*
#define DEBUG 
#define ENABLE_ASSERTIONS
#define DPRINT_MODULE 
#define DPRINT_STAMP
*/
/*
#define MEM_DBG_MAX_NR_ALLOC 500
#define DEBUG_MEM 
#define DEBUG_ENTER_EXIT 
*/

/* Should be power of 2 */
#define CONNECTION_HASHTABLE_SIZE 256

#define DEBUG_DEFAULT_LEVEL 2 /* WARN */

#define DBG_ERR_TO_STDOUT

/**
 * maximum number of characters on a file name given as a command line
 * parameter. 
 * A bit lame, I know.
 */
#define MAX_FILENAME_LEN 250


#define ADDRSTR_BUFLEN 56

#define ENABLE_RESOLVE_POPUP

#ifdef DEBUG
#ifdef DPRINT_MODULE
/**
 * All modules configured.  Assign the correct module to DBG_MODULE_NAME with
 * define where applicable.  Add module info to dbg_modules array in debug.c.
 * This is the index of the module info in dbg_modules
 */
enum dbg_module {
        DBG_MODULE_MEM = 0,
        DBG_MODULE_UTILS,
        DBG_MODULE_STAT,
        DBG_MODULE_PARSER,
        DBG_MODULE_CONN,
        DBG_MODULE_GUI,
        DBG_MODULE_GRP,
        DBG_MODULE_IF,
        DBG_MODULE_PID,
        DBG_MODULE_TCP,
        DBG_MODULE_FILTER,
        DBG_MODULE_RT,
        DBG_MODULE_VIEW,
        DBG_MODULE_READER,
        DBG_MODULE_GENERIC /* this should always be the last */
};
#endif /* DPRINT_MODULE */
#endif /* DEBUG */

/**
 * Maximum length for interface name 
 */
#define IFNAMEMAX 20

/**
 * Can be used to mark unused parameters in function declaration
 * to silence the compiler.
 */
#define _UNUSED __attribute__((unused))

/* Define this to use getifaddrs() instead of
 * SIOCGIFCONF ioctl() to get the addresses of network interfaces.
 */
#define USE_GETIFADDRS

/* 
 * "features" enabled : 
 *
 * ENABLE_ROUTES - Gather information about routes.
 * ENABLE_FOLLOW_PID - Allow following connections belonging
 * to specified processes.
 * ENABLE_IFSTATS - Gather statistics about interfaces.
 */

#ifdef OPENBSD
/* For OpenBSD, no additional features yet */

#endif /* OPENBSD */
#ifdef OSX
/* For OSX, no additional features yet */
#endif 
#ifdef LINUX
#define ENABLE_ROUTES
#define ENABLE_FOLLOW_PID
#define ENABLE_IFSTATS
#endif /* LINUX */

#endif /* _DEFS_H_ */
