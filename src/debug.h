/**
 * @file debug.h
 *
 * All debug stuff goes here; or debug.c if necessary. 
 *
 * This file contains all debug macro definitions as well as 
 * function declarations. 
 *
 * Copyright (c) 2002 - 2006, J. Taimisto
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
 * $Id: debug.h 119 2007-06-07 21:05:43Z jtt $
 */

#ifndef _DEBUG_H_
#define _DEBUG_H_

#if defined(DEBUG_MEM) && !defined(DEBUG)
#undef DEBUG_MEM
#endif /*DEBUG_MEM && !DEBUG */

#ifdef DEBUG
/**
 * Enumeration for different debug levels. 
 */ 
enum dbg_level {
        DBG_L_TRACE = 0,
        DBG_L_DEBUG,
        DBG_L_WARN,
        DBG_L_ERR
};

#ifndef DEBUG_DEFAULT_LEVEL
#define DEBUG_DEFAULT_LEVEL DBG_L_TRACE 
#endif /* not DEBUG_DEFAULT_LEVEL */

#ifdef DPRINT_MODULE 
#ifndef DBG_MODULE_NAME 
#define DBG_MODULE_NAME DBG_MODULE_GENERIC

#endif /* DBG_MODULE_NAME not defined */
#endif /* DPRINT_MODULE */




/* XXX 
 * These really should not be used outside debug module,
 * but it is sometimes more convenient, so we export these.
 */
extern FILE *dbg_file;
extern int dbg_initialized;




/*
 * The debug macros
 */ 


#define DEBUG_MSG(s)(fprintf(dbg_initialized?dbg_file:stdout,"DEBUG[ %s:(%d) %s]: %s \n",__FILE__,__LINE__,__FUNCTION__,s))


#ifdef DPRINT_MODULE 
#define TRACE(m, a...)(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_MODULE_NAME,DBG_L_TRACE,__LINE__,__FILE__,__FUNCTION__,m, ## a))
#define DBG(m, a...)(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_MODULE_NAME,DBG_L_DEBUG,__LINE__,__FILE__,__FUNCTION__,m, ## a))
#define DPRINT(m, a...)(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_MODULE_NAME,DBG_L_DEBUG,__LINE__,__FILE__,__FUNCTION__,m, ## a))
#define WARN(m, a...)(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_MODULE_NAME,DBG_L_WARN,__LINE__,__FILE__,__FUNCTION__,m, ## a))
#define ERROR(m, a...)(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_MODULE_NAME,DBG_L_ERR,__LINE__,__FILE__,__FUNCTION__,m, ## a))
#else /* DPRINT_MODULE */
#define TRACE(m, a...)(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_L_TRACE,__LINE__,__FILE__,__FUNCTION__,m, ## a))
#define DBG(m, a...)(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_L_DEBUG,__LINE__,__FILE__,__FUNCTION__,m, ## a))
#define DPRINT(m, a...)(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_L_DEBUG,__LINE__,__FILE__,__FUNCTION__,m, ## a))
#define WARN(m, a...)(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_L_WARN,__LINE__,__FILE__,__FUNCTION__,m, ## a))
#define ERROR(m, a...)(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_L_ERR,__LINE__,__FILE__,__FUNCTION__,m, ## a))
#endif /* DPRINT_MODULE */

#define DEBUG_DUMP(d,l,m)(dbg_dump_data(dbg_initialized?dbg_file:stdout,d,l,m,__FILE__,__LINE__))
#ifdef DPRINT_MODULE
#define DEBUG_XDUMP(d,l,m)(dbg_xdump_data(dbg_initialized?dbg_file:stdout,DBG_MODULE_NAME,d,l,m))
#else /* DPRINT_MODULE */
#define DEBUG_XDUMP(d,l,m)(dbg_xdump_data(dbg_initialized?dbg_file:stdout,d,l,m))
#endif /* DPRINT_MODULE */

#define DBG_INIT(f)(dbg_init(f))
#define DBG_DEINIT()(dbg_deinit())
#define DBG_LEVEL(l)( dbg_set_level(l) )
#ifdef DPRINT_MODULE
#define DBG_MODULE_LEVEL(m,l)( dbg_set_module_level(m,l) )
#endif /* DPRINT_MODULE */


#ifdef DEBUG_ENTER_EXIT
#ifdef DPRINT_MODULE 
#define ENTER_F()(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_MODULE_NAME,DBG_L_TRACE,__LINE__,__FILE__,__FUNCTION__,"ENTER\n"))
#define EXIT_F()(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_MODULE_NAME,DBG_L_TRACE,__LINE__,__FILE__,__FUNCTION__,"EXIT\n")) 
#else /* DPRINT_MODULE */
#define ENTER_F()(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_L_TRACE,__LINE__,__FILE__,__FUNCTION__,"ENTER\n"))
#define EXIT_F()(do_debug_message(dbg_initialized?dbg_file:stdout,DBG_L_TRACE,__LINE__,__FILE__,__FUNCTION__,"EXIT\n")) 
#endif /* DPRINT_MODULE */
#else
#define ENTER_F()
#define EXIT_F()
#endif /* DEBUG_ENTER_EXIT */

#else /* DEBUG */
#define DEBUG_MSG(s)
#define ENTER_F()
#define EXIT_F()
#define TRACE(m, a...)
#define DBG(m, a...)
#define DPRINT(m, a...)
#define WARN(m, a...)
#define ERROR(m, a...)
#define DEBUG_DUMP(d,l,m)
#define DEBUG_XDUMP(d,l,m)
#define DBG_INIT(f)
#define DBG_DEINIT()
#define DBG_LEVEL(l)
#define DBG_MODULE_LEVEL(m,l)
#endif /* DEBUG */

#ifdef ENABLE_ASSERTIONS
#define ASSERT(c) do {\
        if ( ! (c) ) { \
                fprintf(stderr,"Assertion '%s' failed on %s:%d\n",#c,__FILE__,__LINE__);\
                abort();\
        }\
} while(0);

#else /* ENABLE_ASSERTIONS */
#define ASSERT(c)
#endif /* ENABLE_ASSERTIONS */ 

#ifdef USE_SYSLOG
/*
 * LOG messages and such
 */
enum log_level {
        log_level_info,
        log_level_error,
        log_level_bug,
        log_level_rule
};

void log_message(enum log_level, const char *format, ...);
#define LOG(l,m,a...)(log_message(l,m, ## a))
#endif /* USE_SYSLOG */
/*
 * The error messages. The should really be logged
 */ 
#ifdef DBG_ERR_TO_STDOUT
#define ERROR_MSG(f,s)(fprintf(stdout,"ERROR [%s:(%d) %s]: %s \n",__FILE__,__LINE__,f,s))
#else /* DBG_ERR_TO_STDOUT */
#ifdef DEBUG 
#define ERROR_MSG(f,s)(fprintf(dbg_initialized?dbg_file:stdout,"ERROR [%s:(%d) %s]: %s \n",__FILE__,__LINE__,f,s))
#else /* DEBUG */
#ifdef USE_SYSLOG
#define ERROR_MSG(f,s)(log_message(log_level_error,"ERROR [%s: (%d) %s]: %s \n",__FILE__,__LINE__,f,s))
#else /* USE_SYSLOG */
#define ERROR_MSG(f,s)(fprintf(stdout,"ERROR [%s:(%d) %s]: %s \n",__FILE__,__LINE__,f,s))
#endif /* USE_SYSLOG */
#endif /* DEBUG */
#endif /* DBG_ERR_TO_STDOUT */

/*
 * Misc defines, for utility functions
 */ 
#define UI_BYTE_MASK 0x000000ff
#define UI_GET_BYTE(x,j)( (x&(UI_BYTE_MASK<<((j-1)*8)))>>((j-1)*8) )	

/*
 * Functions
 */ 
/*
 * mem_alloc() and mem_free() should always point to the 
 * correct functions to use.
 */ 
#if defined(DEBUG) && defined(DEBUG_MEM)
void *dbg_mem_alloc(const char *f, size_t size);
void dbg_mem_free(const char *f, void *ptr);
void *dbg_mem_realloc( const char *f, void *ptr, size_t size );
void *dbg_mem_zalloc(const char *f, size_t size);
#define mem_alloc(s) dbg_mem_alloc(__FUNCTION__,(s))
#define mem_free(p) dbg_mem_free(__FUNCTION__,(p))
#define mem_realloc(p,s) dbg_mem_realloc(__FUNCTION__,(p),(s))
#define mem_zalloc(s) dbg_mem_zalloc(__FUNCTION__,(s))
void dump_alloc_table( void );

#define DEBUG_SH_MEM 

#else /* DEBUG_MEM && DEBUG*/
void *do_mem_alloc( size_t size );
void do_mem_free( void *ptr );
void *do_mem_realloc( void *ptr, size_t size );
void *do_mem_zalloc( size_t size);
#define mem_alloc(s) do_mem_alloc((s))
#define mem_free(p) do_mem_free((p))
#define mem_realloc(p,s) do_mem_realloc((p),(s))
#define mem_zalloc(s) do_mem_zalloc((s))
#endif /* DEBUG_MEM && DEBUG */
/*
 * Functions used only when DEBUG was set
 */ 
#ifdef DEBUG
void dbg_init(char *filename);
void dbg_deinit( void );
void dbg_set_level( enum dbg_level lvl );
#ifdef DPRINT_MODULE
void dbg_set_module_level( enum dbg_module module, enum dbg_level lvl );
#endif 
#ifdef DPRINT_MODULE
void do_debug_message(FILE* dfile, enum dbg_module module, enum dbg_level level, int line,char *file, const char *function,char *msg, ...);
#else
void do_debug_message(FILE* dfile, enum dbg_level level, int line,char *file, const char *function,char *msg, ...);
#endif /* DPRINT_MODULE */
void dbg_dump_data(FILE* dbgfp, unsigned char *data, int datalen, char *name,
                   char *fname, int line);
#ifdef DPRINT_MODULE
int dbg_xdump_data(FILE *fp,enum dbg_module module, unsigned char *buf, unsigned int len,
               const char *text);
#else /*DPRINT_MODULE*/
int dbg_xdump_data(FILE *fp, unsigned char *buf, unsigned int len,
               const char *text);
#endif /*DPRINT_MODULE */
#endif /* DEBUG */ 

/*
 * Data dumping functions, usable always 
 */ 
void dump_data(unsigned char *data, int datalen, char *name);
int xdump_data(FILE *fp, unsigned char *buf, unsigned int len,
               const char *text);
/*
 * Utility functions, usable always 
 */ 
void str2bytes(char *str,unsigned char *buf, int *buflen);
void i2bytes(int nbr, unsigned char *bytes);

#endif /* _DEBUG_H_ */
