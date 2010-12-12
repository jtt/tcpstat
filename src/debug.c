/**
 * @file debug.c 
 *
 * @brief All debug relaetd stuff are here
 *
 * This is debug module version 2
 *
 * The debug functions and macros will be usable when DEBUG is defined. Four
 * debug levels are available: TRACE, DEBUG, WARN and ERROR. The messages on
 * each level are printed with TRACE(), DBG() (or DPRINT), WARN() and ERROR()
 * macros. These macros can be used "printf" -like. DBG_SET_LEVEL() macro can
 * be used to set debugging level (all messages below the set level are
 * suppressed). DBG_INIT() macro can be called (with filename argument) to set
 * a file where debug output is printed, is DBG_INIT() is not called, debug
 * messages will be printed to stdout.  DBG_DENIT() can be called to close the
 * file (further debug messages are printed to stdout. 
 *
 * A file called defs.h will be included, it is assumed to contain all
 * necessary definitions for configuring the debugging module. NOTE: one must
 * include defs.h before including debug.h, yes that is stubid.
 *
 *
 * There are several modifiers for debugging:
 * <ul>
 * <li> if DEBUG_MEM is defined, then additional information on heap memory
 * usage is printed. Additional functions for memory leak debugging are
 * available.</li>
 * <li> if DEBUG_ENTER_EXIT is defined, macros ENTER_F() and EXIT_F() can be
 * used to display function enter and exit points, messages are printed on
 * TRACE level. </li>
 * <li> if DPRINT_STAMP is defined a timestamp is printed with each debug
 * message.</li>
 * <li> if DPRINT_MODULE is defined, name of the module is printed with each
 * debug message.  The module name should be defined in dbg_modules enum on
 * defs.h, printable name and default level for the module should be set to
 * dbg_modules array on debug.c. Setting the global debug level will set the
 * level for all modules.  </li>
 * <li> if USE_SYSLOG is defined, LOG() macro can be used to log mesages
 * through syslog facility.</li>
 * </ul>
 *
 * debug.h file contains the macros that should be used for debugging. No, they
 * are not properly documented. My bad.
 *  
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
 * $Id: debug.c 169 2008-06-01 07:16:22Z jtt $
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <ctype.h>
#include <time.h>

#include "defs.h"
#include "debug.h"

/**
 * @defgroup debugs Functions for doing debug
 */

/**
 * @defgroup utils Utility functions, in debug.c for some reason.
 */ 


#ifdef DEBUG

#ifdef DPRINT_MODULE 
/** 
 * @brief Structure containig module spcecific information
 */
struct dbg_module_info {
        const char name[10];/**< printable name of the module */
        enum dbg_level level;/**< default debug level for the module */
};

/** 
 * @brief All debugging modules and their info
 * This array is indexed by the dbg_module enums, and should contain the
 * printable string for the module name and default debugging level.
 */
struct dbg_module_info dbg_modules[] = {
        {"MEM",DEBUG_DEFAULT_LEVEL},
        {"UTILS",DBG_L_ERR},
        {"STAT",DEBUG_DEFAULT_LEVEL},
        {"PARSER",DEBUG_DEFAULT_LEVEL},
        {"CONN",DEBUG_DEFAULT_LEVEL},
        {"GUI",DEBUG_DEFAULT_LEVEL},
        {"GRP",DEBUG_DEFAULT_LEVEL},
        {"IF",DEBUG_DEFAULT_LEVEL},
        {"PID",DEBUG_DEFAULT_LEVEL},
        {"TCP",DEBUG_DEFAULT_LEVEL},
        {"FILTER", DEBUG_DEFAULT_LEVEL},
        {"RTINFO", DEBUG_DEFAULT_LEVEL},
        {"VIEW", DEBUG_DEFAULT_LEVEL },
        {"GENERIC",DEBUG_DEFAULT_LEVEL},
};
#endif /* DPRINT_MODULE */

/**
 * @var dbg_file 
 * @brief Pointer to the file descriptor used for debug file
 * If this is NULL, then debug messages are printed to stdout
 *
 */  
FILE *dbg_file = NULL;

/**
 * @var dbg_initialized
 * @brief This variable is set to 1 if debugs are written to file
 */  
int dbg_initialized = 0;

/**
 * @enum dbg_level 
 * @brief Current debug level.
 */
static enum dbg_level dbg_current_level = DEBUG_DEFAULT_LEVEL; 

/**
 * Set the filename for debug file
 *
 * The file with given name is opened and all debugs will be written to
 * this file.
 * This should be used from DBG_INIT() macro, not directly.
 */ 
static void dbg_set_file(char *name)
{
        if ( dbg_initialized && dbg_file != NULL ) {
                fclose(dbg_file);
        }
        dbg_file = fopen(name,"w"); 
        if ( dbg_file == NULL ) {
                fprintf(stderr,"%s : Can not open debug file!\n",__FUNCTION__);
        } else {
                dbg_initialized = 1;
        }
}

/**
 * Close the debug file
 *
 */  
static void dbg_close_file( void )
{
        if ( dbg_initialized && dbg_file != NULL ) {
                fflush(dbg_file);
                fclose(dbg_file);
                dbg_file = NULL;
        }
}

/**
 * Deinitialize the debugging system. If debugs have been written to a file,
 * the file is closed. 
 */
void dbg_deinit( void )
{
#ifdef DEBUG_MEM
        dump_alloc_table();
#endif /* DEBUG_MEM */
        dbg_close_file();
        dbg_initialized = 0;
}


/**
 * Initialize debuggin framework, name of the file where debugs will be written
 * can be given as parameter. 
 * This function should not be called directly, DBG_DEINIT should be used
 * instead.
 * @param filename Name of the debug file, NULL for stdout
 */
void dbg_init(char *filename)
{
        if (filename != NULL)
                dbg_set_file(filename);

        atexit(dbg_deinit);
}

/**
 * Set the debug level.
 * This should be used by the DBG_LEVEL() macro 
 *
 *  @param lvl New debug level.
 */ 
void dbg_set_level( enum dbg_level lvl ) 
{
#ifdef DPRINT_MODULE
        int i;
        for ( i=0; i<= DBG_MODULE_GENERIC ; i++ ) {
                dbg_modules[i].level = lvl;
        }
#endif /* DPRINT_MODULE */
        dbg_current_level = lvl;

}

#ifdef DPRINT_MODULE

/** 
 * @brief Set debug level for given module.
 * 
 * @param module Module to set the level for.
 * @param lvl Level to set for the module.
 */
void dbg_set_module_level( enum dbg_module module, enum dbg_level lvl )
{
        if ( module > DBG_MODULE_GENERIC )
                return;

        dbg_modules[module].level = lvl;
}
#endif /* DPRINT_MODULE */

/** 
 * @brief Wrapper for xdump_data(), used in debugging macros.
 * @ingroup debugs
 * 
 * @bug Hard coded level of DEBUG.
 * @see xdump_data()
 *
 * @param fp File pointer to dump the data.
 * @param module Name of the debugging module printing the message (if enabled).
 * @param buf Buffer to dump
 * @param len Length of the data to dump.
 * @param text Information text to be shown with the dump.
 * @return 0
 */
#ifdef DPRINT_MODULE
int dbg_xdump_data(FILE *fp, enum dbg_module module, unsigned char *buf, unsigned int len,
               const char *text)
#else /* DPRINT_MODULE */
int dbg_xdump_data(FILE *fp, unsigned char *buf, unsigned int len,
               const char *text)
#endif /* DPRINT_MODULE */
{
#ifdef DPRINT_MODULE
        if ( dbg_modules[module].level > DBG_L_DEBUG )
                return 0;
#else /* DPRINT_MODULE */
        if ( dbg_current_level > DBG_L_DEBUG ) 
                return 0;
#endif /* DPRINT_MODULE */
        
        return xdump_data( fp, buf, len, text );
        
}

         
/**
 * Dumps given data to debug file.
 *
 * @ingroup debugs
 * This function should not be used directly, use macro
 * DEBUG_DUMP() instead.
 *
 *@param dbgfp Pointer to debug file handle DEBUG_DUMP() sets this
 *automagically 
 *@param data Pointer to the data
 *@param datalen Length of given data in bytes
 *@param name "Name" of the data. Will be printed before the dump
 *@param fname Name of the calling function DEBUG_DUMP() sets this
 * automagically.
 *@param line Number of the line this function is called from, DEBUG_DUMP()
 * sets this automagically.
 */

void dbg_dump_data(FILE* dbgfp, unsigned char *data, int datalen, char *name,
                   char *fname, int line)
{
	int i = 1;
	unsigned char *ptr;

	fprintf(dbgfp,"DEBUG[%s (%d) %s (%d bytes):]\n",fname,
                line,name,datalen);
	ptr = data;
	while( i <= datalen ) {
		fprintf(dbgfp," %.2x",*ptr);
		if ( i % 8 == 0 ) {
			fprintf(dbgfp,"\n");
		}
		ptr++;
		i++;
	}
	fprintf(dbgfp,"\n");
}
/*
 * Misc. debug functions 
 */ 
#ifdef DPRINT_STAMP

/**
 * Generate timestamp for printing with the debug message.
 *
 * @param buf Buffer to write the stamp to.
 * @param size Size of the buffer.
 */ 
static void dbg_stamp( char *buf, unsigned int size  ) 
{
        struct tm *tmp;
        time_t now;

        now = time( NULL );

        tmp = localtime( &now );

        snprintf( buf, size, "{%.2d:%.2d.%.2d}", tmp->tm_hour, tmp->tm_min, tmp->tm_sec );

}
#endif /* DPRINT_STAMP */

/** 
 * String representation of debug levels.
 */
char dbg_level_str[4][6] = {
        {"TRACE"},
        {"DEBUG"},
        {"WARN"},
        {"ERR"}
};


/**
 * extended debug printout,
 * @ingroup debugs
 * Used by debug macros (TRACE(),DBG(),DPRINT(),WARN(), ERR() ).
 *
 * @param dfile FILEpointer pointing to debug file
 * @param module Name of the debugging module printing the message (if enabled).
 * @param level The debug level for this message. If this is smaller than
 * dbg_current_level, the message is not printed.
 * @param line Number of the line where this call was made, set by debug macros.
 * @param file Name of the file where this call was made, set by debug macros.
 * @param function Name of the function where the call was made, set by debug macros.
 * @param msg Format string for the message to print 
 */
#ifdef DPRINT_MODULE 
void do_debug_message(FILE* dfile, enum dbg_module module, enum dbg_level level, 
                int line,char *file, const char *function,char *msg, ...)
#else 
void do_debug_message(FILE* dfile, enum dbg_level level, 
                int line,char *file, const char *function,char *msg, ...)
#endif 
{
        va_list args;
#ifdef DPRINT_STAMP
        char stamp[15];
#endif /* DPRINT_STAMP */

#ifdef DPRINT_MODULE
        if ( level < dbg_modules[module].level ) 
                return;
#else /* DPRINT_MODULE */
        if ( level < dbg_current_level ) {
               return;
        } 
#endif /* DPRINT_MODULE */
        
#ifdef DPRINT_STAMP
        dbg_stamp( stamp,15);
#ifdef DPRINT_MODULE 
        fprintf(dfile,"%s-{%s/%s} [%s:(%d) %s]:",stamp,dbg_modules[module].name,dbg_level_str[level],file,line,function);
#else /* DPRINT_MODULE */
        fprintf(dfile,"%s-%s[%s:(%d) %s]:",stamp,dbg_level_str[level],file,line,function);
#endif /* DPRINT_MODULE */ 
#else /* DPRINT_STAMP */
#ifdef DPRINT_MODULE 
        fprintf(dfile,"{%s/%s} [%s:(%d) %s]:",dbg_modules[module].name,dbg_level_str[level],file,line,function);
#else /* DPRINT_MODULE */
        fprintf(dfile,"%s[%s:(%d) %s]:",dbg_level_str[level],file,line,function);
#endif /* DPRINT_MODULE */
#endif /* DPRINT_STAMP */
        va_start(args,msg);
        vfprintf(dfile,msg,args);
        va_end(args);
	fflush(dfile);

}

/* Memory debugging functions */

#ifdef DEBUG_MEM
#ifdef DPRINT_STAMP
#undef DBG_MODULE_NAME
#define DBG_MODULE_NAME DBG_MODULE_MEM
#endif /* DPRINT_STAMP */
/* 
 * All global symbols and variables defined here
 *  must have prefix mem_dbg
 */
#ifndef MEM_DBG_MAX_NR_ALLOC
/**
 * @def MEM_DBG_MAX_NR_ALLOC
 * @brief Maximum number of allocation slots on alloc_table
 */ 
#define MEM_DBG_MAX_NR_ALLOC 100
#endif 

/**
 * @def MEM_DBG_MAXNAME
 * @brief Maximum length of function name
 * 
 */ 
#define MEM_DBG_MAXNAME 40

typedef enum mem_dbg_flags{ MEM_DBG_UNUSED, MEM_DBG_USED} mem_dbg_flags;
        
struct mem_dbg {
        char fname[MEM_DBG_MAXNAME];
        size_t size;
        void *ptr;
        mem_dbg_flags flag;
};

struct mem_dbg alloc_table[MEM_DBG_MAX_NR_ALLOC];
/**
 * @var mem_dbg_alloc
 * @brief ammount of memory allocated currently
 */ 
unsigned long int mem_dbg_alloc = 0;
/**
 * @var mem_dbg_alloc_peak
 * @brief The peak ammount of memory allocated
 */ 
unsigned long int mem_dbg_alloc_peak = 0;

/**
 * Add malloc info to the memory debug table.
 * This function is used by the memory debug macros and should not
 * be used directly.
 *
 * @param name Name of the function doing the malloc.
 * @param size Size of the allocation.
 * @param ptr Pointer to the start of the alloced memory area.
 *  
 */

static void add_dbg_table(const char *name, size_t size, void *ptr)
{
        int i=0;

        while ( i < MEM_DBG_MAX_NR_ALLOC && alloc_table[i].flag == MEM_DBG_USED ) 
                i++;

        if ( i == MEM_DBG_MAX_NR_ALLOC ) {
                ERROR_MSG(__FUNCTION__,"alloc_table is full, increase MEM_DBG_MAX_NR_ALLOC");
                return;
        } else {
                strcpy(alloc_table[i].fname,name); /* XXX */
                alloc_table[i].size = size;
                alloc_table[i].ptr = ptr;
                alloc_table[i].flag = MEM_DBG_USED;
                mem_dbg_alloc = mem_dbg_alloc + size;
                if ( mem_dbg_alloc > mem_dbg_alloc_peak ) {
                        mem_dbg_alloc_peak = mem_dbg_alloc;
                        DPRINT("mem_dbg_alloc_peak grown to %ld \n",mem_dbg_alloc_peak);
                }
        }
        return;
}


/**
 * Remove memory allocation info from the memory debug table.
 * This function is used by the memory debug macros and should not
 * be used directly.
 *
 * @param ptr Pointer to the memory region to be freed.
 */ 
static void rem_dbg_table(void *ptr)
{
        int i = 0;

        while ( i < MEM_DBG_MAX_NR_ALLOC && alloc_table[i].ptr != ptr )
                i++;

        if ( i == MEM_DBG_MAX_NR_ALLOC ) {
                ERROR("Unable to find pointer which was freed\n");
        } else if ( alloc_table[i].ptr == ptr ) {
                mem_dbg_alloc = mem_dbg_alloc - alloc_table[i].size;
                alloc_table[i].ptr = NULL;
                alloc_table[i].flag = MEM_DBG_UNUSED;
        } 
        return;
}

/**
 * Dump the contents of memory debug table
 *
 * The current state of the memory debug table is printed to the 
 * debug file.
 */ 
void dump_alloc_table( void )
{
        int i;
        int cnt =0;
        DPRINT("--=[ Dumping alloc table ]=--\n");
        for ( i=0; i< MEM_DBG_MAX_NR_ALLOC; i++ ){
                if ( alloc_table[i].flag == MEM_DBG_USED ) {
                        DPRINT("--[%d\t %s [%p](%d bytes)\n",i
                               ,alloc_table[i].fname,alloc_table[i].ptr,alloc_table[i].size);
                                cnt = cnt + alloc_table[i].size;
                }
        }
        DPRINT("Total unfreed memory %d bytes (mem_dbg_alloc = %ld)\n",cnt,mem_dbg_alloc);
        DPRINT("Memory usage peak %ld bytes\n",mem_dbg_alloc_peak);
        DPRINT("--=[End of dump]=--\n");
}

/*
 * The memory allocation routines with mem_debug stuff
 */

/**
 * Allocate memory with memory debugging enabled
 * @ingroup debugs
 * This function should not be used directly.
 * @see do_mem_alloc
 * @param f Name of the function doing the allocation.
 * @param size Number of bytes to allocate
 * @return Pointer to the allocated block
 */ 
void *dbg_mem_alloc(const char *f, size_t size )
{
        void *ptr;

        ptr = (void *)malloc( size );
#ifdef ENABLE_ASSERTIONS
        ASSERT( ptr != NULL );
#else
        abort();
#endif /* ENABLE_ASSERTIONS */

        add_dbg_table(f,size,ptr);
        DPRINT("%s allocated %d bytes (allocated to %p)\n",f,size,ptr);
        return ptr;
}

/**
 * Reallocate memory with memory debugging enabled.
 * @ingroup debugs 
 * This function should not be used directly.
 * @see do_mem_realloc
 * @param f name of the function doing the allocation.
 * @param ptr Pointer to the memory to reallocate.
 * @param size Number of bytes for the reallocated memory.
 * @return Pointer to allocated block (may differ from @a ptr).
 */
void *dbg_mem_realloc( const char *f, void *ptr, size_t size ) 
{
        void *nptr ;

        nptr = (void *)realloc(ptr, size );
#ifdef ENABLE_ASSERTIONS
        ASSERT( ptr != NULL );
#else
        abort();
#endif /* ENABLE_ASSERTIONS */
        rem_dbg_table( ptr );
        add_dbg_table( f, size, nptr );
        DBG( "%s reallocated %d bytes (allocated to %p,was %p)\n",f,size,nptr,ptr );
        return nptr;
} 
/**
 * Free memory
 * @ingroup debugs
 * This function should not be used directly.
 * @see do_mem_free
 * @param f Name of the function doing the call
 * @param ptr Pointer to the block to free
 */ 
void dbg_mem_free(const char *f, void *ptr ) 
{

        DPRINT("DEBUG_MEM: %s freed memory (freeing from %p)\n",f,ptr);

        if ( ptr == NULL ) {
                ERROR("trying to free NULL pointer\n");
                return;
        } else {
                free( ptr );
        }
        rem_dbg_table(ptr);
}
#endif /* DEBUG_MEM */
#ifdef DPRINT_STAMP
#undef DBG_MODULE_NAME
#endif /* DPRINT_STAMP */

#endif /* DEBUG */

/*
 * NO DEBUGGING FUNCTIONS PASS THIS POINT
 */


/*
 * Logging functions. These functions log messages to some logging
 * system.
 */

#ifdef USE_SYSLOG
void log_message(enum log_level lvl, const char *format, ...)
{
        va_list args;
        va_start(args,format);

        switch ( lvl ) {

                case log_level_info :
                        vsyslog(LOG_INFO,format,args);
                        break;

                case log_level_error :
                        vsyslog(LOG_ERR,format,args);
                        break;

                case log_level_bug :
                        vsyslog(LOG_ERR,format,args);
                        break;

                case log_level_rule :
                        vsyslog(LOG_WARNING,format,args);
                        break;

                default :
                        vsyslog(LOG_INFO,format,args);
                        break;

        }
        va_end(args);
}

#endif /* USE_SYSLOG */ 

#if defined(DEBUG) && defined(DPRINT_MODULE)
#define DBG_MODULE_NAME DBG_MODULE_UTILS
#endif /* DEBUG && DPRINT_MODULE */
         

/*
 * Memory allocation routines with no memory debugs enabled.
 */ 
/**
 * Allocate memory.
 * @ingroup utils
 * wrapper for malloc with error checking. This function should no be
 * used directly. Macro mem_alloc() should be used for all memory
 * allocation, it points either to this or to dbg_mem_alloc().   
 *
 *@param size number of bytes to allocate
 *@return pointer to allocated memory
 */
void *do_mem_alloc( size_t size )
{
        void *ptr;

        ptr = (void *)malloc( size );
#ifdef ENABLE_ASSERTIONS
        ASSERT( ptr != NULL );
#else
        abort();
#endif /* ENABLE_ASSERTIONS */
        return ptr;
}


/** 
 * @brief Wrapper for realloc with error checking. 
 * @ingroup utils
 * This function should not be used directly. Macro mem_realloc() should be
 * used for memory realloction, it points to this function or
 * dbg_mem_realloc().
 *
 * @param ptr Pointer for the block to reallocate.
 * @param size Size for the reallocation.
 * @return Pointer to reallocated memory (may differ from @a ptr).
 */
void *do_mem_realloc( void *ptr, size_t size ) 
{
        void *nptr;

        nptr = (void *)realloc( ptr, size );
#ifdef ENABLE_ASSERTIONS
        ASSERT( nptr != NULL );
#else
        abort();
#endif /* ENABLE_ASSERTIONS */
        return nptr;
}
/**
 * Free memory
 * @ingroup utils
 * wrapper for free with error checking
 * This function should no be
 * used directly. Macro mem_free() should be used for all memory
 * allocation, it points either to this or to dbg_mem_free().   
 *@param ptr pointer to memory to be freed
 */
void do_mem_free( void *ptr ) 
{
        if ( ptr == NULL ) {
                ERROR("Trying to free NULL pointer!");
                return;
        } else {
                free( ptr );
        }
}

/*
 * Utility functions, these have nothing to do with debug actually
 * and should be moved to some other file.
 */ 

/**
 * Converts an given hex number from string to unsigned
 * char buffer.
 * @ingroup utils
 * 
 *@param str The string containing the number
 *@param buf Data will be put here 
 *@param buflen This will receive the length of output data
 */

void str2bytes(char *str,unsigned char *buf, int *buflen)
{
	int len = strlen(str);
	int i;
	unsigned char *ptr;

	ptr = buf; 
	for (i=0; i < len; i++ ) {
		if ( '0' <= str[i] && str[i] <= '9' ) {
			*ptr = str[i]^0x30;
		} else if ( 'a'<= str[i] && str[i]<='f' ) {
			*ptr = str[i]- 'a' + 10;
                } else if ( 'A' <= str[i] && str[i] <= 'F' ) {
                        *ptr = tolower( str[i] ) - 'a' + 10;
		} else {
			ERROR_MSG("str2bytes","Wrong characters in string!");
		}
		if (str[i+1] == '\0' ) {
			break;
		}
		*ptr = *ptr<<4;

		i++;
			
		if ( '0' <= str[i] && str[i] <= '9' ) {
			*ptr = *ptr|(str[i]^0x30);
		} else if ( 'a'<= str[i] && str[i] <='f' ) {
			*ptr = *ptr|((str[i] - 'a' + 10));
                } else if ( 'A' <= str[i] && str[i] <= 'F' ) {
                        *ptr = *ptr | ( tolower( str[i] ) - 'a' + 10 );
		} else {
			ERROR_MSG("str2bytes","Wrong characters in string!");
		}
		
		ptr++;
	}
#if 0
#ifdef DEBUG
	dump_data(buf,len%2==0?len/2:len/2+1,"[str2bytes] Data out");
#endif
#endif 
	*buflen = len%2==0?len/2:len/2+1;
}
/**
 * Converts given bytestring to string 
 * @ingroup utils
 * Does no memory allocation...
 *@param bytes The bytestring
 *@param str The string 
 *@param bytelen of the bytestring 
 */

int bytes2str(unsigned char *bytes,char *str,int bytelen)
{
	int i;
	unsigned char *ptr;
	char *str_tmp;
	
	ptr = bytes;
	str_tmp = str;
	for (i=0; i < bytelen; i++ ) {
		sprintf(str_tmp,"%.2x",*ptr);
		ptr++;
		str_tmp += 2;
	}
	
	return 0;
}
/**
 * Returns byte representation of (unsigned) integer
 *
 * @ingroup utils
 * The bytes are in big endian(?) format (bytes[0] = msb).
 *
 *@param nbr The integer to convert
 *@param bytes Pointer to the place where bytes are placed
 */

void i2bytes(int nbr, unsigned char *bytes)
{
	int i;

	for( i=0; i < 4; i++ ) {
		bytes[i] = UI_GET_BYTE(nbr,i);
	}

}
/*
 * Data dumping functions
 */  

/**
 * Dumps given data to stdout
 *
 *@ingroup utils
 *@param data Pointer to the data
 *@param datalen Length of given data in bytes
 *@param name "Name" of the data. Will be printed before the dump
 */

void dump_data(unsigned char *data, int datalen, char *name)
{
	int i = 1;
	unsigned char *ptr;

	printf("[%s (%d bytes):]\n",name,datalen);
	ptr = data;
	while( i <= datalen ) {
		printf(" %.2x",*ptr);
		if ( i % 8 == 0 ) {
			printf("\n");
		}
		ptr++;
		i++;
	}
	printf("\n");
}
/**
 * Dumps given data in "standard" hexdump format
 *
 * @ingroup utils
 *
 * @param fp Pointer to filepointer to use, if NULL then stdout is used
 * @param buf Pointer to the data
 * @param len Length of the data in bytes
 * @param text Message to print before dumping the data
 */ 
int xdump_data(FILE *fp, unsigned char *buf, unsigned int len,
               const char *text)
{
        unsigned char *bufptr;
        char line[80] = "\n";
        char tmp_data[30];
        char tmp_ascii[10];
        char *lineptr;
        unsigned int cnt;
        int s = 0;

        if ( buf == NULL || len == 0 ) {
                return 0;
        }
        if ( fp == NULL ) {
                fp = stdout;
        }

        fprintf(fp,"\n[%s (%d bytes):]\n",text,len);
        bufptr = buf;
        cnt = 0;
        lineptr = line;
        while( cnt < len ) {
               if ( s == 0 ) {
                       if ( cnt != 0 ) {
                               snprintf(lineptr,80,"\t%s\t%s\n",tmp_data,
                                        tmp_ascii);
                               fprintf(fp,"%s",line);
                               tmp_data[0] = '\0';
                               tmp_ascii[0] = '\0';
                       }
                        snprintf(line,80,"%.4x",cnt);
                        lineptr = line+4;
               }
               snprintf(tmp_data+(s*3),30,"%.2x ",*bufptr);
               if ( ' ' <= (char)*bufptr && (char)*bufptr <= '~') {
                       snprintf(tmp_ascii+s,10,"%c",(char)*bufptr);
               } else {
                       snprintf(tmp_ascii+s,10,".");
               }
               cnt++;
               s = cnt%8; 
               bufptr++;
        }
        if ( s != 0 ) {
                /* XXX
                 * Fill the data buffer for formating...
                 */
                for ( ; s<8; s++ ) {
                        snprintf(tmp_data+(s*3),80,"   ");
                }
                /* Write the last line */
                snprintf(lineptr,80,"\t%s\t%s\n",tmp_data,tmp_ascii);
                fprintf(fp,"%s\n",line);
        } else if ( tmp_data[0] != '\0' ) {
                snprintf( lineptr, 80, "\t%s\t%s\n", tmp_data, tmp_ascii );
                fprintf( fp, "%s\n", line );
        }
        return 0;
}
