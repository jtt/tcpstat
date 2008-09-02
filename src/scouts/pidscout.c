/**
 * @file pidscout.c
 * @brief Fill me in 
 * @author Jukka Taimisto
 *
 * @par Copyright
 * Copyright (C) 2006 Jukka Taimisto 
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
 *
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

#define DBG_MODULE_NAME DBG_MODULE_PID

#include "defs.h"
#include "debug.h"
#include "connection.h"
#include "pidscout.h"

#define MAX_PATH_LEN 50
#define INODETAB_INIT_SIZE 10

extern int errno;

/**
 * Get inode from the string of format <code>socket:[&lt;inode&gt;]</code> (the
 * /proc/&lt;pid&gt;/fd/nn link to socket).
 *
 * @note Modifies the string passed as parameter.
 *
 * @param linkstr String containing the socket + inode information.
 * @return The inode read or -1 on error.
 */  
static ino_t get_inode( char *linkstr )
{
        char *start, *end;
        ino_t rv;

        start = strchr( linkstr, '[' );
        end = strchr( linkstr, ']' );
        if ( start == NULL || end == NULL ) {
                WARN( "Could not get inode from %s\n", linkstr );
                return -1;
        }
        *end = '\0';
        rv = strtol( start + 1, NULL, 10 );

        return rv;
}
        

/** 
 * @brief Add inode to pidinfo struct. 
 * Pidinfo struct holds the inodetab. Inodetab size is grown dynamically, the
 * tab is reallocated to double size when it fills up.
 * 
 * @param info_p Pointer to pidinfo struct.
 * @param inode The inode to add.
 */
static void info_add_inode( struct pidinfo *info_p, ino_t inode ) 
{
        if ( info_p->nr_inodes >= info_p->inodetab_size ) {
                /* inodetab full, let's make if bigger */
                info_p->inodetab_size = 2 * info_p->inodetab_size; 
                info_p->inodetab = mem_realloc( info_p->inodetab, info_p->inodetab_size * sizeof( ino_t));
                TRACE( "Inodetab for pid %d increased to %d \n", info_p->pid, info_p->inodetab_size );
        }
        info_p->inodetab[info_p->nr_inodes] = inode;
        info_p->nr_inodes++;

}
/** @defgroup pidscout_grp Functions for gathering process information from /proc */ 
        
/**
 * Initialize new pidinfo struct used for scanning socket inodes for given pid. 
 * @see scan_socket_inodes()
 * @ingroup pidscout_grp
 * @param pid PID for the process to scan (can be 0 if the pid is not yet known).
 * @return Pointer to the freshly allocated pidinfo struct.
 */ 
struct pidinfo *init_pidinfo( int pid )
{
        struct pidinfo *info_p;

        info_p = mem_alloc( sizeof( struct pidinfo ) );
        memset( info_p, 0, sizeof( struct pidinfo ) );
        info_p->pid = pid;
        info_p->inodetab = mem_alloc( INODETAB_INIT_SIZE * sizeof( ino_t ));
        info_p->inodetab_size = INODETAB_INIT_SIZE;
        info_p->grp = group_init(); /* XXX selector */
        info_p->next = NULL;


        return info_p;
}

/**
 * Scan files in <code>/proc/&lt;pid&gt;/fd</code> for given pid and search for
 * sockets. Inodes for the sockets are saved to the pidinfo struct. Old entries
 * in the struct are deleted.
 *
 * @note Program needs to have enough permissions to read the target.
 * @see init_pidinfo()
 * @ingroup pidscout_grp
 *
 * @param info_p Pointer to the pidinfo struct holding the inode information.
 * @return  0 on success, -1 on error.
 */ 
int scout_pid( struct pidinfo *info_p )
{
        char base_path[MAX_PATH_LEN + 1];
        char linkname[MAX_PATH_LEN + 1];

        DIR *dir;
        struct dirent *ent_p;
        int base_path_len, link_len;
        ino_t inode;
        struct stat filestat;
        
        TRACE( "Scanning inodes \n" );
        memset( info_p->inodetab, 0, info_p->inodetab_size * sizeof(ino_t));
        info_p->nr_inodes = 0;

        snprintf( base_path, MAX_PATH_LEN, "/proc/%d/fd", info_p->pid );
        base_path_len = strlen( base_path );
        dir = opendir( base_path );
        if ( dir == NULL ) {
                WARN( "Could not open %s -- process has possibly died\n", base_path );
                return -1;
        }

        ent_p = readdir( dir );
        while ( ent_p != NULL ) {
                snprintf( base_path + base_path_len, MAX_PATH_LEN - base_path_len, 
                                "/%s",ent_p->d_name );
                if ( stat( base_path, &filestat ) != 0 ) {
                       WARN( "stat() failed for %s \n", base_path );
                       goto next;
                }
                if ( ! ( filestat.st_mode & S_IFLNK ) )  {
                        goto next;
                }
                link_len = readlink( base_path, linkname, MAX_PATH_LEN );
                if ( link_len == -1 ) {
                        WARN( "readlink() failed for %s \n", base_path );
                        goto next;
                }
                linkname[link_len] = '\0';
                if ( strstr( linkname, "socket" ) != NULL ) {
                        /* We have found a socket */
                        TRACE( "Found socket (%s->%s)\n", base_path, linkname );
                        inode = get_inode( linkname );
                        TRACE( "Inode %d \n", inode );
                        TRACE( "base_path: %s\n", base_path );
                        info_add_inode( info_p, inode );
                }
next:
                ent_p = readdir( dir );
        }
        closedir( dir );

        TRACE( "Scan done\n" );
        return 0;
}

#ifdef DEBUG
static void dump_pidinfos( struct pidinfo *pinfo_p )
{
        struct pidinfo *iterator = pinfo_p;
        int i;

        DBG( "--[Inodetab dump]-- \n" );

        while( iterator != NULL ) {
                DBG( "{%p}[%d/%s]->{%p}\n",iterator, iterator->pid, iterator->progname, iterator->next );
                for ( i=0; i< iterator->nr_inodes; i++ ) {
                        DBG("\ttab[%d]-%d\n", i,iterator->inodetab[i] );
                }
                iterator=iterator->next;
        }
        DBG( "--[End Inodetab dump]-- \n" );
}
#endif /* DEBUG */



/** 
 * @brief Scout inodes for all pidinfo structures on the linked list. 
 * 
 * @param info_p Pointer to the entry on the list where scan should start.
 * @return 0 if operation was succesfull,  -1 otherwise.
 */
int scan_inodes( struct pidinfo *info_p )
{
        struct pidinfo *iterator = info_p;
        

        while (iterator != NULL ) {
                /* XXX return value */
                TRACE( "Scanning inodes for PID %d\n", iterator->pid );
                if ( scout_pid( iterator ) == -1 ) {
                        DBG( "Process %d has possibly died!\n" );
                        iterator->pid = -1;
                }
                TRACE( "Next ptr %p\n", iterator->next );
                iterator = iterator->next;
        }
#ifdef DEBUG
        dump_pidinfos(info_p);
#endif /* DEBUG */


        return 0;
}




/**
 * Read commandlined for process with given PID. 
 * The commandline is saved to pidinfo struct given as parameter, the struct
 * should contain the PID for process. If the command line can not be read,
 * "unknown" is set as command line. 
 * @ingroup pidscout_grp
 * @param info_p Pointer to pidinfo struct holding the PID for the process.
 */
void scan_cmdline( struct pidinfo *info_p )
{
        int fd;
        char path[MAX_PATH_LEN]; 
        int bytes;

        snprintf( path, MAX_PATH_LEN, "/proc/%d/cmdline", info_p->pid );
        fd = open( path, O_RDONLY );
        if ( fd == -1 ) {
                WARN( "Unable to open %s:%s\n", path, strerror( errno));
                strncpy( info_p->progname,"unknown",PROGNAME_MAX);
                return; 
        }
        bytes = read( fd, info_p->progname, PROGNAME_MAX );
        if ( bytes == -1 ) {
                WARN( "Error in read() : %s\n", strerror( errno));
                strncpy( info_p->progname,"unknown",PROGNAME_MAX);
                close( fd );
                return;
        }
        close( fd );
        info_p->progname[PROGNAME_MAX] = '\0';
        DBG ( "Commandline for process %d:%s\n", info_p->pid, info_p->progname );
        return;
}

/**
 * Free memory allocated for the pidinfo struct returned by scan_inodes().
 * @note The struct is no longer usable after this function returns. 
 * @see init_pidinfo()
 * @ingroup pidscout_grp
 * @param info_p Pointer to the struct to be freed.
 */
void free_pidinfo( struct pidinfo *info_p )
{
        if ( info_p != NULL ) {
                if (info_p->grp) 
                        group_deinit( info_p->grp, 1 );
                        
                mem_free( info_p->inodetab );
                mem_free( info_p );
        }

}

/** 
 * @brief Find pidinfo file containing given inode.
 *
 * First pidinfo file that contains the given inode is returned. 
 * 
 * @ingroup pidscout_grp
 * @param inode Inode to search.
 * @param info_p Pointer to the first pidinfo structure on the list of
 * structures. 
 * @return Pointer to pidinfo file is match is found. 
 */
struct pidinfo *get_pidinfo_by_inode( ino_t inode, struct pidinfo *info_p )
{
        int i;
        struct pidinfo *iterator, *rv;

        rv = NULL;
        iterator = info_p;
        while (iterator != NULL ) {
                TRACE( "Searching inodes of PID %d\n", iterator->pid );
                for( i =0; i < iterator->nr_inodes; i++ ) {
                        TRACE( "tab[%d] %d <--> %d\n", i, iterator->inodetab[i], inode );
                        if ( iterator->inodetab[i] == inode ) {
                                TRACE( "Found match\n" );
                                rv = iterator;
                                return rv;
                               
                        }
                }
                iterator = iterator->next;
        }
        return rv;
}

