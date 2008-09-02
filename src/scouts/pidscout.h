/**
 * @file pidscout.h
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

/**
 * Maximum length for commandline read from /proc/&lt;pid&gt;/cmdline
 */
#define PROGNAME_MAX 100

/**
 * Structure holding information gathered from /proc entry of given PID 
 */ 
struct pidinfo {
        int pid; /**< PID for the program */ 
        char progname[PROGNAME_MAX]; /**< Name of the program */
        int nr_inodes; /**< Number of socket inodes. */
        ino_t* inodetab; /**< Inodes of all sockets used by the prog */ 
        int inodetab_size; /**< Maximum number of entries in tab */
        struct pidinfo *next; /**< Pointer to next pidinfo struct */
        struct group *grp;/**< Group for connections for this PID */
};

int scout_pid( struct pidinfo *info_p );
int scan_inodes( struct pidinfo *info_p );
void scan_cmdline( struct pidinfo *info_p );
void free_pidinfo( struct pidinfo *info_p );
struct pidinfo *init_pidinfo( int pid );
struct pidinfo *get_pidinfo_by_inode( ino_t inode, struct pidinfo *info_p );
