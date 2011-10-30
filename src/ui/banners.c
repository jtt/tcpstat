/**
 * @file banners.c
 * @brief Different banners which can be printed to the ui
 *
 * This module provides the entry point for ncurses based GUI.
 *
 * Copyright (c) 2008, J. Taimisto
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
 * @author Jukka Taimisto
 */ 
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <ncurses.h>


/* #include <arpa/inet.h>  inet_ntop */

#define DBG_MODULE_NAME DBG_MODULE_GUI

#include "defs.h"
#include "debug.h"
#include "connection.h"
#include "stat.h"
#include "scouts.h"
#include "printout_curses.h"

#ifdef DEBUG 

#ifdef DEBUG_MEM
extern unsigned long int mem_dbg_alloc;
extern unsigned long int mem_dbg_alloc_peak;
#endif /* DEBUG_MEM */

/** 
 * @brief Print a line containing debug information.
 * A line containing the info on hashtable and heap usage is printed. 
 * 
 * @param ctx Pointer to the global context.
 */
void gui_print_dbg_banner( struct stat_context *ctx )
{
        int active_buckets = 0;
        struct chashtable *ch;
        int i;

        ch = ctx->chash;
        for( i=0; i < ch->nrof_buckets; i++ ) {
                if ( ch->buckets[i] != NULL ) {
                        active_buckets++;
                }
        }

        //attron( A_REVERSE );
        add_to_linebuf( "DBG: hashtable{%d (%d/%d active)} dimensions(%dx%d)", ch->size, ch->nrof_buckets, active_buckets,COLS,LINES );
#ifdef DEBUG_MEM
        add_to_linebuf(" mem{%dbytes/peak %dbytes}", mem_dbg_alloc, mem_dbg_alloc_peak );
#endif /* DEBUG_MEM */
        write_linebuf();
        //attroff( A_REVERSE );
}

#endif /* DEBUG */


static void write_statnum( int num, char *text )
{
        add_to_linebuf( " %d", num );
        write_linebuf_partial_attr( A_BOLD );
        add_to_linebuf( "%s", text );
        write_linebuf_partial();
}


/** 
 * @brief Print the "main" banner.
 * @ingroup gui_c
 * 
 * @param ctx Pointer to the global context.
 */
void gui_print_banner( struct stat_context *ctx )
{
        time_t now;
        struct tm *tm_p;
#ifdef ENABLE_FOLLOW_PID
        struct pidinfo *info_p;
#endif /* ENABLE_FOLLOW_PID */

        //clear(); /* This is the first line to print */
        reset_ctx();

        //attron( A_REVERSE );
        now = time(NULL);

        tm_p = localtime(&now);

        add_to_linebuf( "%.2d:%.2d:%.2d ", tm_p->tm_hour, 
                        tm_p->tm_min, tm_p->tm_sec );

        add_to_linebuf( "  Grouping:" );
        write_linebuf_partial();

        if ( ctx->common_policy & POLICY_CLOUD ) {
                add_to_linebuf( " Related" );
                write_linebuf_partial_attr( A_BOLD );
        } else if ( ctx->common_policy & POLICY_IF ) {
                add_to_linebuf( " Interface" );
                write_linebuf_partial_attr( A_BOLD );
        } else if ( OPERATION_ENABLED(ctx, OP_FOLLOW_PID) ) {
                add_to_linebuf( "pid" );
                write_linebuf_partial_attr( A_BOLD );
        } else {
                add_to_linebuf(" local" );
                if ( ctx->common_policy & POLICY_LOCAL ) {
                        write_linebuf_partial_attr( A_BOLD );
                } else {
                        write_linebuf_partial();
                }

                add_to_linebuf(" remote" );
                if ( ctx->common_policy & POLICY_REMOTE ){
                        write_linebuf_partial_attr( A_BOLD );
                } else {
                        write_linebuf_partial();
                }

                add_to_linebuf(" address" );
                if ( ctx->common_policy & POLICY_ADDR ) {
                        write_linebuf_partial_attr( A_BOLD );
                } else {
                        write_linebuf_partial();
                }

                add_to_linebuf(" port" );
                if ( ctx->common_policy & POLICY_PORT ) {
                        write_linebuf_partial_attr( A_BOLD );
                } else {
                        write_linebuf_partial();
                }

                add_to_linebuf(" state" );
                if ( ctx->common_policy & POLICY_STATE ) {
                        write_linebuf_partial_attr( A_BOLD );
                } else {
                        write_linebuf_partial();
                }
        }

        if ( OPERATION_ENABLED(ctx,OP_LINGER ) ) 
                add_to_linebuf( " lingering on" );
        write_linebuf();
#ifdef ENABLE_FOLLOW_PID
        if ( OPERATION_ENABLED(ctx, OP_FOLLOW_PID) ) {
                info_p = ctx->pinfo;
                add_to_linebuf("Following PIDs: ");
                write_linebuf_partial();
                while( info_p != NULL ) {
                        if ( info_p->pid != -1 ) {
                                add_to_linebuf("%d ", info_p->pid );
                                write_linebuf_partial_attr(A_BOLD);
                        }
                        info_p = info_p->next;
                }
                write_linebuf();
        }
#endif /* ENABLE_FOLLOW_PID */

        add_to_linebuf( "Connections:");
        write_linebuf_partial();
        write_statnum( ctx->total_count, " total,");
        write_statnum( ctx->new_count, " new,");

        if ( ! OPERATION_ENABLED(ctx, OP_FOLLOW_PID) ) {
                /* we do not know the direction of connections on
                 * "follow pid" mode. 
                 */
                write_statnum( glist_connection_count(ctx->out_groups), " outgoing,");
                write_statnum( glist_connection_count(ctx->listen_groups), " incoming,");
        }

        write_statnum( glist_parent_count( ctx->listen_groups), " listening,");
        write_statnum( get_ignored_count(ctx), " ignored");

        write_linebuf();
        
        //attroff( A_REVERSE );
}

/**
 * Print banner containing the interface stats. 
 * @ingroup gui_c
 * @param ctx Pointer to the global context.
 */
#ifdef ENABLE_IFSTATS
void gui_print_if_banners( struct stat_context *ctx )
{
        struct ifinfo *if_p;
        struct ifinfo_tab *tab_p = ctx->iftab;

        if ( tab_p->size == 0 ) {
                WARN( "Empty interface table\n" );
        }
     
        attron( A_REVERSE );
        add_to_linebuf("\t\t\t Interface statistics \t\t\t");
        write_linebuf();
        attroff( A_REVERSE );


        if_p = tab_p->ifs;
        while( if_p != NULL ) {
                add_to_linebuf( "%4s : RX ", if_p->ifname );
                write_linebuf_partial();
                if (gui_is_enabled(UI_IFSTAT_DIFFS)){
                        add_to_linebuf( "%10llu", if_p->stats.rx_bytes_diff );
                } else {
                        add_to_linebuf( "%10llu", if_p->stats.rx_bytes );
                }
                write_linebuf_partial_attr( A_BOLD );
                add_to_linebuf( " bytes, ");
                write_linebuf_partial();
                if (gui_is_enabled(UI_IFSTAT_DIFFS)) {
                        add_to_linebuf( "%6llu", if_p->stats.rx_packets_diff);
                } else {
                        add_to_linebuf( "%6llu", if_p->stats.rx_packets );
                }
                write_linebuf_partial_attr( A_BOLD );
                add_to_linebuf( " packets" );

                add_to_linebuf( "  TX ", if_p->ifname );
                write_linebuf_partial();
                if (gui_is_enabled(UI_IFSTAT_DIFFS)){
                        add_to_linebuf( "%10llu", if_p->stats.tx_bytes_diff );
                } else {
                        add_to_linebuf( "%10llu", if_p->stats.tx_bytes );
                }
                write_linebuf_partial_attr( A_BOLD );
                add_to_linebuf( " bytes, ");
                write_linebuf_partial();
                if (gui_is_enabled(UI_IFSTAT_DIFFS)){
                        add_to_linebuf( "%6llu", if_p->stats.tx_packets_diff );
                } else {
                        add_to_linebuf( "%6llu", if_p->stats.tx_packets );
                }
                write_linebuf_partial_attr( A_BOLD );
                add_to_linebuf( " packets" );
                write_linebuf();
                add_to_linebuf("       RX ");
                write_linebuf_partial();
                add_to_linebuf( "%6llu", if_p->stats.rx_bytes_sec );
                write_linebuf_partial_attr( A_BOLD );
                add_to_linebuf(" bytes/sec TX ");
                write_linebuf_partial();
                add_to_linebuf( "%6llu", if_p->stats.tx_bytes_sec );
                write_linebuf_partial_attr( A_BOLD );
                add_to_linebuf(" bytes/sec");
                write_linebuf();
                if_p = if_p->next;
        }
}
#endif /* ENABLE_IFSTATS */
                



        

/** 
 * @brief Print banner for incoming connection groups.
 * 
 * @ingroup gui_c
 * @param ctx Pointer to the global context.
 */
void gui_print_in_banner( struct stat_context *ctx )
{
        attron( A_REVERSE );
        if ( OPERATION_ENABLED(ctx, OP_SHOW_LISTEN) ) {
                add_to_linebuf( "\t\t\t Listening and incoming (%d groups )\t\t\t",
                                glist_get_size( ctx->listen_groups));
        } else {
                add_to_linebuf( "\t\t\t Incoming (%d groups )\t\t\t",
                                glist_get_size_nonempty( ctx->listen_groups));
        }

        write_linebuf();
        attroff( A_REVERSE );
}

/** 
 * @brief Print banner for outgoing connection groups.
 * 
 * @ingroup gui_c
 * @param ctx Pointer to the global context
 */
void gui_print_out_banner( struct stat_context *ctx )
{
        attron( A_REVERSE );
        add_to_linebuf( "\t\t\t Outgoing (%d groups )\t\t\t",
                        glist_get_size( ctx->out_groups));
        write_linebuf();
        attroff( A_REVERSE );
}

/** 
 * @brief Print banner for groups in follow pids mode. 
 * @ingroup gui_c
 * 
 * @param info_p Pointer to struct pidinfo holding information for groups.
 */
#ifdef ENABLE_FOLLOW_PID
void gui_print_pid_banner( struct pidinfo *info_p )
{
        attron( A_REVERSE );
        if ( info_p->pid == -1 )
                add_to_linebuf("\t Remaining connections for dead process %s (%d connections)\n",
                             info_p->progname, group_get_size( info_p->grp) );
        add_to_linebuf("\t Connections by %s(%d) (%d connections)", info_p->progname, 
                        info_p->pid, group_get_size( info_p->grp ));
        write_linebuf();
        attroff( A_REVERSE );
}
#endif /* ENABLE_FOLLOW_PID */


