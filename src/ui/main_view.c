/**
 * @file main_view.c
 * @brief Module responsible for printing the information on main view.
 *
 * Copyright (c) 2006 - 2008, J. Taimisto
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

#define DBG_MODULE_NAME DBG_MODULE_VIEW

#include "defs.h"
#include "debug.h"
#include "connection.h"
#include "stat.h"
#include "ifscout.h"
#include "rtscout.h"
#include "pidscout.h" /* need to dereference pidinfo pointer */
#include "printout_curses.h"

/**
 * Table holding the string representations of enum tcp_state.
 */
static char *tcp_stat_str[] = {
        "-",
        "ESTABLISHED", 
        "SYN_SENT",
        "SYN_RECV",
        "FIN_WAIT1",
        "FIN_WAIT2",
        "TIME_WAIT",
        "CLOSE",
        "CLOSE_WAIT",
        "LAST_ACK",
        "LISTEN",
        "CLOSING"
};
/**
 * Table holding the string representations of enum connection_dir.
 */
static char *dir_str[] = {
      "---",
      "-->",
      "<--"
};  
/**
 * Convert a given enum constant to corresponding direction.
 * @param dir The direction.
 * @return string representation of the enum constant. (local static buffer is
 * used, hence don't call multiple times e.g in prinf()).
 */ 
static char *dir_to_string( enum connection_dir dir )
{

        if ( dir > DIR_INBOUND ) {
                dir = DIR_UNKNOWN;
        }
        return dir_str[ dir ];
        
}

/**
 * String representation of enum tcp_state.
 * @param state The enum constant to get string for.
 * @return String containing the string representation of the enum constant.
 */ 
static char *conn_state_to_str( enum tcp_state state ) 
{
        if ( state > TCP_CLOSING ) {
                state = 0;
        }
        return tcp_stat_str[ state ];
}
/** 
 * @brief Get the number of seconds the connection has been active
 * 
 * @param data_p  Pointer to the metadata structure for the connection.
 * @param buf Pointer to the buffer that will receive the string containing the
 * number of seconds the connection has been active
 * @param buflen Length of the buffer.
 * 
 * @return Pointer to the buffer @a buf.
 */
static char *get_live_time( struct conn_metadata *data_p,
               char *buf, int buflen )
{
        time_t now = time( NULL );
        time_t diff = now - data_p->added;

        if ( diff > 60 ) {
                time_t min = diff/60;
                time_t sec = diff % 60;
                snprintf(buf, buflen, "%ld:%.2ld", min, sec );
        } else {
                snprintf( buf, buflen, "%lds", diff );
        }

        return buf;
}



/**
 * Format string used when printing address information to "wide" terminal.
 */
static const char conn_format_widest[] = "%40.40s";
static const char conn_format_wide[] = "%30.30s";
/**
 * Format string used when printing connection information to "narrow"
 * terminal.
 */
static const char conn_format_narrow[] = "%15.15s";

static const char port_format[] = ":%-5hu";
static const char servname_format[] = ":%-5.10s";

/** 
 * @brief Print addresses of the connection on human readable form.
 *
 * The source and destination addresses of the connection are printed on either
 * "dotted decimal" (IPv4) or IPv6 form. If hostname resolution is requested in
 * the gui context, resolve names for numerical hosts (if not done yearlier)
 * and print the resolved names.
 *
 * The connection metadata caries most of the strings, the strings are printed
 * directly to the screen.
 *
 * @bug Formating for different size screens sucks. Port number/servname is not fixed width. 
 * 
 * @param conn_p Pointer to the connection whose addresses to print.
 * strings.
 */
static void print_connection_addrs( struct tcp_connection *conn_p )
{
        const char *fmt;
        int cols;

        if ( gui_resolve_names() && ( ! ( conn_p->metadata.flags & METADATA_RESOLVED)) ) {
                connection_resolve( conn_p );
        }
        cols = gui_get_columns();

        if ( cols < GUI_COLUMN_WIDE_LIMIT ) {
                fmt = conn_format_narrow;
        } else if ( cols < GUI_COLUMN_WIDEST_LIMIT ) {
                fmt = conn_format_wide;
        } else if ( cols >= GUI_COLUMN_WIDEST_LIMIT ) {
               fmt = conn_format_widest;
        } 

        /* Local address, is not resolved */
        add_to_linebuf( fmt, conn_p->metadata.laddr_string );
        add_to_linebuf( port_format, connection_get_port( conn_p, 1 ));

        if ( conn_p->state == TCP_LISTEN ) {
                /* Listening connection, there is no remote end. Just 
                 * fill to keep aligned with proper connections
                 */
                /* direction */
                add_to_linebuf( " %.3s ", "   " );
                /* remote address */
                add_to_linebuf( fmt, " " );
                /* port */
                add_to_linebuf( " %5s", " " );
                return;
        }

        add_to_linebuf( " %.3s ", dir_to_string( conn_p->metadata.dir ));


        if ( gui_resolve_names() && conn_p->metadata.rem_hostname[0] != '\0' ) {
                add_to_linebuf( fmt, conn_p->metadata.rem_hostname );
        } else {
                add_to_linebuf( fmt, conn_p->metadata.raddr_string );
        }
        if ( gui_resolve_names() && conn_p->metadata.rem_servname[0] != '\0' ) {
                add_to_linebuf( servname_format, conn_p->metadata.rem_servname );
        } else {
                add_to_linebuf( port_format, connection_get_port( conn_p, 0 ));
        }
}



/**
 * Print a line containing the connection information. 
 * @ingroup gui_c
 * @bug Layout of the line is messed up the address fields should change
 * dynamically according to the available row length.
 * @param conn_p Pointer to the connection which information should be printed.
 */ 
static void gui_print_connection( struct tcp_connection *conn_p )
{
        char update_symbol, live_time[10];

        if ( conn_p->state == TCP_DEAD ) {
                /* lingering, already dead connection */
                update_symbol = '#';
                attron( A_DIM );
        } else if ( metadata_is_state_changed( conn_p->metadata ) ){
                update_symbol = '*';
                //attron( A_UNDERLINE );
        }  else if ( metadata_is_new( conn_p->metadata ) ) {
                update_symbol = '+';
                attron( A_STANDOUT );
        } else {
                update_symbol = ' ';
        }

        add_to_linebuf( "%c %4s   ",update_symbol, 
                        conn_p->metadata.ifname?conn_p->metadata.ifname:"N/A");
        print_connection_addrs( conn_p );
        if ( gui_do_routing() && gui_get_columns() >= GUI_COLUMN_WIDEST_LIMIT  ) {
                if ( conn_p->metadata.route != NULL ) {
                        if ( rtinfo_is_on_local_net( conn_p->metadata.route )) {
                                add_to_linebuf( "%20.20s", "on local net");
                        } else { 
                                add_to_linebuf( " via %15.15s", conn_p->metadata.route->addr_str);
                        }
                } else {
                        add_to_linebuf(" via %15.15s","-" );
                }
        }

        write_linebuf_partial();
        add_to_linebuf( " %-12s", conn_state_to_str( conn_p->state ));
        if ( metadata_is_state_changed( conn_p->metadata ) ) 
                write_linebuf_partial_attr(A_BOLD);


        add_to_linebuf( " %-9s", get_live_time( &(conn_p->metadata),live_time,10 ) );
        write_linebuf();

        attrset(A_NORMAL);


}


/** 
 * @brief Print information for a connection group.
 * A line containing information for each connection on the group is printed.
 *
 * @bug The printing of banner is really, really limited. And broken. 
 *
 * @ingroup gui_c
 * 
 * @param grp Pointer to the group that the info should be printed.
 * @param print_parent non-zero if information should be printed about the parent.
 * @param print_banner non-zero if a "banner" for the group should be printed.
 */
static void gui_print_group( struct group *grp, int print_parent, int print_banner )
{
        struct tcp_connection *conn_p;

        uint16_t policy = group_get_policy( grp );

        if ( print_banner && (print_parent || group_get_size( grp ) > 0) ) {


                attron( A_UNDERLINE );
                if ( policy & POLICY_IF ) {
                        add_to_linebuf( "Connections in interface %s\n", grp->grp_filter->ifname );
                } else if ( policy & POLICY_CLOUD ) {
                        add_to_linebuf("Related ( %d connections)", group_get_size( grp ));

                } else if ( (policy & (POLICY_REMOTE | POLICY_LOCAL ) ) != 0 ) {
                        conn_p = group_get_first_conn( grp );
                        if ( conn_p == NULL ) {
                                /* Can happen. Especially with incoming
                                 * groups, try to use parent instead.
                                 */
                                conn_p = group_get_parent( grp );
                        }
                        /* I know that conn_p be can be NULL here. I
                         * just don't care, since it would mean that we
                         * have group without connections and without
                         * parent, we should not be printing that and
                         * we deserve to die with segmentation fault on
                         * that.
                         */
                        add_to_linebuf( "Connections to " );
                        if ( policy & POLICY_ADDR ) {
                                if ( policy & POLICY_LOCAL ) {
                                        add_to_linebuf( "%s ", conn_p->metadata.laddr_string );
                                } else {
                                        add_to_linebuf( "%s ", conn_p->metadata.raddr_string );
                                }
                        }
                        if ( policy & POLICY_PORT ) 
                                add_to_linebuf( " port %d ", connection_get_port( conn_p, 
                                                        policy & POLICY_LOCAL ));

                        add_to_linebuf( " (%d connections)", group_get_size( grp) );
                } else  if ( policy & POLICY_STATE ) {
                        add_to_linebuf( "Connections on state %s\n", 
                                        conn_state_to_str( grp->grp_filter->state ));
                        add_to_linebuf( " (%d connections)", group_get_size( grp) );
                } else {

                        add_to_linebuf( "+   Group: %d connections", group_get_size( grp ));
                }


                write_linebuf();
                attroff( A_UNDERLINE);
        }
         
        conn_p = group_get_parent( grp );
        if ( conn_p ) {
                if ( print_parent ) 
                        gui_print_connection( conn_p );
                /* XXX */
                metadata_clear_flags( conn_p->metadata );
        }

        conn_p = group_get_first_conn( grp );

        while ( conn_p != NULL ) {
                gui_print_connection( conn_p );
                /* XXX */
                metadata_clear_flags( conn_p->metadata );
                conn_p = conn_p->next;
        } 

        return;
}

/**
 * @defgroup mview Main view functions 
 */

/** 
 * @brief Handle user input when main view is active.
 *
 * This function is called when a user command is received and the command is
 * not any of the generic commands and main view is active.
 *
 * @ingroup mview
 * 
 * @param ctx Pointer to the main context.
 * @param key The kay pressed.
 * 
 * @return 1 if the key was main view command, 0 if not.
 */
int main_input( struct stat_context *ctx, int key )
{
        int rv = 1;

        switch( key ) {

                case 'l' :
                        TRACE( "Toggling display of listen & In groups \n" );
                        ctx->display_listen = ! ctx->display_listen;
                        break;
                case 'L' :
                        TRACE( "Setting lingering on" );
                        ctx->do_linger = ! ctx->do_linger;
                        break;
                        case 'A' :
                        TRACE( "Switching grouping to remote address" );
                        if ( gui_get_current_view() == MAIN_VIEW )
                                switch_grouping( ctx, POLICY_REMOTE | POLICY_ADDR );
                        break;
                case 'a' :
                        TRACE( "Swithing the groupint to remote address and port" );
                        if ( gui_get_current_view() == MAIN_VIEW )
                                switch_grouping( ctx, POLICY_REMOTE | POLICY_ADDR | POLICY_PORT );
                        break;
                case 'P' :
                        TRACE( "Switching grouping to remote port " );
                        if ( gui_get_current_view() == MAIN_VIEW )
                                switch_grouping( ctx, POLICY_REMOTE | POLICY_PORT );
                        break;
                case 'c' :
                        TRACE("Swithcing to cloud (port) mode" );
                        if ( gui_get_current_view() == MAIN_VIEW )
                                switch_grouping( ctx, POLICY_CLOUD | POLICY_REMOTE | POLICY_PORT );
                        break;
                case 'S' :
                        TRACE( "Switching grouping to state " );
                        if ( gui_get_current_view() == MAIN_VIEW )
                                switch_grouping( ctx, POLICY_STATE );
                        break;
                default :
                        WARN( "Unkown key pressed %c (%d), ignoring\n",(char)key,key );
                        rv = 0;
                        break;
        }
        return rv;
}

/** 
 * @brief Initialize the main view. 
 *
 * This function should be called every time the main view is to be activated.
 * After this function has been called, the main_update() function can be
 * called to update the UI.
 *
 * @ingroup mview
 * 
 * @param ctx Pointer to the global context.
 * 
 * @return -1 on error, 0 on success.
 */
int init_main_view( struct stat_context *ctx )
{
        gui_set_current_view( MAIN_VIEW );
        return 0;
}




/** 
 * @brief Print information on follow pid -mode. 
 * 
 * For every PID we are following, all connections are printed. 
 * @see do_print_stat()
 * 
 * @param ctx Pointer to main context.
 */
static void do_print_stat_pids( struct stat_context *ctx )
{
        struct pidinfo *info_p;

        gui_print_banner( ctx );
        if ( ctx->do_ifstats )
                gui_print_if_banners( ctx );
#ifdef DEBUG
        gui_print_dbg_banner( ctx );
#endif /* DEBUG */
        info_p = ctx->pinfo;
        while ( info_p != NULL ) {
                if ( group_get_size( info_p->grp ) > 0 ) {
                        gui_print_pid_banner( info_p );
                        gui_print_group( info_p->grp, 0,0 );
                }
                info_p = info_p->next;
        }
}
/** 
 * @brief Print the information for all connections. 
 * Call relevant gui functions for printing the information, this function does
 * not call gui_draw() to actually update the displayed GUI.
 * 
 * @param ctx Pointer to main context.
 */
static void do_print_stat( struct stat_context *ctx )
{
        struct group *grp;

        gui_print_banner( ctx );
        if ( ctx->do_ifstats ) 
                gui_print_if_banners( ctx );
#ifdef DEBUG
        gui_print_dbg_banner( ctx );
#endif /* DEBUG */
        gui_print_in_banner( ctx );

        grp = glist_get_head( ctx->listen_groups );
        while ( grp != NULL ) {
                gui_print_group( grp, ctx->display_listen,1 );
                grp = grp->next;
        }
        gui_print_out_banner( ctx );
        grp = glist_get_head( ctx->out_groups );
        while ( grp != NULL ) {
                gui_print_group( grp,1,1 );
                grp = grp->next;
        }
}

/** 
 * @brief Update the UI with according to main view.
 *
 * This function updates the UI with latest information gathered by the scouts. 
 * 
 * @ingroup mview
 *
 * @param ctx Pointer to the global context.
 * 
 * @return -1 on error, 0 on success.
 */
int main_update( struct stat_context *ctx )
{
        if ( ctx->follow_pid )
                do_print_stat_pids( ctx );
        else
                do_print_stat( ctx );

        return 0;
}
