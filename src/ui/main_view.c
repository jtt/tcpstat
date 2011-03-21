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
#include "scouts.h"
#include "printout_curses.h"

/*
 * Symbols shown on UI for some connection situations.
 */
/**
 * Dead (lingering) connection
 */
#define SYMBOL_DEAD '#'
/**
 * Connection state has changed
 */
#define SYMBOL_NEW_STATE '*'
/**
 * New connection.
 */
#define SYMBOL_NEW '+'
/**
 * Warning about the connection requested.
 */
#define SYMBOL_WARN '!'
/*
 * default symbol shown
 */
#define SYMBOL_DEFAULT ' ' 

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
#ifdef LINUX
#define LONG_TIME_FMT "%ld:%.2ld"
#define TIME_FMT "%lds"
#endif /* LINUX */
#ifdef OPENBSD
/* time_t, it seems, is not long */
#define LONG_TIME_FMT "%d:%.2d"
#define TIME_FMT "%ds"
#endif /* OPENBSD */
#ifdef OSX
#define LONG_TIME_FMT "%ld:%.2ld"
#define TIME_FMT "%lds"
#endif /* OSX */

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
                snprintf(buf, buflen, LONG_TIME_FMT, min, sec );
        } else {
                snprintf( buf, buflen, TIME_FMT, diff );
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
static const char conn_format_narrow_rt[] = "%11.11s";

static const char port_format[] = ":%-5hu";
static const char servname_format[] = ":%-5.5s";

#ifdef ENABLE_ROUTES
static const char via_narrow_format[] = " %6.6s";
static const char via_wide_format[] = " %19.19s";
static const char via_wide_format_a[] = " via %15.15s";
#endif /* ENABLE_ROUTES */

/** 
 * @brief Get the format string which is used to print the connection address information
 * 
 * @return Format string.
 */
static const char *format_string_for_addr()
{
        int cols;
        const char *fmt;

        cols = gui_get_columns();

        if ( cols < GUI_COLUMN_WIDE_LIMIT ) {
                if ( gui_do_routing() )
                        fmt = conn_format_narrow_rt;
                else 
                        fmt = conn_format_narrow;
        } else if ( cols < GUI_COLUMN_WIDEST_LIMIT ) {
                fmt = conn_format_wide;
        } else if ( cols >= GUI_COLUMN_WIDEST_LIMIT ) {
               fmt = conn_format_widest;
        } 
        return fmt;
}




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

        if ( gui_resolve_names() && ( ! ( conn_p->metadata.flags & METADATA_RESOLVED)) ) {
                connection_resolve( conn_p );
        }
        fmt = format_string_for_addr();

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
 * @brief Print the routing information of connection to the screen
 * 
 * @param conn_p pointer to connection whose routing information should be
 * printed.
 */
#ifdef ENABLE_ROUTES
static void print_rt_info( struct tcp_connection *conn_p )
{
        if ( conn_p->metadata.route == NULL ) {
                if ( gui_get_columns() < GUI_COLUMN_RT_WIDE_LIMIT ) 
                        add_to_linebuf( via_narrow_format, "-" );
                else
                        add_to_linebuf( via_wide_format, "-" );

                return;
        }
        if ( gui_get_columns() < GUI_COLUMN_RT_WIDE_LIMIT ) {
                if ( rtinfo_is_on_local_net( conn_p->metadata.route ) ) 
                        add_to_linebuf( via_narrow_format, "on net" );
                else 
                        add_to_linebuf( via_narrow_format, "via gw" );
        } else {
                if ( rtinfo_is_on_local_net( conn_p->metadata.route ) ) 
                        add_to_linebuf( via_wide_format, "on local net" );
                else  
                        add_to_linebuf( via_wide_format_a, conn_p->metadata.route->addr_str );
        }
}
#endif /* ENABLE_ROUTES */




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
                update_symbol = SYMBOL_DEAD;
                attron( A_DIM );
        } else if ( metadata_is_state_changed( conn_p->metadata ) ){
                update_symbol = SYMBOL_NEW_STATE;
                //attron( A_UNDERLINE );
        }  else if ( metadata_is_new( conn_p->metadata ) ) {
                update_symbol = SYMBOL_NEW;
                attron( A_STANDOUT );
        } else if ( metadata_is_warn( conn_p->metadata)) {
                update_symbol = SYMBOL_WARN;
        } else {
                update_symbol = SYMBOL_DEFAULT;
        }

        add_to_linebuf( "%c %4s   ",update_symbol, 
                        conn_p->metadata.ifname?conn_p->metadata.ifname:"N/A");
        print_connection_addrs( conn_p );
#ifdef ENABLE_ROUTES
        if ( gui_do_routing() )
                print_rt_info( conn_p );
#endif /* ENABLE_ROUTES */

        write_linebuf_partial();
        add_to_linebuf( " %-12s", conn_state_to_str( conn_p->state ));
        if ( metadata_is_state_changed( conn_p->metadata ) ) 
                write_linebuf_partial_attr(A_BOLD);


        add_to_linebuf( " %-9s", get_live_time( &(conn_p->metadata),live_time,10 ) );
        write_linebuf();

        attrset(A_NORMAL);


}

/**
 * Print the titlebar containing the column information for the printed connections
 */
static void print_titlebar()
{
        const char *fmt = format_string_for_addr();

        add_to_linebuf( " %4s   ","Inf");
        add_to_linebuf( fmt,"Local address");
        add_to_linebuf( " %5s", "Port" );
        add_to_linebuf( " %3s ", "Dir" );
        add_to_linebuf( fmt, "Remote address");
        add_to_linebuf( " %5s", "Port" );
#ifdef ENABLE_ROUTES
        if ( gui_do_routing() ) {
                /* XXX : we really should not use numbers here */
                if ( gui_get_columns() < GUI_COLUMN_RT_WIDE_LIMIT )
                        add_to_linebuf( via_narrow_format, "Route");
                else 
                        add_to_linebuf( via_wide_format, "Route");
        }
#endif /* ENABLE_ROUTES */
        add_to_linebuf( " %-12s", "State" );
        add_to_linebuf( " %-9s", "Time" );

        write_linebuf_partial_attr( A_REVERSE );
        write_linebuf();
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
        if ( conn_p && print_parent ) 
                gui_print_connection( conn_p );

        conn_p = group_get_first_conn( grp );

        while ( conn_p != NULL ) {
                gui_print_connection( conn_p );
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
                        OPERATION_TOGGLE(ctx, OP_SHOW_LISTEN);
                        break;
                case 'L' :
                        TRACE( "Setting lingering on" );
                        OPERATION_TOGGLE( ctx, OP_LINGER);
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
#ifdef ENABLE_ROUTES 
                case 'R' :
                        TRACE("Toggling routing");
                        gui_toggle_routing();
                        break;
#endif /* ENABLE_ROUTES */
                default :
                        WARN( "Unkown key pressed %c (%d), ignoring\n",(char)key,key );
                        rv = 0;
                        break;
        }
        return rv;
}

void main_print_help() 
{
        attron( A_UNDERLINE );
        add_to_linebuf("\tMain view commands:");
        write_linebuf();
        attroff( A_UNDERLINE );
        add_to_linebuf(" l  ");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" Toggle display of listening \"connections\"");
        write_linebuf();
        add_to_linebuf(" L  ");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" Toggle lingering of closed connections");
        write_linebuf();
#ifdef ENABLE_ROUTES 
        add_to_linebuf(" R  ");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" Toggle displaying of routing information");
        write_linebuf();
#endif /* ENABLE_ROUTES */
        write_linebuf();
        add_to_linebuf("  Commands for switching grouping of outgoing connections");
        write_linebuf();
        add_to_linebuf(" a");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" group by remote address and port  ");
        write_linebuf_partial();
        add_to_linebuf("A");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" group by remote address");
        write_linebuf();
        add_to_linebuf(" P");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" group by remote port  ");
        write_linebuf_partial();
        add_to_linebuf("S");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" group by connection state");
        write_linebuf();
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
int init_main_view( _UNUSED struct stat_context *ctx )
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
#ifdef ENABLE_FOLLOW_PID
static void do_print_stat_pids( struct stat_context *ctx )
{
        struct pidinfo *info_p;

        info_p = ctx->pinfo;
        while ( info_p != NULL ) {
                if ( group_get_size( info_p->grp ) > 0 ) {
                        gui_print_pid_banner( info_p );
                        print_titlebar();
                        gui_print_group( info_p->grp, 0,0 );
                }
                info_p = info_p->next;
        }
}
#endif /* ENABLE_FOLLOW_PID */
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

        if ( OPERATION_ENABLED( ctx, OP_SHOW_LISTEN) ||
                        glist_get_size_nonempty( ctx->listen_groups ) > 0 ) {

                gui_print_in_banner( ctx );
                glist_foreach_group( ctx->listen_groups, grp ) {
                        gui_print_group( grp, OPERATION_ENABLED(ctx, OP_SHOW_LISTEN),1 );
                }
        }

        gui_print_out_banner( ctx );
        print_titlebar();
        glist_foreach_group( ctx->out_groups, grp ) {
                gui_print_group( grp,1,1 );
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

#ifdef ENABLE_FOLLOW_PID
        if ( OPERATION_ENABLED(ctx, OP_FOLLOW_PID) )
                do_print_stat_pids( ctx );
        else
#endif /* ENABLE_FOLLOW_PID */
                do_print_stat( ctx );

        return 0;
}
