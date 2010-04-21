/**
 * @file endpoint_view.c
 * @brief Module responsible for printing the information on endpointview.
 *
 * When endpoint view is active, the main banner is still printed and for every 
 * outgoing address, the number of connections to that address are printed.
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
#include "printout_curses.h"
#include "ui.h"

/**
 * The active policy when this view was initialized,
 * when this view is deinitialized, we switch back to this policy.
 */
static policy_flags_t saved_policy;

/**
 * @defgroup eview Endpoint view functions
 */


/** 
 * @brief Initalize the endpoint view.
 *
 * This function initializes the endpoint view to be ready for use. 
 * The active grouping policy is changed, when this view is deinitialized, the
 * grouping policy is changed back.
 *
 * @ingroup eview
 * 
 * @param ctx Pointer to the global context.
 * 
 * @return -1 if the view can not be initialized, 0 if view is initialized
 * succesfully.
 */
int init_endpoint_view( struct stat_context *ctx )
{
        TRACE("Initializing endpoint view!\n");
        if ( gui_get_current_view() == ENDPOINT_VIEW ) {
                WARN("Already on endpoint view\n");
                return 0;
        }
        if ( OPERATION_ENABLED(ctx, OP_FOLLOW_PID) ) {
                ui_show_message(LOCATION_BANNER,"Endpoint view not available on follow pid -mode");
                return -1;
        }

        saved_policy = ctx->common_policy;
        switch_grouping( ctx, POLICY_REMOTE | POLICY_ADDR );

        gui_set_current_view( ENDPOINT_VIEW );
        return 0;
}

/** 
 * @brief Deinitialize the endpoint view.
 * 
 * The outgoing connection grouping is changed back to saved value.
 *
 * Note that the current view in the gui is not changed, the caller should
 * initialize new view after this call has been made.
 *
 * @param ctx Pointer to the global context.
 * 
 */
void deinit_endpoint_view( struct stat_context *ctx )
{
        TRACE("Deinitializing endpoint view\n");
        if ( gui_get_current_view() != ENDPOINT_VIEW ) 
                return;

        switch_grouping( ctx, saved_policy );
}
                

/** 
 * @brief Print information about the given group.
 *
 * The group should have connections grouped by the remote address.
 * 
 * @param grp Pointer to the group to print information about.
 */
static void do_group( struct group *grp )
{
        struct tcp_connection *conn_p;
        int new_count = 0;


        conn_p = group_get_first_conn( grp );
        if ( conn_p == NULL ) {
                WARN("Empty group, should not be\n");
                return;
        }

        if ( gui_resolve_names() ) {
                if ( ! (conn_p->metadata.flags & METADATA_RESOLVED )) {
                        connection_resolve( conn_p );
                }
                if ( conn_p->metadata.rem_hostname[0] != '\0' ) {
                        add_to_linebuf("\t%40.40s ", conn_p->metadata.rem_hostname );
                } else {
                        add_to_linebuf("\t%40.40s ", conn_p->metadata.raddr_string );
                }
        } else {
                add_to_linebuf("\t%40.40s ", conn_p->metadata.raddr_string );
        }

        add_to_linebuf(" %d connections", group_get_size( grp ) );
        new_count = group_get_newcount( grp );
        if ( new_count )
                add_to_linebuf(" / %d new", new_count );

        write_linebuf();
}

/** 
 * @brief Update the UI with infromation.
 *
 * The UI is updated with the currently active outgoing endpoints.
 *
 * @ingroup eview
 * 
 * @param ctx Pointer to the global context.
 * 
 * @return -1 if update didn't succeed, 0 if it did.
 */
int endpoint_update( struct stat_context *ctx )
{
        struct group *grp;

        attron( A_REVERSE );
        add_to_linebuf("\t\tOutgoing connection endpoint(s): ");
        write_linebuf();
        attroff( A_REVERSE );

        glist_foreach_group( ctx->out_groups, grp ) {
                do_group( grp );
        }

        return 0;
}

/** 
 * @brief Handle incoming view-specific commands.
 *
 * @ingroup eview
 * 
 * @param ctx Pointer to the global context
 * @param key The key pressed by user.
 * 
 * @return 0 if the key did not match any command, 1 if it did.
 */
int endpoint_input( _UNUSED struct stat_context *ctx, _UNUSED int key )
{
        /* no commands for endpoint view */
        return 0;
}
        






