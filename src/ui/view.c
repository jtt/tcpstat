/**
 * @file view.c
 * @brief This file contains the implementation for UI views.
 *
 * This module provides the module which is used to present information to
 * user. In ideal world the rest of the program does not need to know anything
 * about the actual UI code.
 *
 *  Copyright (c) 2008-, J. Taimisto
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
 */ 

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <ncurses.h>

#define DBG_MODULE_NAME DBG_MODULE_VIEW

#include "defs.h"
#include "debug.h"
#include "connection.h"
#include "pidscout.h"
#include "stat.h"
#include "printout_curses.h"


/** 
 * @brief Initialize the UI.
 *
 * This function is used to initialize the user interface.
 * 
 * @param ctx Pointer to the main context.
 * 
 * @return 0 on success, -1 on error.
 */
int ui_init( struct stat_context *ctx )
{
        if ( gui_init(ctx) != 0 )
                return -1;

        init_main_view( ctx );
        return 0;
}

/** 
 * @brief Deinitialize the UI
 *
 * Deinitializes the UI and frees any resources allocated.
 */
void ui_deinit( void )
{
        gui_deinit();
}

/** 
 * @brief Update the current view and refresh the UI.
 *
 * The information is printed to the user according to the currently active
 * view.
 * 
 * @param ctx Pointer to the main context.
 * 
 */
void ui_update_view( struct stat_context *ctx )
{
        switch( gui_get_current_view() ) {
                case MAIN_VIEW :
                        main_update( ctx );
                        break;
                case ENDPOINT_VIEW :
                        endpoint_update( ctx );
                        break;
                default :
                        main_update( ctx );
                        break;
        }
        gui_draw();
}

extern void do_exit( struct stat_context *ctx, char *exit_msg );
/** 
 * @brief Handle user commands.
 * Input loop waits for key presses from user and acts on them. When GUI is
 * initialized it should have been put to halfdelay mode with proper timeout,
 * this way the update time is honored.
 *
 * This function handles the common conmmands which should be the same for all
 * the views. If the command is not any of the common commands, the input
 * command of currently active view is called.
 *
 * @bug In case user presses other than command key, the wait time might be too small.
 *
 * @param ctx Pointer to the global context.
 */
void ui_input_loop( struct stat_context *ctx )
{
        int key;
        enum gui_view view;

        view = gui_get_current_view();

        /* We should be in halfdelay mode, with timeout set properly */
        key = getch();
        if ( key == ERR ) {
                /* We have (hopefully) timed out, no key pressed */
                TRACE( "Timedout\n" );
                return;
        }
        switch( key ) {

                case 'q' :
                        TRACE( "Got quit key press. Exiting \n" );
                        do_exit( ctx, NULL );
                        break;
                case 'n' :
                case 'N' :
                        TRACE( "Toggling numeric display\n" );
                        /* XXX */
                        ctx->do_resolve = gui_toggle_resolve();
                        break;
                case 'I' :
                        TRACE( "Toggling interface stats" );
                        ctx->do_ifstats = ! ctx->do_ifstats;
                        break;
                case 'i' :
                        TRACE( "Toggling interface stat diffs" );
                        gui_toggle_ifdiffs();
                        break;
                case 'E' :
                        TRACE("Enabling endpoint view\n");
                        if ( view != ENDPOINT_VIEW ) 
                                init_endpoint_view( ctx );
                        break;
                case 'M' :
                        if ( view != MAIN_VIEW ) {
                                if ( view == ENDPOINT_VIEW )
                                        deinit_endpoint_view( ctx );

                                init_main_view( ctx );
                        }
                        break;

                default :
                        TRACE("Not generic command, let view sort it out\n");
                        if ( view == MAIN_VIEW ) {
                                main_input( ctx, key );
                        } else if ( view == ENDPOINT_VIEW ) {
                                endpoint_input( ctx, key );
                        } else {
                                do_exit(ctx, "No active view!");
                        }
                        break;
        }
}



