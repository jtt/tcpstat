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
#include "ui.h"

#define BANNER_MESSAGE_MAX 200

/**
 * This will contain the message which is show after standard banners.
 */
static char banner_message[BANNER_MESSAGE_MAX];

/**
 * @defgroup uiapi API for using the user interface. 
 */

/** 
 * @brief Initialize the UI.
 *
 * This function is used to initialize the user interface.
 * 
 * @ingroup uiapi
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
 * @ingroup uiapi
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
 * The "default" banners are printed before the view -specific update is
 * called.
 * 
 * @ingroup uiapi
 * @param ctx Pointer to the main context.
 * 
 */
void ui_update_view( struct stat_context *ctx )
{
        gui_print_banner( ctx );
        if( OPERATION_ENABLED(ctx, OP_IFSTATS) )
                gui_print_if_banners( ctx );
#ifdef DEBUG
        gui_print_dbg_banner( ctx );
#endif /* DEBUG */
        if ( banner_message[0] != '\0' ) {
                add_to_linebuf(banner_message);
                write_linebuf_partial_attr( A_BOLD );
                write_linebuf();
                banner_message[0] = '\0';
        }

        switch( gui_get_current_view() ) {
                case MAIN_VIEW :
                        main_update( ctx );
                        break;
                case ENDPOINT_VIEW :
                        endpoint_update( ctx );
                        break;
                case HELP_VIEW :
                        help_update( ctx );
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
 * @ingroup uiapi
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
                        if ( gui_toggle_resolve() ) 
                                OPERATION_ENABLE(ctx, OP_RESOLVE);
                        else
                                OPERATION_DISABLE(ctx, OP_RESOLVE);
                        break;
                case 'I' :
                        TRACE( "Toggling interface stats" );
                        OPERATION_TOGGLE( ctx, OP_IFSTATS);
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
                case 'H' :
                        if ( view == ENDPOINT_VIEW )
                                deinit_endpoint_view( ctx );

                        init_help_view( ctx );
                        break;
                default :
                        TRACE("Not generic command, let view sort it out\n");
                        if ( view == MAIN_VIEW ) {
                                main_input( ctx, key );
                        } else if ( view == ENDPOINT_VIEW ) {
                                endpoint_input( ctx, key );
                        } 
                        break;
        }
}

/** 
 * @brief Display a message to user. 
 *
 * Message can be displayed at different positions. If @a loc parameter is
 * LOCATION_STATUSBAR, the message is displayed at the bottom of the screen,
 * and the message is displayed immediately and will be shown untill next
 * update. If it is LOCATION_BANNER, the message is shown after the standard
 * banners, the message will be sshown when the next update is done and is
 * removed after that. 
 *
 * ui_clear_message() can be used to explicitly clear message, with
 * LOCATION_STATUSBAR, the displayed message is removed immediately and with
 * LOCATION_BANNER, the displaying of the message is cancelled for the nexct
 * update (note that banner messages are only shown for one update duration and
 * removed after that).
 *
 * @ingroup uiapi
 * @see ui_clear_message()
 * 
 * @param loc Location where the message is to be displayed.
 * @param message The message to display.
 */
void ui_show_message( enum message_location loc, char *message)
{
        switch( loc ) {
                case LOCATION_STATUSBAR :
                        gui_print_statusbar(message);
                        break;
                case LOCATION_BANNER :
                        strncpy(banner_message, message, BANNER_MESSAGE_MAX );
                        banner_message[BANNER_MESSAGE_MAX-1] = '\0';
                        break;
                default :
                        break;
        }
}

/** 
 * @brief Clear the message from being shown.
 *
 * If @a loc is LOCATION_STATUSBAR, the message is removed immediately and the
 * screen is refressed, LOCATION_BANNER messages are removed and won't be shown
 * on next update round.
 *
 * @ingroup uiapi
 *
 * @see ui_show_message()
 * 
 * @param loc Location to clear.
 */
void ui_clear_message( enum message_location loc)
{
        switch( loc ) {
                case LOCATION_STATUSBAR :
                        gui_clear_statusbar();
                        break;
                case LOCATION_BANNER :
                        banner_message[0] = '\0';
                        break;
                default :
                        break;
        }
}
