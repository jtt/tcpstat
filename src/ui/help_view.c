/**
 * @file help_view.c
 * @brief This file contains the implementation for help view.
 *
 * The help view will show the commands available on different modes.
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
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <ncurses.h>

#define DBG_MODULE_NAME DBG_MODULE_VIEW

#include "defs.h"
#include "debug.h"
#include "connection.h"
#include "stat.h"
#include "scouts.h"
#include "printout_curses.h"

/** 
 * @brief Initialize the help view.
 * 
 * @param ctx Pointer to global context
 * 
 * @return  0.
 */
int init_help_view( _UNUSED struct stat_context *ctx )
{
        TRACE("Initializing help view\n");
        if ( gui_get_current_view() == HELP_VIEW ) 
                return 0;

        gui_set_current_view( HELP_VIEW );

        return 0;
}


/** 
 * @brief Print the generic help text to screen.
 */
static void print_generic_help()
{
        attron( A_UNDERLINE );
        add_to_linebuf("\tGeneric commands:");
        write_linebuf();
        attroff( A_UNDERLINE );
        add_to_linebuf(" q  ");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" Quit program");
        write_linebuf();
        add_to_linebuf(" n N");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" Toggle name resolution");
        write_linebuf();
        add_to_linebuf(" i  ");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" Show differences in interface stats (if enabled)");
        write_linebuf();
        add_to_linebuf(" I  ");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" Toggle display of interface stats");
        write_linebuf();
        attron( A_UNDERLINE );
        add_to_linebuf("\tViews:");
        write_linebuf();
        attroff( A_UNDERLINE );
        add_to_linebuf(" M  ");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" Switch to main view");
        write_linebuf();
        add_to_linebuf(" E  ");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" Switch to endpoint view");
        write_linebuf();
        add_to_linebuf(" H  ");
        write_linebuf_partial_attr( A_BOLD);
        add_to_linebuf(" Show Help");
        write_linebuf();

}
        


        


/** 
 * @brief Update the UI with help texts. 
 * 
 * In addition to help texts, also the normal banners are printed. 
 * 
 * @param ctx Pointer to the global context.
 * 
 * @return 0.
 */
int help_update( _UNUSED struct stat_context *ctx )
{

        attron( A_REVERSE );
        add_to_linebuf("\t\tAvailable commands: ");
        write_linebuf();
        attroff( A_REVERSE );

        print_generic_help();

        main_print_help();

        write_linebuf();
        add_to_linebuf(" Select a view to exit from help ");
        write_linebuf();

        return 0;
}

        


