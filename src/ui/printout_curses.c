/**
 * @file printout_curses.c
 * @brief Main entry module GUI. 
 *
 * This module provides the entry point for ncurses based GUI.
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

#define DBG_MODULE_NAME DBG_MODULE_GUI

#include "defs.h"
#include "debug.h"
#include "connection.h"
#include "stat.h"
#include "ifscout.h"
#include "rtscout.h"
#include "pidscout.h" /* need to dereference pidinfo pointer */
#include "printout_curses.h"

/**
 * Context holding runtime information for the GUI.
 */
struct gui_curses_context {
        int rows; /**< Number of rows in use */
        int columns;/**< Number of columns in use */
        int current_row; /**< Current row we are writing. */
        int current_column; /**< Current column we are writing */
        char row_buf[GUI_MAX_ROW_LEN];
        int more_lines;
        int do_resolve; /**< Resolve hostnames */
        int ifstat_diffs;
        int do_routing; /** Display the routing information */
        enum gui_view view; /**< Currently active view */
};

static struct gui_curses_context gui_ctx;

/**
 * Reset the gui context to initial state.
 * The contex will be set with current dimensions and
 * the current row will be reset to 0.
 */
void reset_ctx( void )
{
        gui_ctx.rows = LINES;
        if ( COLS > GUI_MAX_ROW_LEN -1) {
                gui_ctx.columns = GUI_MAX_ROW_LEN;
        } else {
                gui_ctx.columns = COLS;
        }
        gui_ctx.current_row = 0;
        gui_ctx.current_column = 0;
        gui_ctx.more_lines = 0;
}

/** 
 * @brief Get the currently active view mode.
 * 
 * @return The viewmode currently active
 */
enum gui_view gui_get_current_view()
{
        return gui_ctx.view;
}

void gui_set_current_view( enum gui_view view )
{
        gui_ctx.view = view;
}

int gui_print_ifdiffs()
{
        return gui_ctx.ifstat_diffs;
}

int gui_toggle_ifdiffs()
{
        gui_ctx.ifstat_diffs = ! gui_ctx.ifstat_diffs;
        return gui_ctx.ifstat_diffs;
}

int gui_resolve_names()
{
        return gui_ctx.do_resolve;
}

int gui_toggle_resolve()
{
        gui_ctx.do_resolve = ! gui_ctx.do_resolve;
        return gui_ctx.do_resolve;
}

int gui_get_columns()
{
        return gui_ctx.columns;
}

int gui_do_routing()
{
        return gui_ctx.do_routing;
}

int gui_toggle_routing() 
{
        gui_ctx.do_routing = ! gui_ctx.do_routing;
        return gui_ctx.do_routing;
}

/**
 * Print message (or no message, clear the statusbar) to the statusbar.
 *
 * @param msg Message to print (NULL is allowed to clear the currently
 * displayed message).
 */
void gui_print_statusbar( char *msg )
{
        attron(A_BOLD);
        mvprintw(gui_ctx.rows-1, 0, " %s", msg );
        attroff(A_BOLD);
        clrtoeol();
        refresh();
}

/**
 * Clear a message being currently displayed on the statusbar. 
 */
void gui_clear_statusbar() 
{
        mvprintw(gui_ctx.rows-1,0," ");
        clrtoeol();
        refresh();
}


/** 
 * @defgroup linebuf_api Internal functions for handling writing lines to screen. 
 * These functions are supposed to be used when writing lines to the screen,
 * they keep track on the current cursor position on the screen. 
 *
 * The writing works with a <i>linebuf</i>. One appends data to linebuf
 * (add_to_linebuf()) and writes the contents of linebuf to window using
 * write_linebuf(), write_linebuf_partial() or write_linebuf_partial_attr()
 * (note that the data is not actually written to screen, it is written to
 * virtual screen, which will be updated with a call to gui_draw()).
 *
 * The whole GUI code is a mess and needs a reorg. 
 *
 */

/**
 * Append the contents of linebuffer to the window and move to next line. 
 * This function must be called when the final contents of a line are to be
 * written, since otherwise the counting on lines and columns will get
 * confused. 
 *
 * @ingroup linebuf_api
 *
 * If there is no space left on window, then <code>--MORE--</code> is written
 * to last line.
 * @bug It is assumed that there is room for <code>--MORE--</code> (i.e
 * terminal is at least
 * 8 chars wide).
 * @see add_to_linebuf()
 * @see write_linebuf_partial()
 * @return 0 if line was written, -1 if there was no space.
 */
int write_linebuf( void )
{
        int rv = 0;

        if ( gui_ctx.current_row == gui_ctx.rows-1 ) {
                gui_ctx.more_lines++;
                /* Last line */
                attron( A_BOLD );
                mvprintw( gui_ctx.rows-1, 0, "--MORE (%d)--",gui_ctx.more_lines);
                attroff( A_BOLD );
                rv = -1;
        } else {
                mvprintw( gui_ctx.current_row, gui_ctx.current_column,
                                gui_ctx.row_buf );
                printw( "\n" );
                gui_ctx.current_row++;
                gui_ctx.current_column = 0;
        }
        gui_ctx.row_buf[0] = '\0';
        return rv;
}


/** 
 * @brief Append the contents of linebuffer to the window but do not move to
 * next line. 
 * This function can be called to write partial line, write_linebuf() must be
 * called to write the final contents of the line. 
 * @see write_linebuf()
 * @see add_to_linebuf()
 * @see write_linebuf_partial_attr()
 * @ingroup linebuf_api
 * 
 * @return - if line was written, -1 if there was no space. 
 */
int write_linebuf_partial( void ) 
{
        int rv = 0;
        int len;

        if ( gui_ctx.current_row == gui_ctx.rows-1 ) {
                /* no more lines, don't write anything,
                 * the finall call to write_linebuf()
                 * will handle this
                 */
                rv = -1;
        } else {
                len = strlen( gui_ctx.row_buf );
                mvprintw( gui_ctx.current_row, gui_ctx.current_column,
                                gui_ctx.row_buf );
                gui_ctx.current_column += len;
        }
        gui_ctx.row_buf[0] = '\0';
        return rv;
}


/** 
 * @brief Write contents of linebuf to screen, don't change line and turn of
 * given attributes while writing the contents.
 * This function is similar to write_linebuf_partial(), except that it turns on
 * given attribute while writing the linebuf. 
 * 
 * @param attr Attributes to turn on while writing (will be turned off after
 * writing).
 * @see write_linebuf_partial()
 * @see write_linebuf()
 * @see add_to_linebuf()
 * @ingroup linebuf_api
 * 
 * @return 0 if contents of linebuf were written, -1 if there was no space. 
 */
int write_linebuf_partial_attr( int attr ) 
{
        int rv = 0;
        int len;

        if ( gui_ctx.current_row == gui_ctx.rows-1 ) {
                /* no more lines, don't write anything,
                 * the finall call to write_linebuf()
                 * will handle this
                 */
                rv = -1;
        } else {
                len = strlen( gui_ctx.row_buf );
                
                attron( attr );
                mvprintw( gui_ctx.current_row, gui_ctx.current_column,
                                gui_ctx.row_buf );
                attroff( attr );
                gui_ctx.current_column += len;
        }
        gui_ctx.row_buf[0] = '\0';
        return rv;
}

/** 
 * @brief Add stuff to line buffer.
 * Line buffer holds text going to be printed to next line. Only as many
 * characters as will fit the line will be added to the buffer. The maximum
 * width of line is set in compile time. 
 *
 * @see write_linebuf_partial()
 * @see write_linebuf_partial_attr()
 * @see write_linebuf()
 * @ingroup linebuf_api
 * 
 * @param fmt The format string.
 * @param ... va_arg arguments for the string.
 * 
 * @return 0 if all data was added to line buffer, -1 if there was no room for
 * more.
 */
int add_to_linebuf( const char *fmt, ... )
{
        int rv = 0, len;
        va_list ap;

        va_start( ap, fmt );
        len = strlen( gui_ctx.row_buf );
        if ( len + gui_ctx.current_column >= gui_ctx.columns ) {
                rv = -1;
        } else {
                vsnprintf( &(gui_ctx.row_buf[len]), 
                                gui_ctx.columns-(len+gui_ctx.current_column), 
                                fmt, ap );
        }
        va_end( ap );
        return rv;
}






/**
 * @defgroup gui_c Functions for graphical user interface using ncurses
 * library.
 */

/**
 * Initialize the GUI for use. 
 * Sets up the ncurses library to control the screen, after this function has
 * been called, the GUI should be usable.
 *
 * @ingroup gui_c
 * @bug The return values are not checked.
 * @return 0 on success, -1 on failure.
 */
int gui_init( struct stat_context *ctx )
{
        initscr();
        //cbreak();
        halfdelay( ctx->update_interval * 10 );
        nodelay( stdscr, FALSE );
        keypad( stdscr, TRUE );
        noecho();

        reset_ctx();
        gui_ctx.do_resolve = ctx->do_resolve;
        gui_ctx.ifstat_diffs = 0;
        gui_ctx.do_routing = ctx->do_routing;
        gui_ctx.view = MAIN_VIEW;

        return 0;
}

/**
 * Deinitialize the GUI.  All ncurses related stuff are properly cleaned up, no
 * messages can be shown to users. 
 * @ingroup gui_c
 *
 */
void gui_deinit( void )
{
        endwin();
}

/** 
 * @brief Update the screen with latest printed info. 
 * All other GUI functions will draw the information on virtual screen, only
 * after this function is called the actual screen is updated (see some
 * tutorial on ncurses). This function also clears the screen as aside effect
 * to make it ready for next round, hence it should be only called when all
 * information has been updated. 
 * @ingroup gui_c
 */
void gui_draw( void )
{

        clrtobot();
        refresh();
       // clear(); /* Get ready for next update round */
}

