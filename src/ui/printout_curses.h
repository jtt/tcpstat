/**
 * @file printout_curses.h
 * @brief Type definitions and function prototypes for printout_curses.c
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

#ifndef _PRINTOUT_CURSES_H_
#define _PRINTOUT_CURSES_H_

/**
 * The view currentry active 
 */
enum gui_view {
        MAIN_VIEW, 
        ENDPOINT_VIEW,
        HELP_VIEW
};
/* the linebuf API */
int write_linebuf( void );
int write_linebuf_partial( void );
int write_linebuf_partial_attr( int attr );
int add_to_linebuf( const char *fmt, ... );

/* GENERIC GUI CONTEXT ACCESSORS */
void reset_ctx( void );
int gui_print_ifdiffs();
int gui_toggle_ifdiffs();
int gui_resolve_names();
int gui_toggle_resolve();
int gui_do_routing();
int gui_get_columns();
enum gui_view gui_get_current_view();
void gui_set_current_view( enum gui_view view );
void gui_print_statusbar( char *msg );
void gui_clear_statusbar();

int gui_init( struct stat_context *ctx );
void gui_deinit( void );
void gui_draw( void );

/* BANNERS */
void gui_print_banner( struct stat_context *ctx );
void gui_print_in_banner( struct stat_context *ctx );
void gui_print_out_banner( struct stat_context *ctx );
void gui_print_pid_banner( struct pidinfo *info_p );
void gui_print_if_banners( struct stat_context *ctx );
#ifdef DEBUG
void gui_print_dbg_banner( struct stat_context *ctx );
#endif /* DEBUG */

/* MAIN VIEW  */
int main_update( struct stat_context *ctx );
int init_main_view( struct stat_context *ctx );
int main_input( struct stat_context *ctx, int key );
void main_print_help();

/* ENDPOINT VIEW */
int endpoint_input( struct stat_context *ctx, int key );
int endpoint_update( struct stat_context *ctx );
int init_endpoint_view( struct stat_context *ctx );
void deinit_endpoint_view( struct stat_context *ctx );

/* HELP VIEW */
int init_help_view( struct stat_context *ctx );
int help_update( struct stat_context *ctx );

#define GUI_MAX_ROW_LEN 200

/* Start using "wide" formating after this limit of columns is in use */
#define GUI_COLUMN_WIDE_LIMIT 110
#define GUI_COLUMN_WIDEST_LIMIT 150
#define GUI_COLUMN_RT_WIDE_LIMIT 130



#endif /* _PRINTOUT_CURSES_H_ */
