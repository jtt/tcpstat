/**
 * @file ui.h
 * @brief Common header for UI functions.
 *
 * This header contains the type definitions and such necessary for the UI API.
 * The functions defined on this file should be the ones used by the modules
 * outside ui/ -directory.
 *
 * Hence, in theory, the UI can be ported more easily.
 *
 *  Copyright (c) 2005-2008, J. Taimisto
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
#ifndef _UI_H_
#define _UI_H_

/** 
 * This enum defines the places where messages can be 
 * printed using the ui_show_message() function.
 *
 * @see ui_show_message()
 */
enum message_location {
        LOCATION_BANNER, /**< Print the message into upper banner area */
        LOCATION_STATUSBAR /**< Print the message to the bottom of the screen */
};

int ui_init( struct stat_context *ctx );
void ui_deinit( void );
void ui_update_view( struct stat_context *ctx );
void ui_input_loop( struct stat_context *ctx );
void ui_show_message( enum message_location, char *message);
void ui_clear_message( enum message_location );

#endif /* _UI_H_ */
