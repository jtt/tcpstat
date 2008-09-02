/**
 * @file parser.c 
 * @brief This file contains functions that can be used to parse text files.
 *
 * @par Copyright 
 * Copyright (c) 2005, J. Taimisto
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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define DBG_MODULE_NAME DBG_MODULE_PARSER

#include "defs.h"
#include "debug.h"
#include "parser.h"

/** @defgroup parser_utils Trivial line tokenizing parser utility */

/**
 * Get next token from given line. 
 * Token means any set of chracters not containing blank (' ','<code>\\t</code>'). Token can
 * also be ended by newline. 
 * @note This function modifies the line pointed by the parameter and returns
 * pointers to data contained in the line parameter given. Hence the tokens
 * will become invalid if the data on line is modified.
 *
 * @param line Pointer to line containing the tokens.
 * @param bytes Pointer to integer that will receive the number of bytes the
 * line has been forwarded.
 * @param token_p Pointer to token structure that should be used.
 * @return Pointer to structure that will contain the token data.
 */ 
static struct line_token *get_next_token( char *line, int *bytes, struct line_token *token_p ) 
{

        char *ch_p = line;

        /* Initialize the token, we always return token with next == NULL */
         
        token_p->token = NULL;
        token_p->token_len = 0; 
        token_p->next = NULL;

        *bytes = 0;

        /* First remove leading newline */
        while ( isblank( *ch_p ) ) {
                ch_p++;
                (*bytes)++;
        }

        if ( *ch_p == '\n' || *ch_p == '\0' ) {
                /* no token */
                DPRINT( "No token\n" );
                token_p->token = NULL;
                token_p->token_len = 0;
                return token_p;
        }

        /* save the start of the token */
        token_p->token = ch_p;
        token_p->token_len = 0;

        /* search for the end of token */
        while ( !isblank( *ch_p ) && *ch_p != '\n' ) { 
                ch_p++;
                token_p->token_len++; 
                (*bytes)++;
        }

        /* convert the blank or newline to \0 */
        *ch_p = '\0';
        (*bytes)++;

        return token_p;
}

/**
 * Generate a linked list of tokens from given line. 
 * Token is a set of chrarcters separaetd by blanks (' ','<code>\\t</code>'). 
 * The @a req parameter should point to structure giving details on what tokens
 * should actually be extracted, only the tokens listed as interesting are
 * returned. 
 * @bug There is no way to specify that all tokens should be extracted. 
 * 
 * @note The line given as parameter will be modified. The returned tokens will
 * point to the line, hence the line should not be modified while examining the
 * tokens. 
 *
 * @ingroup parser_utils
 *
 * @param req Pointer to the structure describing what tokens to return.
 * @param line The line to tokenize 
 * @return Pointer to the linked list of tokens or NULL if no tokens were found
 * or if there were not enough tokens.
 */ 
struct line_token *tokenize( struct parser_req *req, char *line ) 
{
        struct line_token *curr;
        int bytes_forward = 0;
        int count = 0;
        int interested_cnt = 0;

        curr = req->tokens; 

        curr = get_next_token( line, &bytes_forward, curr );
        if ( curr->token_len == 0 ) {
                DPRINT( "No tokens in line \n" );
                return NULL;
        }
        count++;

        do { 
                TRACE( "Token %d \n", count );
                if ( count == req->interested_tokens[ interested_cnt ] ) {
                        TRACE( "Found interesting one \n" );
                        /* This is one of the tokens we are looking for */
                        interested_cnt++;
                        if ( interested_cnt == req->interested_size ) {
                                TRACE( "Got all tokens \n" );
                                /* We have collected all tokens we need */
                                curr->next = NULL;
                                break;
                        } else {
                                curr->next = &(req->tokens[ interested_cnt ]);
                                curr = curr->next;
                        }
                } 
                line = line + bytes_forward;
                curr = get_next_token( line, &bytes_forward, curr );
                count++;
        } while ( curr->token_len != 0 );

        if ( interested_cnt < req->interested_size ) {
                WARN( "There we not enough tokens!\n" );
                return NULL;
        }
                
        return req->tokens;
} 

/** 
 * @brief Read given file line per line and call the spcecified callback for each read line.
 * 
 * @param filename File to read.
 * @param to_skip Number of lines to skip from the beginning.
 * @param callback Pointer to the function to call for each line.
 * @param ctx Pointer to context to pass for the callback.
 *
 * @ingroup parser_utils
 * 
 * @return -1 on error, 0 otherwise.
 */
int parse_file_per_line( char *filename, int to_skip, parser_line_callback_t callback, void *ctx)
{
        FILE *fp; 
        char statline[ LINELEN ];
        char *line_p;
        int nrchar = 0;
        int nrlines = 0; 

        fp = fopen( filename, "r" );
        if ( fp == NULL ) {
                ERROR( "Could not open %s \n", filename );
                return -1;
        }

        line_p = &statline[0];

        do {
                *line_p = getc( fp );
                nrchar++;

                if ( *line_p == EOF ) {
                        DBG( "End-of-file \n" );
                        break;
                }

                if ( *line_p == '\n' ) {
                        nrlines++; 
                        if ( nrchar < LINELEN ) {
                                *(line_p + 1) = '\0';
                        }
                        TRACE( "Read line *%s*", statline );
                        if ( nrlines > to_skip ) {
                                callback( statline, ctx );
                        }
                        line_p = &statline[0];
                        nrchar = 0;
                } else if ( nrchar == LINELEN ) {
                        WARN( "Too long line (%d) read, increase LINELEN\n",nrchar );
                        /* Drain the rest of the line */
                        while ( *line_p != '\n' ) {
                                *line_p = getc( fp );
                                if ( *line_p == EOF ) {
                                        fclose( fp );
                                        return -1;
                                } 
                        }
                        line_p = &statline[0];
                        nrchar = 0;
                } else {
                        line_p++;
                }
        } while( 1 );

        fclose( fp );
        return 0;
}
        
        



