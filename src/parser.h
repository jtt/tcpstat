/**
 * @file parser.h 
 * @brief This file contains type definitions and function declarations for parser.c
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

#ifndef _PARSER_H_
#define _PARSER_H_

#define LINELEN 260
/**
 * Structure containing one token separated from line.
 * @ingroup parser_utils
 */ 
struct line_token {
        char *token; /** The token */
        int token_len; /** Length of the token */

        struct line_token *next; /** Pointer to next token */ 
};

/**
 * Struct describing the request for for parser.  This struct contains the
 * information tokenize needs to tokenize a line.
 * @ingroup parser_utils
 */ 
struct parser_req {
        /**
         * Numbers of tokens that are interesting (first token is 1 )
         */ 
        int *interested_tokens;
        int interested_size;/**< Size of the interested_tokens tab */

        /**
         * Preallocated line_token structs that tokenize() will fill.
         */  
        struct line_token *tokens;
        /**
         * Number of structs allocated. 
         * @bug Is this really needed anywhere.
         */ 
        int token_count;
};

/**
 * Typedef for callback function used on parse_file_per_line().
 * @ingroup parser_utils
 */ 
typedef void (*parser_line_callback_t)(char *line, void *ctx); 


struct line_token *tokenize( struct parser_req *req, char *line );
int parse_file_per_line( char *filename, int to_skip, parser_line_callback_t callback, void *ctx);

#endif /* _PARSER_H_ */
