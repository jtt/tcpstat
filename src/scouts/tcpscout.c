/**
 * @file tcpscout.c
 * @brief TCP statistics extractor. 
 * This module is responsible for extracting TCP connection information from
 * /proc/net/tcp.
 *
 * Copyright (c) 2006, J. Taimisto
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define DBG_MODULE_NAME DBG_MODULE_TCP

#include "defs.h"
#include "debug.h"
#include "parser.h"
#include "connection.h"
#include "stat.h"

#define NROF_WANTED_TOKENS 4
#define STATFILE "/proc/net/tcp"
#define STAT6FILE "/proc/net/tcp6"


/**
 * Convert a IPv4 address on token read from proc/net/tcp (of format
 * "addr:port" ) to struct sockaddr.
 *
 * @param token Pointer to read token.
 * @param addr_p Pointer to struct sockaddr that should receive the address.
 * @return -1 on error, 0 on success.
 */ 
        
static int token_to_addr( struct line_token *token, struct sockaddr_storage *addr_p )
{
        char *ptr = strchr( token->token, ':' );
        char *port; 
        uint8_t buffer[4];
        int len;
        struct sockaddr_in *addrin_p;
        int rv = 0;

        if ( ptr == NULL ) {
                WARN( "Not valid ip address and port \n" );
                return -1;
        }

        port = ptr + 1;
        *ptr = '\0';

        addrin_p = (struct sockaddr_in *)addr_p;

        /* XXX len!! */
        str2bytes( token->token, buffer, &len );
        //DEBUG_XDUMP( buffer, len, "IP address" );
        /* XXX Make sure this is in network byte order */
        addrin_p->sin_addr.s_addr = htonl(*((uint32_t *) buffer));
        addrin_p->sin_family = AF_INET;

        addrin_p->sin_port = htons( (uint16_t)strtol( port, NULL, 16 ) );

        TRACE( "The ip |%s| and port 0x%x/%d \n", inet_ntoa( addrin_p->sin_addr ), addrin_p->sin_port, addrin_p->sin_port );

        return rv;
}

/**
 * Convert a IPv6 address on token read from proc/net/tcp6 (of format
 * <code>addr:port</code> ) to struct sockaddr.
 *
 * @param token Pointer to read token.
 * @param addr_p Pointer to struct sockaddr (really a sockaddr_in6) that should
 * receive the address.
 * @return -1 on error, 0 on success.
 */
static int token_to_addr6( struct line_token *token, struct sockaddr_storage *addr_p )
{
        char *ptr = strchr( token->token, ':' );
        char *port;
        uint8_t buffer[16];
        int len;
        struct sockaddr_in6 *addrin_p;
        int rv = 0;
        int i;

        if ( ptr == NULL ) {
                WARN( "Not valid IPv6 address and port on token\n" );
                return -1;
        }

        port = ptr + 1;
        *ptr = '\0';

        addrin_p = (struct sockaddr_in6 *)addr_p;
        /* XXX len */
        str2bytes( token->token, buffer, &len );
        /* XXX Do we need to order bytes with IPv6 addresses.. */
        memcpy( &(addrin_p->sin6_addr.s6_addr), buffer, 16 );
        for ( i = 0; i < 4; i++ ) {
                addrin_p->sin6_addr.s6_addr32[i] = htonl( addrin_p->sin6_addr.s6_addr32[i]);
        }
        addrin_p->sin6_family = AF_INET6;
        addrin_p->sin6_port = htons( (uint16_t)strtol( port, NULL, 16));

        return rv;
}




/** 
 * @brief Parse one line of TCP stats.
 * This is a callback function which is called for each line parsed by
 * parse_file_per_line() when parsing the <code>/proc/net/tcp</code>.
 * A line of information from /proc/net/tcp is parsed and interested components
 * (src and dst addresses and ports, connection state and inode number) are
 * extracted. The connection information is then inserted to system with
 * insert_connection(). 
 * 
 * @param line Line read from file. 
 * @param ctx Pointer to the main context.
 */
static void parse_connection_data( char *line, void *ctx ) 
{
        struct line_token *tokens_p;
        struct sockaddr_storage local_addr, remote_addr;
        int state;
        int wanted[NROF_WANTED_TOKENS] = { 2,3,4,10 };
        struct line_token tokens[NROF_WANTED_TOKENS];
        struct parser_req req = {
                .interested_tokens = wanted,
                .interested_size = NROF_WANTED_TOKENS,
                .tokens = tokens,
                .token_count = NROF_WANTED_TOKENS
        };
        ino_t inode; 

        TRACE("Tokenizing\n" );
        tokens_p = tokenize( &req, line );
        TRACE("Done\n");

        TRACE( "Building connection \n" );

        if ( tokens_p == NULL ) {
                WARN( "Error in generating interesting tokens \n" );
                return;
        } 
                
        memset( &local_addr, 0, sizeof( local_addr ) );
        memset( &remote_addr, 0, sizeof( remote_addr ) );

        TRACE( "token 1:(%d)*%s*\n", tokens_p->token_len, tokens_p->token );
        TRACE( "Decoding the local address \n" );
        if ( token_to_addr( tokens_p, &local_addr ) != 0 ) {
               WARN( "Error while parsing data, discarding connection! \n" );
               return;
        } 

        tokens_p = tokens_p->next;
        TRACE( "token 2:(%d)*%s*\n", tokens_p->token_len, tokens_p->token );
        TRACE( "Decoding the remote address \n" );
        if ( token_to_addr( tokens_p, &remote_addr ) != 0 ) {
               WARN( "Error while parsing data, discarding connection! \n" );
               return;
        } 

        tokens_p = tokens_p->next;
        TRACE( "token 3:(%d)*%s*\n", tokens_p->token_len, tokens_p->token );
        state = strtol( tokens_p->token, NULL, 16 );
        TRACE( "State %d \n", state ); 

        tokens_p = tokens_p->next;
        TRACE( "token 4:(%d)*%s*\n", tokens_p->token_len, tokens_p->token );
        inode = strtol( tokens_p->token, NULL, 10 );
        TRACE( "Inode %d \n", inode );
        

        TRACE("Done\n" );
        if ( tokens_p->next != NULL ) {
                WARN( "Eccess elements in token structure \n" );
        }

        insert_connection( &local_addr, &remote_addr, state, inode, (struct stat_context *)ctx );

}

/** 
 * @brief Parse one line of TCP stats.
 * This is a callback function which is called for each line parsed by
 * parse_file_per_line() when parsing the <code>/proc/net/tcp6</code>.
 * A line of information from /proc/net/tcp6 is parsed and interested components
 * (src and dst addresses and ports, connection state and inode number) are
 * extracted. The connection information is then inserted to system with
 * insert_connection(). 
 * 
 * @param line Line read from file. 
 * @param ctx Pointer to the main context.
 */
static void parse_connection6_data( char *line, void *ctx ) 
{
        struct line_token *tokens_p;
        struct sockaddr_storage local_addr, remote_addr;
        int state;
        int wanted[NROF_WANTED_TOKENS] = { 2,3,4,10 };
        struct line_token tokens[NROF_WANTED_TOKENS];
        struct parser_req req = {
                .interested_tokens = wanted,
                .interested_size = NROF_WANTED_TOKENS,
                .tokens = tokens,
                .token_count = NROF_WANTED_TOKENS
        };
        ino_t inode; 
        char addrbuf[INET6_ADDRSTRLEN];

        TRACE("Tokenizing\n" );
        tokens_p = tokenize( &req, line );
        TRACE("Done\n");

        TRACE( "Building connection \n" );

        if ( tokens_p == NULL ) {
                WARN( "Error in generating interesting tokens \n" );
                return;
        } 
                
        memset( &local_addr, 0, sizeof( local_addr ) );
        memset( &remote_addr, 0, sizeof( local_addr ) );

        TRACE( "token 1:(%d)*%s*\n", tokens_p->token_len, tokens_p->token );
        TRACE( "Decoding the local address \n" );
        if ( token_to_addr6( tokens_p, (struct sockaddr_storage *)&local_addr ) != 0 ) {
               WARN( "Error while parsing data, discarding connection! \n" );
               return;
        } 

        tokens_p = tokens_p->next;
        TRACE( "token 2:(%d)*%s*\n", tokens_p->token_len, tokens_p->token );
        TRACE( "Decoding the remote address \n" );
        if ( token_to_addr6( tokens_p, (struct sockaddr_storage *)&remote_addr ) != 0 ) {
               WARN( "Error while parsing data, discarding connection! \n" );
               return;
        } 

        tokens_p = tokens_p->next;
        TRACE( "token 3:(%d)*%s*\n", tokens_p->token_len, tokens_p->token );
        state = strtol( tokens_p->token, NULL, 16 );
        TRACE( "State %d \n", state ); 

        tokens_p = tokens_p->next;
        TRACE( "token 4:(%d)*%s*\n", tokens_p->token_len, tokens_p->token );
        inode = strtol( tokens_p->token, NULL, 10 );
        TRACE( "Inode %d \n", inode );
        

        TRACE("Done\n" );
        if ( tokens_p->next != NULL ) {
                WARN( "Eccess elements in token structure \n" );
        }

        inet_ntop( ((struct sockaddr_in6 *)&local_addr)->sin6_family, 
                        &(((struct sockaddr_in6 *)&local_addr)->sin6_addr),
                        addrbuf, INET6_ADDRSTRLEN );
        DBG( "Read local IPV6 address %s \n", addrbuf );
        inet_ntop( ((struct sockaddr_in6 *)&remote_addr)->sin6_family, 
                        &(((struct sockaddr_in6 *)&remote_addr)->sin6_addr),
                        addrbuf, INET6_ADDRSTRLEN );
        DBG( "Read remote IPV6 address %s \n", addrbuf );


        insert_connection( &local_addr, &remote_addr, state, inode, (struct stat_context *)ctx );

}

/** 
 * @brief Read TCP stats from /proc/net/tcp.
 * TCP stats are read and parsed. The detected connections are inserted.
 * 
 * @param ctx Pointer to the main context.
 * 
 * @return 0 success, -1 on error.  
 */
int read_tcp_stat( struct stat_context *ctx )
{
        return parse_file_per_line( STATFILE, 1, parse_connection_data, ctx );
}

/** 
 * @brief Read TCP stats from /proc/net/tcp6.
 * TCP stats are read and parsed. The detected connections are inserted.
 * 
 * @param ctx Pointer to the main context.
 * 
 * @return 0 success, -1 on error.  
 */
int read_tcp6_stat( struct stat_context *ctx )
{

        return parse_file_per_line( STAT6FILE, 1, parse_connection6_data, ctx );
}
