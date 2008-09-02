/**
 * @file rtscout.c
 * @brief This file contains module which is used to scout information about
 * routes. 
 *
 * This module can be used to look up routing -related information from 
 * <code>/proc/net/route</code>. The information (basically, interface, 
 * ip -mask and router/gw address) is saved to rtinfo
 * structure which in turn can be stored to rtlist list. 
 * 
 * @author Jukka Taimisto 
 *
 * @par Copyright
 * Copyright (C) 2006 -2008 Jukka Taimisto 
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
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>

#define DBG_MODULE_NAME DBG_MODULE_RT

#include "defs.h"
#include "debug.h"
#include "connection.h"
#include "stat.h"
#include "parser.h"
#include "ifscout.h"
#include "rtscout.h"

/**
 * file to read the routes from
 */
#define IPV4_RT_FILE "/proc/net/route" 

/** @defgroup rtlist_api Interface for using lists containing the rtinfo structures.*/

/** 
 * @brief Initialize rtlist
 *
 * The list is initialized, memory for the list is allocated and the list can be
 * used. 
 * @ingroup rtlist_api
 * 
 * @return Pointer to the list. 
 */
struct rtlist *rtlist_init()
{
        struct rtlist *ret; 

        ret = mem_alloc( sizeof( *ret ));
        memset( ret, 0, sizeof( *ret ));

        return ret;
}

/** 
 * @brief Add new element to routing info list
 *
 * 
 * @note One routing info element can be only on one list at the time. 
 * @ingroup rtlist_api
 *
 * @param list Pointer to the list.
 * @param info Pointer to the element on the list.
 * 
 * @return Pointer to the element added to list.
 */
struct rtinfo *rtlist_add( struct rtlist *list, struct rtinfo *info )
{
        struct rtinfo *iter;

        if ( rtinfo_is_default_gw( info ) ) {
                if ( list->default_gw != NULL ) {
                        WARN("Replacing default GW on the list!!\n");
                }
                list->default_gw = info;
                list->count++;
                TRACE("Adding default GW to the list, count %d\n", list->count);
                return info;
        }


        if ( list->count == 0 ) {
                list->head = info;
        } else {
                iter = list->head;
                while ( iter->next != NULL ) {
                        if ( iter->next->rtinfo_v4.mask > info->rtinfo_v4.mask ) {
                                iter = iter->next;
                        } else {
                                info->next = iter->next;
                                iter->next = info;
                                break;
                        }
                }
                if ( iter->next == NULL ) 
                        iter->next = info;
        }
        list->count++;
        TRACE("Added new element to list, count %d\n", list->count );
        return info;
}

/** 
 * @brief Get the number of elements on the routing info list.
 * @ingroup rtlist_api
 * 
 * @param list Pointer to the list.
 * 
 * @return Number of elements on the list.
 */
int rtlist_get_count( struct rtlist *list )
{
        return list->count;
}

/** 
 * @brief Remove element from the head of the list
 * 
 * @param list Pointer to the list
 * @ingroup rtlist_api
 * 
 * @return Pointer to the removed element or NULL if no elements were on the list.
 */
struct rtinfo *rtlist_pop( struct rtlist *list )
{
        struct rtinfo *ret;

        if ( list->count == 0 ) 
                return NULL;
        if ( list->head == NULL ) {
                /* default GW is returned last */
                ASSERT( list->default_gw != NULL );
                ret = list->default_gw;
                list->default_gw = NULL;
        } else {
                ret = list->head;
                list->head = ret->next;
                ret->next = NULL;
        }
        list->count--;
        return ret;
}

/** 
 * @brief Deinitialize the given list
 *
 * Memory allocated for the list is freed and the list is no longer usable.
 * 
 * @ingroup rtlist_api
 * @param list Pointer to the list
 * @param kill_elements  1 if all the remaining element on the list should be
 * free as well.
 */
void rtlist_deinit( struct rtlist *list, int kill_elements )
{
        struct rtinfo *iter;

        if ( kill_elements ) {

                iter = rtlist_pop(list);
                while ( iter != NULL ) {
                        mem_free( iter );
                        iter = rtlist_pop(list);
                }
        }
        mem_free( list );
}

 /** 
 * @brief Find routing information for given connection. 
 *
 * Routing information matching the given connection is returned. 
 * 
 * @param list Pointer to the rtlist holding the routing info.
 * @param conn_p Pointer to the connection to find the info for. 
 * 
 * @return Pointer to the routing info, or NULL if none found. 
 */
struct rtinfo *rtlist_find_info( struct rtlist *list, struct tcp_connection *conn_p ) 
{
        struct rtinfo *info_p, *ret = NULL;
        struct sockaddr_in *saddr;

        if ( rtlist_get_count( list ) == 0 ) 
                return ret;

        info_p = list->head; 
        while ( info_p != NULL ) {
                if ( info_p->family != conn_p->family ) {
                        TRACE("Address family don't match!");
                        goto next;
                }
                saddr = (struct sockaddr_in *)(&conn_p->raddr);
                TRACE("Comparing addr 0x%.8x to 0x%.8x \n", saddr->sin_addr.s_addr, 
                                info_p->rtinfo_v4.dst.s_addr );
                if ( (saddr->sin_addr.s_addr & info_p->rtinfo_v4.mask) 
                                == info_p->rtinfo_v4.dst.s_addr ) {
                        TRACE("Match!\n");
                        ret = info_p;
                }
next :
                info_p = info_p->next;
        }
        if ( ret == NULL && list->default_gw != NULL ) {
		if ( list->default_gw->family == conn_p->family ) {
			TRACE("No mask match, returning default GW\n" );
			ret = list->default_gw;
		}
        }
        return ret;
}

/** @defgroup rtinfo_api API for using the routing information */

/** 
 * @brief Check if given routing information is about default gw.
 *
 * @ingroup rtinfo_api
 * 
 * @param info_p Pointer to the routing information struct.
 * 
 * @return 1 if the routing information is about default gw, 0 if not.
 */
int rtinfo_is_default_gw( struct rtinfo *info_p ) 
{
        int rv = 0;
        if ( info_p->family == AF_INET ) {
                if ( info_p->rtinfo_v4.mask == 0 ) 
                        rv = 1;
        }
        return rv;
}

/** 
 * @brief Check if the routing info points to route on local net. 
 * 
 * @ingroup rtinfo_api
 *
 * @param info_p Pointer to routing info to check.
 * 
 * @return 1 if the routing info is for local net.
 */
int rtinfo_is_on_local_net( struct rtinfo *info_p )
{
        int rv = 0;
        if ( info_p->family == AF_INET ) {
                if ( info_p->rtinfo_v4.gw.s_addr == 0 ) 
                        rv = 1;
        }
        return rv;
}


/** 
 * @brief Parse the IPv4 routing information from the /proc/net/route.
 *
 * The routes are parsed and the routing information is added to the proper
 * interface information structure. 
 *
 * This funtion is intended to be a callback for parse_file_per_line() function.
 * 
 * @param line A line read from /proc/net/route
 * @param ctx  Context, should point interface information table.
 */
static void parse_rt_v4_data( char *line, void *ctx )
{
#define NROF_WANTED_TOKENS 4
        struct line_token *tokens_p, tokens[NROF_WANTED_TOKENS];

        int wanted[NROF_WANTED_TOKENS] = {1,2,3,8};
        struct parser_req req = {
                .interested_tokens = wanted,
                .interested_size = NROF_WANTED_TOKENS,
                .tokens = tokens,
                .token_count = NROF_WANTED_TOKENS
        };
        uint8_t data_buf[4];
        int len;
        struct rtinfo *info_p;
        struct ifinfo *iinfo;
        //struct rtlist *list_p = (struct rtlist *)ctx;
        struct ifinfo_tab *ifs = (struct ifinfo_tab *)ctx;

        tokens_p = tokenize( &req, line );
        
        if ( tokens_p == NULL ) 
                return;

        info_p = mem_alloc( sizeof( *info_p ));
        memset( info_p, 0, sizeof( *info_p));
        info_p->family = AF_INET;

        /* First token, interface name */
        TRACE("Token 1, interface: %s\n", tokens_p->token );

        strncpy( info_p->ifname, tokens_p->token, IFNAMEMAX ); 
        info_p->ifname[IFNAMEMAX-1] = '\0';

        tokens_p = tokens_p->next;

        /* 2nd token, destination address */
        TRACE("Token 2, destination addr %s\n", tokens_p->token );
        str2bytes( tokens_p->token, data_buf, &len );
        if ( len != 4 ) {
                WARN("Error while reading IPv4 address bytes!");
                return;
        }
        //info_p->rtinfo_v4.dst.s_addr = (uint32_t)data_buf; /* XXX endianess? */
        memcpy( &(info_p->rtinfo_v4.dst.s_addr), data_buf, 4 );
        info_p->rtinfo_v4.dst.s_addr = ntohl( info_p->rtinfo_v4.dst.s_addr );

        /* 3rd token, gateway address */
        tokens_p = tokens_p->next;
        TRACE("Token 3, gw address %s \n", tokens_p->token );
        str2bytes( tokens_p->token, data_buf, &len );
        if ( len != 4 ) {
                WARN("Error while reading IPv4 address bytes!");
                return;
        }
        //info_p->rtinfo_v4.gw.s_addr = (uint32_t)data_buf; /* XXX endianess? */
        memcpy( &(info_p->rtinfo_v4.gw.s_addr), data_buf, 4 );
        info_p->rtinfo_v4.gw.s_addr = ntohl( info_p->rtinfo_v4.gw.s_addr );
        if ( inet_ntop( AF_INET, &(info_p->rtinfo_v4.gw), 
                                info_p->addr_str, ADDRSTR_BUFLEN) == NULL ) {
                WARN("inet_ntop() failed, no addrstr\n");
                info_p->addr_str[0] = '\0';
        }

        /* last token, the destination mask */
        tokens_p = tokens_p->next;
        TRACE("Token 4, mask %s \n", tokens_p->token );
        str2bytes( tokens_p->token, data_buf, &len );
        if ( len != 4 ) {
                WARN("Error while reading IPv4 address bytes!");
                return;
        }
        //info_p->rtinfo_v4.mask = (uint32_t)data_buf; /* XXX endianess? */
        memcpy( &(info_p->rtinfo_v4.mask), data_buf, 4 );
        info_p->rtinfo_v4.mask = ntohl( info_p->rtinfo_v4.mask);


        ASSERT( tokens_p->next == NULL );

        //rtlist_add( list_p, info_p );
        iinfo = get_ifinfo_by_name( ifs, info_p->ifname );
        if ( iinfo == NULL ) {
                WARN("Could not get interface named %s for routing info\n", info_p->ifname);
        } else {
                if ( iinfo->routes == NULL )
                        iinfo->routes = rtlist_init();

                rtlist_add( iinfo->routes, info_p );
        }

}

/** 
 * @brief Read routing information from proc filesystem.
 *
 * Reads the routing information and adds the gathered information to
 * appropriate interfaces.
 *
 * @ingroup rtinfo_api
 *
 * @param ifs Pointer to the interface information table.
 *  
 */
void parse_routing_info( struct ifinfo_tab *ifs ) 
{
        parse_file_per_line( IPV4_RT_FILE, 1, parse_rt_v4_data, ifs );
}

