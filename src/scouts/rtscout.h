/**
 * @file rtscout.h
 * @brief This file is a header for rtscout module. 
 *
 * 
 * @author Jukka Taimisto
 *
 * @par Copyright
 * Copyright (C) 2006 -2007 Jukka Taimisto 
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

#ifndef _RTSCOUT_H_
#define _RTSCOUT_H_

/**
 * Saved route information for IPv4 
 */
struct ipv4_rtinfo {
        struct in_addr dst;/**< Destination for the route */
        uint32_t mask;/**< Mask for the route */
        struct in_addr gw;/**< Gateway used for this route */
};

/**
 * Dummy placeholder for IPv6 info, 
 * not implemented yet.
 */
struct ipv6_rtinfo {
        struct in6_addr gw;
};


/**
 * The general structure holding the routing information for both 
 * address families. This is the structure which should be used 
 * outside of the rtinfo module. 
 * @ingroup rtinfo_api
 */
struct rtinfo {
        char addr_str[ADDRSTR_BUFLEN]; /**< Printable string for the addr */
        char ifname[IFNAMEMAX];/**< Name of the interface applied for this route*/
        int family;/**< Address family for the routes */
        union {
                struct ipv4_rtinfo ipv4;
                struct ipv6_rtinfo ipv6;
        } rtinfos;
#define rtinfo_v4 rtinfos.ipv4
#define rtinfo_v6 rtinfos.ipv6
        struct rtinfo *next; /**< for the list implementation */
};

/**
 * The rtlist structure holding number of rtinfo structures.
 * @ingroup rtlist_api
 */
struct rtlist {
        int count;/**< Number of elements on the list */
        struct rtinfo *head;/**< First element on the list */
        struct rtinfo *default_gw;/**< The default gw, can be NULL */
};

/*
 * rtlist API
 */
struct rtlist *rtlist_init();
void rtlist_deinit( struct rtlist *list, int kill_elements );
struct rtinfo *rtlist_add( struct rtlist *list, struct rtinfo *info );
struct rtinfo *rtlist_pop( struct rtlist *list );
int rtlist_get_count( struct rtlist *list );
struct rtinfo *rtlist_find_info( struct rtlist *list, struct tcp_connection
                *conn_p ); 

/* rtinfo API */
int rtinfo_is_default_gw( struct rtinfo *info_p ); 
int rtinfo_is_on_local_net( struct rtinfo *info_p );
/* routing info parsing */
void parse_routing_info( struct ifinfo_tab *ifs );

#endif /* _RTSCOUT_H_ */
