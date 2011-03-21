/**
 * @file scouts.h
 * @brief Common header for the scouts. 
 *
 * This header contains the type definitions and function declarations
 * for all the different "scout" modules.
 *
 * Copyright (c) 2011, J. Taimisto <jtaimisto@gmail.com>
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
 */ 
#ifndef _SCOUTS_H_
#define _SCOUTS_H_

#ifdef ENABLE_ROUTES 

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
#endif /* ENABLE_ROUTES */

#ifdef ENABLE_IFSTATS
/**
 * Structure holding interface statistics.
 * @ingroup ifscout_api
 */ 
struct if_stat {
        unsigned long long rx_bytes; /**< Number of received bytes */
        unsigned long long rx_bytes_diff; /**< Difference since last time */
        unsigned long rx_bytes_sec;
        unsigned long long rx_packets;/**< Number of received packets */
        unsigned long long rx_packets_diff;
        unsigned long long tx_bytes;/**< Number of sent bytes */
        unsigned long long tx_bytes_diff;
        unsigned long tx_bytes_sec;
        unsigned long long tx_packets;/**< Number of sent packets */
        unsigned long long tx_packets_diff;
        time_t stamp; /**< Timestamp when previous data was read */
};
#endif /* ENABLE_IFSTATS */

/**
 * Union holdin one IPv6 or one IPv4 address.
 */
union ifinfo_addr_u {
        struct in_addr addr; /**< IPv4 address */
        struct in6_addr addr6;/**< IPv6 address */
};

/**
 * Structure holding IP address bound on interface. 
 * The IP address can be either IPv4 or IPv6 address.
 */
struct ifinfo_addr {
        struct ifinfo_addr *next;/**< Pointer to next address for this interface */
        int family; /**< Address family for the address, either AF_INET or AF_INET6 */
        union ifinfo_addr_u addrs;/**< The IP address for the interface */
#define ifinfo_v6addr addrs.addr6
#define ifinfo_v4addr addrs.addr
};

/**
 * Structure holding interface information.
 * @ingroup ifscout_api
 */ 
struct ifinfo {
        char ifname[ IFNAMEMAX ]; /**< Name of the interface */
        //uint32_t ifaddr; /**< IP address for the interface */
        struct ifinfo_addr *ifaddr;
#ifdef ENABLE_IFSTATS
        struct if_stat stats; /**< Last staticstics gathered */
#endif /* ENABLE_IFSTATS */
#ifdef ENABLE_ROUTES
        struct rtlist *routes;/**< "Routing" information for this interface */
#endif /* ENABLE_ROUTES */
        struct ifinfo *next; /**< Pointer to the next interface on list */
};

/**
 * Structure holding all interface informations 
 * @ingroup ifscout_api
 */ 
struct ifinfo_tab {
        uint8_t size; /**< Number of interfaces on the tab */
        struct ifinfo *ifs;/**< Pointer to table of interfaces */
}; 

#ifdef ENABLE_FOLLOW_PID
/**
 * Maximum length for commandline read from /proc/&lt;pid&gt;/cmdline
 */
#define PROGNAME_MAX 100

/**
 * Structure holding information gathered from /proc entry of given PID 
 */ 
struct pidinfo {
        int pid; /**< PID for the program */ 
        char progname[PROGNAME_MAX]; /**< Name of the program */
        int nr_inodes; /**< Number of socket inodes. */
        ino_t* inodetab; /**< Inodes of all sockets used by the prog */ 
        int inodetab_size; /**< Maximum number of entries in tab */
        struct pidinfo *next; /**< Pointer to next pidinfo struct */
        struct group *grp;/**< Group for connections for this PID */
};
#endif /* ENABLE_FOLLOW_PID */
/*
 * Function prototypes
 */
int read_tcp_stat( struct stat_context *ctx );

/*
 * Interface Information API
 */
struct ifinfo_tab *scout_ifs( void );
const char *ifname_for_addr( struct ifinfo_tab *tab_p, struct sockaddr_storage *addr );
void deinit_ifinfo_tab( struct ifinfo_tab *tab_p );
struct ifinfo *get_ifinfo_by_name( struct ifinfo_tab *tab, const char *name );
int iftab_has_routes( struct ifinfo_tab *tab_p ); 
#ifdef ENABLE_IFSTATS
void read_interface_stat( struct stat_context *ctx );
#endif /* ENABLE_IFSTATS */
#ifdef ENABLE_ROUTES

/* 
 * Route list API
 */
struct rtlist *rtlist_init();
void rtlist_deinit( struct rtlist *list, int kill_elements );
struct rtinfo *rtlist_add( struct rtlist *list, struct rtinfo *info );
struct rtinfo *rtlist_pop( struct rtlist *list );
int rtlist_get_count( struct rtlist *list );
struct rtinfo *rtlist_find_info( struct rtlist *list, struct tcp_connection
    *conn_p);
/*
 * Route information API
 */
int rtinfo_is_default_gw( struct rtinfo *info_p ); 
int rtinfo_is_on_local_net( struct rtinfo *info_p );
/* routing info parsing */
void parse_routing_info( struct ifinfo_tab *ifs );
#endif /* ENABLE_ROUTES */
#ifdef ENABLE_FOLLOW_PID
/*
 * process information API
 */
int scout_pid( struct pidinfo *info_p );
int scan_inodes( struct pidinfo *info_p );
void scan_cmdline( struct pidinfo *info_p );
void free_pidinfo( struct pidinfo *info_p );
struct pidinfo *init_pidinfo( int pid );
struct pidinfo *get_pidinfo_by_inode( ino_t inode, struct pidinfo *info_p );
#endif /* ENABLE_FOLLOW_PID */

#endif /* _SCOUTS_H_ */
