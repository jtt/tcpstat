/**
 * @file ifscout.c
 * @brief This file contains module which is used to scout information about
 * network interfaces. 
 *
 * This module can be used to get the names and addresses of the interfaces
 * configured to the system. The found devices are saved to <i>interface
 * information table</i>. This module contains also functions for reading
 * interface statistics from <code>/proc/net/dev</code> file. 
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

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#define DBG_MODULE_NAME DBG_MODULE_IF

#include "defs.h"
#include "debug.h"
#include "connection.h"
#include "stat.h"
#include "parser.h"
#include "rtscout.h"
#include "ifscout.h"

/**
 * File to look for interface statistics
 */
#define IFSTAT_FILE "/proc/net/dev"

/**
 * Name of the file to look for IPv6 addresses for interfaces. 
 */
#define IF6_FILE "/proc/net/if_inet6"

/**
 * First number of interfaces to look for. 
 */
#define IF_COUNT_START 4

/* forward declaration */
static void read_interface_v6addrs( struct ifinfo_tab *tab );

/** 
 * @defgroup ifscout_api Interface infromation gathering functions. 
 * 
 * This API provides functions for gatehering information about network
 * interfaces configured to the system.
 *
 * scout_ifs() Can be used to collect the names and addresses of the network
 * interfaces.
 */

/**
 * Scan through every interface on the system and record name and address for
 * the interface.
 * Goes through all interfaces on the system, also interfaces currently not up
 * are listed. A pointer to a info table is returned, the memory allocated for
 * the tab should be freed when the table is no longer needed. 
 * @ingroup ifscout_api
 * @return Pointer to the table containing information for the interfaces.
 */ 
struct ifinfo_tab *scout_ifs( void )
{
        int sockfd, len, cnt;
        struct ifconf ifc;
        struct ifreq *ifr;
        struct ifinfo *info_p = NULL;
        struct ifinfo_tab *tab_p;

        /* Create dummy socket, needed for the ioctl. */
        sockfd = socket( PF_INET, SOCK_DGRAM, 0 );
        if ( sockfd  < 0 ) {
                ERROR( "Creating socket failed, bailing out!\n" );
                return NULL;
        }

        cnt = 1;
        memset( &ifc, 0, sizeof(ifc));
        ifc.ifc_len = cnt * IF_COUNT_START * sizeof( struct ifreq );
        ifc.ifc_buf = mem_alloc( ifc.ifc_len );
        while ( cnt > 0 ) {
                TRACE("cnt %d\n", cnt );

                if ( ioctl( sockfd, SIOCGIFCONF, &ifc ) < 0 ) {
                        ERROR( "Error in ioctl() \n" );
                        mem_free( ifc.ifc_buf );
                        return NULL;
                }

                TRACE( "after ioctl(), ifc_len = %d \n", ifc.ifc_len );
                if ( ifc.ifc_len == cnt * IF_COUNT_START * (int)sizeof( struct ifreq)) {
                        TRACE("Possible overflow in SIOCGIFCONF, retrying\n");
                        cnt++;
                        ifc.ifc_len = cnt * IF_COUNT_START * sizeof( struct ifreq );
                        ifc.ifc_buf = mem_realloc( ifc.ifc_buf, ifc.ifc_len );
                } else {
                        cnt = 0;
                }

        }
        len = ifc.ifc_len / sizeof( struct ifreq );
        TRACE( "Number of interfaces %d \n", len );
        close( sockfd );
        

        if ( len > 0 ) {
                /* Prepare the info table */
                tab_p = mem_alloc( sizeof( struct ifinfo_tab ) );
                tab_p->ifs = mem_alloc( len * sizeof( struct ifinfo ) );
                memset( tab_p->ifs, 0, len * sizeof( struct ifinfo));
                tab_p->size = len;
                info_p = tab_p->ifs;
        } else {
                tab_p = NULL;
        } 
        
        /* Iterate through all interfaces */
        ifr = ( struct ifreq *)ifc.ifc_buf;
        while ( len > 0 ) {
                struct sockaddr_in *addr;

                DBG( "Interface %d \n", len );
                addr = (struct sockaddr_in *)&(ifr->ifr_addr);
                DBG( "Interface name |%s| and addr 0x%x\n", ifr->ifr_name, addr->sin_addr.s_addr );

                strncpy( info_p->ifname, ifr->ifr_name, IFNAMEMAX );
                info_p->ifaddr = mem_alloc( sizeof( struct ifinfo_addr ));
                memcpy( &info_p->ifaddr->ifinfo_v4addr, &addr->sin_addr, sizeof( struct in_addr));
                info_p->ifaddr->next = NULL;
                info_p->ifaddr->family = AF_INET;
                
                ifr++; 
                info_p++;
                len--; 
        }

        TRACE( "Reading v6 addresses \n" );
        read_interface_v6addrs( tab_p );

        TRACE( "Done\n" );

        mem_free( ifc.ifc_buf );

        return tab_p;
} 

/**
 * Compare the IP address given in sockaddr storage to IP address on the 
 * interface. If the given IP address is IPv6 address and it is v4 address 
 * mapped as v6 address and the interface IP address is v4 address, the v4
 * form of the mapped address is compared. Complicated?
 *
 * @param iaddr Address on the interface.
 * @param addr_p Address to compare.
 * @return 1 if addresses match, 0 if not (note that v4-mapped v6 address may 
 * match v4 address on interface).
 */
static int compare_ifinfo_addr( struct ifinfo_addr *iaddr, 
                struct sockaddr_storage *addr_p)
{
        struct sockaddr_in *saddr;
        struct sockaddr_in6 *saddr6;
        int rv = 0;


        if ( iaddr->family != addr_p->ss_family ) {
                /* check if the given address is v4 mapped */
                if ( iaddr->family == AF_INET && 
                        addr_p->ss_family == AF_INET6 &&
                        IN6_IS_ADDR_V4MAPPED(ss_get_addr6(addr_p))) {

                        saddr6 = (struct sockaddr_in6 *)addr_p;
                        TRACE("Comparing (iaddr) %.4x to %.4x\n", iaddr->ifinfo_v4addr.s_addr,
                                        ntohl(saddr6->sin6_addr.s6_addr32[3]) );
                        if ( sin6_get_v4addr(saddr6) == iaddr->ifinfo_v4addr.s_addr ) {
                                return 1;
                        }
                } 
                /* Addresses don't match and is not a case of v4-mapped-as-v6 */
                return 0;
        } 

        if ( addr_p->ss_family == AF_INET ) {
                saddr = (struct sockaddr_in *)addr_p;

                if ( memcmp( &saddr->sin_addr, 
                             &iaddr->ifinfo_v4addr,
                            sizeof( struct in_addr )) == 0 ) {
                       rv = 1;
                } 
        } else {
                saddr6 = (struct sockaddr_in6 *)addr_p;
                if ( memcmp( &saddr6->sin6_addr, 
                             &iaddr->ifinfo_v6addr,
                             sizeof( struct in6_addr )) == 0 ) {
                        rv = 1;
                }
        }

        return rv;
}

/**
 * Get interface name for given address. 
 * The address given as parameter should be local ip address, function will
 * returrn name of the interface the address belongs to.  
 * @ingroup ifscout_api
 * @note We make the naive assuption that one interface has only one address.
 * @param tab_p Pointer to the structure containing interface information.
 * @param addr_p The address (in network byte order) for the interface.
 * @return String containig the name of the interface or NULL if no interface
 * with given address was found on the system.
 */ 
const char *ifname_for_addr( struct ifinfo_tab *tab_p, struct sockaddr_storage *addr_p )
{
        struct ifinfo_addr *iaddr;
        struct ifinfo *info_p;
        int i;

        for ( i = 0; i < tab_p->size; i++ ) {
                info_p = &(tab_p->ifs[i] );
                ASSERT((info_p != NULL) );
                TRACE( "Matching to interface %s\n", info_p->ifname );
                iaddr = info_p->ifaddr;
                while( iaddr != NULL ) {
                        if ( compare_ifinfo_addr( iaddr, addr_p ) ) {
                                TRACE("Found match\n");
                                return info_p->ifname;
                        }
                        TRACE("No match\n");
                        iaddr = iaddr->next;
                }
        }
        return NULL;

}

/** 
 * @brief Check if (some of) the interfaces on the tab have routing information
 * present.
 *
 * The routing infromation is not necessarily gathered for the interfaces, this
 * function can be used to check if at least some of the interfaces have some
 * routing information (pretty vague, yeah) present.
 * 
 * @param tab_p Pointer to the structure containing the interface information.
 * 
 * @return 1 if some routing information is found, 0 if not.
 */
int iftab_has_routes( struct ifinfo_tab *tab_p ) 
{
        int rv = 0;
#ifdef ENABLE_ROUTES
        int i;

        for ( i = 0; i < tab_p->size; i++ ) {
                if ( tab_p->ifs[i].routes != NULL ) {
                        rv = 1;
                        break;
                }
        }
#endif /* ENABLE_ROUTES */

        return rv;
}


/** 
 * @brief Get ifinfo structure for device with given name. 
 *
 * @ingroup ifscout_api
 * @param tab Pointer to the table holding interface info.
 * @param name Name of the device to find. 
 * 
 * @return Pointer to ifinfo structure of the named debvice, or NULL if no
 * device is found.
 */
struct ifinfo *get_ifinfo_by_name( struct ifinfo_tab *tab, const char *name )
{
        struct ifinfo *ret = NULL;
        int i;

        if ( name == NULL ) 
                return NULL;

        for ( i = 0; i < tab->size; i++ ) {
                if ( strncmp( tab->ifs[i].ifname, name, IFNAMEMAX ) == 0 ) {
                        ret = &(tab->ifs[i]);
                        break;
                }
        }

        return ret;
}
                



/**
 * Deallocate all memory reserved for ifinfo_tab. 
 * All interface information will be deleted and the table can not be used no
 * more.  Note that if there are pointers left to interface names, those
 * pointers have to be changed... 
 * @ingroup ifscout_api
 * @param tab_p Pointer to the table containg interface information.
 */ 
void deinit_ifinfo_tab( struct ifinfo_tab *tab_p )
{
        int i;
        struct ifinfo_addr *iaddr_p, *tmp;

        if ( tab_p->ifs ) {
                for( i= 0; i < tab_p->size; i++ ) {
#ifdef ENABLE_ROUTES
                        if ( tab_p->ifs[i].routes != NULL ) 
                                rtlist_deinit( tab_p->ifs[i].routes, 1 );
#endif /* ENABLE_ROUTES */

                        iaddr_p = tab_p->ifs[i].ifaddr;
                        while ( iaddr_p != NULL ) {
                                tmp = iaddr_p->next;
                                mem_free( iaddr_p );
                                iaddr_p = tmp;
                        }
                }
                mem_free( tab_p->ifs );
        }

        mem_free( tab_p );

}

/**
 * Line parser callback called for every line in 
 * <code>/proc/net/if_inet6</code>. Parses IPv6 addresses for interfaces.
 * @param line Pointer to the line read. 
 * @param ctx Pointer to the context (should be pointer to ifinfo_tab).
 */
static void parse_v6addresses( char *line, void *ctx )
{
#define NROF_WANTED_TOKENS 2
        struct line_token *tokens_p;
        int wanted[NROF_WANTED_TOKENS] = {1,6};
        struct line_token tokens[NROF_WANTED_TOKENS];
        struct parser_req req = {
                .interested_tokens = wanted,
                .interested_size = NROF_WANTED_TOKENS,
                .tokens = tokens,
                .token_count = NROF_WANTED_TOKENS
        };
        struct ifinfo *inf_p;
        struct ifinfo_addr *new_addr;
        uint8_t data_buf[16]; /* temp for the IPv6 addr */
        int len;

        TRACE("Tokenizing\n");

        tokens_p = tokenize( &req, line );
        if ( tokens_p == NULL ) 
                return;

        /* First token should be the IPv6 address */
        str2bytes( tokens_p->token, data_buf, &len );
        if ( len != 16 ) {
                WARN( "Error while reading the IPv6 address bytes, got %d bytes\n", len );
                return;
        }

        tokens_p = tokens_p->next;
        /* Second token (6th field on the file) should be the name of the
         * iterface 
         */
        inf_p = get_ifinfo_by_name((struct ifinfo_tab *)ctx, tokens_p->token );
        if ( inf_p == NULL ) {
                WARN("Did not find interface %s\n",tokens_p->token );
                /* XXX Add the interface, but the table is fixed-size */
                return;
        } else {
                struct ifinfo_addr *iter;
                new_addr = mem_alloc( sizeof( struct ifinfo_addr));
                memset( new_addr, 0, sizeof( struct ifinfo_addr));
                new_addr->family = AF_INET6;
                memcpy( new_addr->ifinfo_v6addr.s6_addr, data_buf, 16 );
                new_addr->next = NULL;

                iter = inf_p->ifaddr;
                while ( iter->next != NULL ) 
                        iter = iter->next;

                iter->next = new_addr;
        }
#undef NROF_WANTED_TOKENS
}

/**
 * Read IPv6 addresses for the interfaces. 
 *
 * @param info Pointer to the interface info tab.
 */
static void read_interface_v6addrs( struct ifinfo_tab *info )
{
        if ( info == NULL )
                return;

        parse_file_per_line( IF6_FILE, 0, parse_v6addresses, info);
}
#ifdef ENABLE_IFSTATS
/** 
 * @brief Parse interface statistic for tokenized lines. 
 * This is a callback which should be called for every line read from
 * <code>/proc/net/dev</code> (excluding the first two lines. Extracts the RX
 * and TX bytes and packets, and calculates the difference to previous values.
 * @bug Does not handle numeric overflows. 
 * 
 * @param line Pointer to the line read from <code>/proc/net/dev</code>
 * @param ctx Pointer to struct ifinfo_tab containing all the interfaces to
 * display.
 */
static void parse_ifstat_data( char *line, void *ctx )
{
#define NROF_WANTED_TOKENS 6
        struct line_token *tokens_p;
        int wanted[NROF_WANTED_TOKENS] = { 1,2,3,9,10,11 };
        struct line_token tokens[NROF_WANTED_TOKENS];
        struct parser_req req = {
                .interested_tokens = wanted,
                .interested_size = NROF_WANTED_TOKENS,
                .tokens = tokens, 
                .token_count = NROF_WANTED_TOKENS 
        };
        struct ifinfo *inf_p;
        struct ifinfo_tab *tab_p = (struct ifinfo_tab *)ctx;
        char *end;
        int mangled = 0;
        unsigned long long tmp;

        TRACE("Tokenizing\n" );
        tokens_p = tokenize( &req, line );

        if ( tokens_p == NULL ) {
                WARN( "Empty line?\n" );
                return;
        }

        /* First token, interface name */
        TRACE("Interface name:%s\n", tokens->token );
        end = strchr( tokens_p->token, ':' );
        if ( end == NULL ) {
                WARN( "Malformed interface name. Stopping\n");
                return;
        } 
        if ( *(end+1) != '\0' ) {
                TRACE("Found the if stats on same token\n" );
                *end = '\0';
                end = end+1;
                mangled = 1;
        } else {
                *end = '\0';
        }
        inf_p = get_ifinfo_by_name( tab_p, tokens_p->token );
        if ( inf_p == NULL ) {
                TRACE( "Did not find match for interface.\n");
                return;
        }

        /* RX bytes. 
         * Note that if the value grows large enough there might not be space
         * between the interface name and the RX bytes value.  Hence they both
         * will be on the first token. Oh the joy.
         */
        if ( mangled ) {
                tmp = strtoull(end, NULL, 10 );
                inf_p->stats.rx_bytes_diff = tmp - inf_p->stats.rx_bytes;
                inf_p->stats.rx_bytes = tmp;
        } else {
                tokens_p = tokens_p->next;
                tmp = strtoull( tokens_p->token, NULL, 10 );
                inf_p->stats.rx_bytes_diff = tmp - inf_p->stats.rx_bytes;
                inf_p->stats.rx_bytes = tmp;
        }
        tokens_p = tokens_p->next;

        /* RX packets */
        tmp = strtoull( tokens_p->token, NULL, 10 );
        inf_p->stats.rx_packets_diff = tmp - inf_p->stats.rx_packets;
        inf_p->stats.rx_packets = tmp;
        tokens_p = tokens_p->next;

        /* This is a kludge. If the interface name and RX bytes stats were at
         * the same token we need to skip the token '3' which does not contain
         * any data we want. In case the interface name and RX bytes were not
         * on the same token, then we need to skip the token '9' which does not
         * contain any data we need. Messy.
         */
        tokens_p = tokens_p->next;


        /* TX bytes */
        tmp = strtoull( tokens_p->token, NULL, 10 );
        inf_p->stats.tx_bytes_diff = tmp - inf_p->stats.tx_bytes;
        inf_p->stats.tx_bytes = tmp;
        tokens_p = tokens_p->next;

        /* TX packets */
        tmp = strtoull( tokens_p->token, NULL, 10 );
        inf_p->stats.tx_packets_diff = tmp - inf_p->stats.tx_packets;
        inf_p->stats.tx_packets = tmp;

        time_t now = time(NULL);
        if ( inf_p->stats.stamp == 0 ) {
                inf_p->stats.stamp = now;
        } else {
                time_t secs = now - inf_p->stats.stamp;
                if ( secs == 0 )
                        secs++; /* XXX close enough */

                inf_p->stats.rx_bytes_sec = inf_p->stats.rx_bytes_diff / secs;
                inf_p->stats.tx_bytes_sec = inf_p->stats.tx_bytes_diff / secs;
                inf_p->stats.stamp = now;
        }
}

/** 
 * @brief Read interface statistics from <code>/proc/net/dev</code>.
 * Currently RX and TX bytes and packets are read. 
 * 
 * @ingroup ifscout_api
 * @param ctx Pointer to global context.
 */
void read_interface_stat( struct stat_context *ctx )
{
        parse_file_per_line( IFSTAT_FILE, 2, parse_ifstat_data, ctx->iftab );
}
#endif /* ENABLE_IFSTATS */
