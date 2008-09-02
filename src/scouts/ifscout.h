/**
 * @file ifscout.h
 * @brief Fill me in 
 * @author Jukka Taimisto 
 *
 * @par Copyright
 * Copyright (C) 2006 Jukka Taimisto 
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
 *
 */ 

#ifndef _IFSCOUT_H_ 
#define _IFSCOUT_H_


/**
 * Structure holding statistics read from <code>/proc/net/dev</code>.
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
        struct if_stat stats; /**< Last staticstics gathered */
        struct rtlist *routes;/**< "Routing" information for this interface */
};

/**
 * Structure holding all interface informations 
 * @ingroup ifscout_api
 */ 
struct ifinfo_tab {
        uint8_t size; /**< Number of interfaces on the tab */
        struct ifinfo *ifs;/**< Pointer to table of interfaces */
}; 


/* Exported functions */
struct ifinfo_tab *scout_ifs( void );
const char *ifname_for_addr( struct ifinfo_tab *tab_p, struct sockaddr_storage *addr );
void deinit_ifinfo_tab( struct ifinfo_tab *tab_p );
struct ifinfo *get_ifinfo_by_name( struct ifinfo_tab *tab, const char *name );
void read_interface_stat( struct stat_context *ctx );
#endif /* _IFSCOUT_H_ */
