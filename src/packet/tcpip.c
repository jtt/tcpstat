/**
 * @file tcpip.h
 * @brief This module contains utility functions for handling TCP/IP packets
 * @author J. Taimisto <jtaimisto@gmail.com>
 *
 * Copyright (c) 2010, J. Taimisto
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
 *     - Neither the name of the author nor the names of its
 *       contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.  
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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <arpa/inet.h>

#define DBG_MODULE_NAME DBG_MODULE_PKT

#include "defs.h"
#include "debug.h"
#include "packet_reader.h"
#include "tcpip.h"

/**
 * Get pointer pointing to the start of the IP packet header. 
 * NOTE: No sanity checks, assume the caller knows there is IP header.
 *
 * FIXME: We assume IP-over-Ethernet
 * @param pkt Pointe to the packet.
 * @return Pointer to the start of the IP header.
 */
static uint8_t *pkt_get_ip_start(struct raw_packet *pkt)
{
        return pkt->pkt_data + ETH_FRAME_HDR_LEN;
}

/**
 * Get the IP packet header for the packet. 
 * NOTE: No sanity checks, assume the caller knows there is IP header.
 * @param pkt Pointer to the packet.
 * @return Pointer to the IP header.
 */
struct ipv4_hdr *pkt_get_ip( struct raw_packet *pkt)
{
        return (struct ipv4_hdr *)pkt_get_ip_start(pkt);
}

/**
 * Get the TCP packet header for the packet. 
 * NOTE: No sanity checks, assume the caller knows there is TCP header.
 * @param pkt Pointer to the packet.
 * @return Pointer to the TCP header.
 */
struct tcp_hdr *pkt_get_tcp( struct raw_packet *pkt)
{
        struct ipv4_hdr *ip = pkt_get_ip(pkt);

        return (struct tcp_hdr *)(pkt_get_ip_start(pkt)+get_ip_header_len(ip));
}


#define IPV4_VERSION_MASK 0xF0
#define IPv4_HLEN_MASK 0x0F

/**
 * Get the IP protocol version number from IP packet header.
 * @param ip Pointer to the IPv4 packet header.
 * @return version as in the packets version field.
 */
int get_ip_version( struct ipv4_hdr *ip)
{
        int ver = ip->ip_verhlen & IPV4_VERSION_MASK;
        ver = ver >> 4;
        return ver;
}

/**
 * Get the lenght of the IPv4 header from IP packet.
 * @param ip Pointer to the IPv4 packet header.
 * @return Lenght of the IPv4 packet header in bytes.
 */
int get_ip_header_len( struct ipv4_hdr *ip)
{
        int hlen = ip->ip_verhlen & IPv4_HLEN_MASK;
        hlen = hlen * 4;
        return hlen;
}

/**
 * Put the source address from given IP header to the 
 * in_addr struct.
 * @param ip IP header to read the source address from
 * @param addr Pointer to the struct in_addr to put the address to.
 */
void put_ip_src( struct ipv4_hdr *ip, struct in_addr *addr)
{
        addr->s_addr = ip->ip_src;
}

/**
 * Put the destination address from given IP header to the
 * in_addr struct.
 * @param ip IP header to read the destination from.
 * @param addr Pointer to the struct in_addr to put the address to.
 */
void put_ip_dst( struct ipv4_hdr *ip, struct in_addr *addr)
{
        addr->s_addr = ip->ip_dst;
}

#define TCP_HLEN_MASK 0xF000
#define TCP_FLAGS_MASK 0x003F

/**
 * Get the header lenght in bytes from given TCP header.
 * @param tcp Pointer to the TCP header.
 * @return header lenght in bytes as read from the TCP header.
 */
int get_tcp_header_len( struct tcp_hdr *tcp)
{
        int hlen = (ntohs(tcp->tcp_hl_flags) & TCP_HLEN_MASK) >> 12;
        hlen = hlen * 4;
        return hlen;
}

/**
 * Get the TCP flag bits from given TCP header.
 * @param tcp Pointer to the TCP header.
 * @return uint8_t containing the flag bits (lowest 6 bits) from TCP header.
 */
uint8_t get_tcp_header_flags(struct tcp_hdr *tcp)
{
        uint8_t flags = ((ntohs(tcp->tcp_hl_flags) & TCP_FLAGS_MASK));
        return flags;
}

/**
 * Put the source port from given TCP header to the socket address structure.
 * @param tcp Pointer to the TCP header.
 * @param sin Pointer to the socket address structure where the source port
 * should be put.
 */
void put_tcp_sport(struct tcp_hdr *tcp, struct sockaddr_in *sin)
{
        sin->sin_port = tcp->tcp_sport;
}

/**
 * Put the source port from given TCP header to the socket address structure.
 * @param tcp Pointer to the TCP header.
 * @param sin Pointer to the socket address structure where the source port
 * should be put.
 */
void put_tcp_dport(struct tcp_hdr *tcp, struct sockaddr_in *sin)
{
        sin->sin_port = tcp->tcp_dport;
}


/**
 * String returned by each print_tcp_flags call.
 */
static char tcp_flags_str[7];

/**
 * Get a null-terminated char array containing shorthands for the flags that
 * are on on the given TCP packet.
 *
 * Returns pointer to static char array which will be overwritten on every
 * call. Not thread-safe.
 *
 * @param tcp Pointer to the TCP header.
 * @return null-terminated char array containing one-letter symbol for every
 * flag that is on on given TCP header.
 */
char *print_tcp_flags(struct tcp_hdr *tcp)
{
        int i =0,j=0;
        uint8_t flags[6] = {
                TCP_URG,TCP_ACK,TCP_PSH,TCP_RST,TCP_SYN,
                TCP_FIN
        };
        char symbols[6] = {
                'U','A','P','R','S','F'
        };
        uint8_t pkt_flags = get_tcp_header_flags(tcp);

        for(i = 0; i < 6; i++ ) {
                if (pkt_flags & flags[i]){
                        tcp_flags_str[j] = symbols[i];
                        j++;
                }
        }
        tcp_flags_str[j] = '\0';
        return tcp_flags_str;
}
