/**
 * @file tcpip.h
 * @brief Header for TCP/IP utility function module. 
 * @author J. Taimisto <jtaimisto@gmail.com>
 *
 * Copyright (c) 2011, J. Taimisto
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
#ifndef _TCPIP_H_
#define _TCPIP_H_
#ifdef OPENBSD
#include <sys/socket.h>
#endif
#include <netinet/in.h>

struct tcp_hdr *pkt_get_tcp( struct raw_packet *pkt);
struct ipv4_hdr *pkt_get_ip( struct raw_packet *pkt);
uint8_t *pkt_get_ip_start(struct raw_packet *pkt);
void fill_sockaddrs(struct raw_packet *pkt, struct sockaddr_storage *src,
                struct sockaddr_storage *dst);

/**
 * Ethernet frame
 */
struct ethernet_frame {
        uint8_t eth_dst[6];
        uint8_t eth_src[6];
        uint16_t eth_type;
        uint8_t eth_data[];
} __attribute__((packed));

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_IP6 0x86dd

/**
 * Number of bytes on ethernet frame
 */
#define ETH_FRAME_HDR_LEN 14

/**
 * IPv4 packet header 
 */
struct ipv4_hdr {
        uint8_t ip_verhlen;
        uint8_t ip_tos;
        uint16_t ip_len;
        uint16_t ip_id;
        uint16_t ip_offset;
        uint8_t ip_ttl;
        uint8_t ip_protocol;
        uint16_t ip_checksum;
        uint32_t ip_src;
        uint32_t ip_dst;
} __attribute__((packed));

/**
 * Minimum length for IP packet header.
 */
#define IP_HEADER_MIN_LEN 20

/**
 * Protocol number for TCP
 */
#define IP_PROTO_TCP 6

int get_ip_version( struct ipv4_hdr *ip);
int get_ip_header_len( struct ipv4_hdr *ip);
uint8_t get_ip_protocol(struct ipv4_hdr *ip);
void put_ip_src( struct ipv4_hdr *ip, struct sockaddr_storage *ss);
void put_ip_dst( struct ipv4_hdr *ip, struct sockaddr_storage *ss);

struct tcp_hdr {
        uint16_t tcp_sport;
        uint16_t tcp_dport;
        uint32_t tcp_seq;
        uint32_t tcp_ack;
        uint16_t tcp_hl_flags;
        uint16_t tcp_win;
        uint16_t tcp_checksum;
        uint16_t tcp_urgp;
} __attribute__((packed));

#define TCP_HEADER_MIN_LEN 20

#define TCP_URG 0x01 << 5
#define TCP_ACK 0x01 << 4
#define TCP_PSH 0x01 << 3
#define TCP_RST 0x01 << 2
#define TCP_SYN 0x01 << 1
#define TCP_FIN 0x01 

int get_tcp_header_len( struct tcp_hdr *tcp);
uint8_t get_tcp_header_flags(struct tcp_hdr *tcp);
char *print_tcp_flags(struct tcp_hdr *tcp);
void put_tcp_sport(struct tcp_hdr *tcp, struct sockaddr_storage *ss);
void put_tcp_dport(struct tcp_hdr *tcp, struct sockaddr_storage *ss);

#endif /* _TCPIP_H_ */
