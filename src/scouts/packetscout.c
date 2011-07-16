/**
 * @file packetscout.c
 * @brief 
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

#define DBG_MODULE_NAME DBG_MODULE_PKT

#include "defs.h"
#include "debug.h"
#include "parser.h"
#include "connection.h"
#include "stat.h"
#include "scouts.h"
#include "packet/packet_reader.h"
#include "packet/tcpip.h"

#define NUM_PACKETS 10

/**
 * Return value for check_packet() indicating that packet was malformed.
 */
#define INVALID_PACKET -1
/**
 * Return value for check_packet() indicating that packet was not IP(v4).
 */
#define NO_IP_PACKET -2

/**
 * Do a preliminary check for new packet. 
 * Sanity checks headers, tries to ensure that packet contains proper IP(v4,
 * for now) protocol data.
 *
 * If the packet is IPv4 packet, returns number of the protocol being carried
 * by the IP packet. If packet is found to be invalid (invalid fields on
 * protocol header etc) INVALID_PACKET is returned. If packet does not contain
 * IPv4 data NO_IP_PACKET is returned.
 *
 * Also sets the values of pkt_payload and pkt_payload_length fields of the raw
 * packet structure: 
 * The pkt_payload will point to the start of TCP payload (in case of TCP
 * packet) or to the start of protocol header (other protocol), the
 * pkt_payload_length will contain the length of data starting from pointer
 * (according to the length field on IP header). In case the packet does not
 * carry IP(v4) protocol, the pkt_payload will point to the data carried by
 * ethernet frame and the pkt_payload_length will contain the number of bytes
 * on the packet not counting ethernet header. 
 *
 * @param pkt pointer to the received packet.
 * @return IP protoco number, INVALID_PACKET or NO_IP_PACKET.
 */
static int check_packet( struct raw_packet *pkt)
{
        struct ethernet_frame *eth;
        struct ipv4_hdr *ip;
        struct tcp_hdr *tcp;
        uint16_t etype;
        int protocol,tcp_paylen, ip_len;
        int hlen, tcp_hlen;

        if (pkt->pkt_length < ETH_FRAME_HDR_LEN + IP_HEADER_MIN_LEN ) {
                TRACE("Too small packet %d \n", pkt->pkt_length);
                return NO_IP_PACKET; // fail fast
        }

        eth = (struct ethernet_frame *)pkt->pkt_data;
        etype = ntohs(eth->eth_type);
        if (etype != ETHERTYPE_IP) {
                TRACE("Not IPv4 packet (ethernetype 0x%.2x)\n",etype);
                return NO_IP_PACKET;
        }

        /* this is IP packet; check version, length and protocol */
        ip = pkt_get_ip(pkt);
        if ( get_ip_version(ip) != 4 ) {
                TRACE("Invalid IP version %d\n",get_ip_version(ip));
                return NO_IP_PACKET;
        }
        hlen = get_ip_header_len(ip);
        if (hlen < IP_HEADER_MIN_LEN ) {
                WARN("Malformed IP packet; invalid header length %d\n",
                                hlen);
                return INVALID_PACKET;
        }
        protocol = ip->ip_protocol;
        ip_len = ntohs(ip->ip_len);
        TRACE("IPv4 packet, protocol %d with %d bytes of data (header %d)\n",
                        protocol, ip_len, hlen);

        if (ip_len < hlen || ip_len > pkt->pkt_length - ETH_FRAME_HDR_LEN) { 
                WARN("IP packet length field is incorrect");
                return INVALID_PACKET;
        }

        if (protocol != IP_PROTO_TCP) {
                if (ip_len == hlen)
                        pkt->pkt_payload = NULL;
                else 
                        pkt->pkt_payload = eth->eth_data + hlen;
                pkt->pkt_payload_len = ip_len - hlen;
                return protocol;
        }
        /* TCP packet, sanity check the header, fill payload pointers to the
         * packet structure
         */
        if (ip_len < hlen + TCP_HEADER_MIN_LEN) {
                WARN("Packet claims to be TCP, but does not contain TCP header\n");
                return INVALID_PACKET;
        }

        tcp = pkt_get_tcp(pkt);
        tcp_hlen = get_tcp_header_len(tcp);
        if (tcp_hlen < TCP_HEADER_MIN_LEN ) {
                WARN("Malformed packet, too small TCP header length %d\n",
                                tcp_hlen);
                return INVALID_PACKET;
        }

        TRACE("TCP header length %d\n", tcp_hlen);
        tcp_paylen = ntohs(ip->ip_len) - hlen -tcp_hlen;
        ASSERT(tcp_paylen >= 0);

        if (tcp_paylen > 0)
                pkt->pkt_payload = (eth->eth_data+hlen+tcp_hlen);
        else
                pkt->pkt_payload = NULL;

        pkt->pkt_payload_len = tcp_paylen;
        return protocol;
}

int read_packet_stat( struct stat_context *ctx)
{
        struct packet_context *pkt = ctx->pkt;
        struct raw_packet *raw;
        struct pkt_list *list;
        enum reader_error err;
        int proto;

        if (!OPERATION_ENABLED(ctx, OP_PCAP) || !pkt)
                return -1;

        if (pkt->handle == PKT_HANDLE_INVALID) {
                if (reader_create(&pkt->handle, pkt->pcap_name, 0) != RD_OK) {
                        WARN("Unable to open Pcap file %s \n",pkt->pcap_name);
                        return -1;
                }
                TRACE("Opened pcap file %s to handle %d \n",pkt->pcap_name,
                                pkt->handle);
        }
        list = pkt_list_init();
        if (!list) {
                reader_delete(pkt->handle);
                pkt->handle = PKT_HANDLE_INVALID;
                return -1;
        }
        while (pkt_list_count(list) < NUM_PACKETS) {
                raw = mem_zalloc( sizeof( *raw));
                err = reader_read_packet(pkt->handle, raw);
                if (err != RD_OK) {
                        mem_free(raw);
                        break;
                }

                pkt_list_append(list, raw);
        }
        if ( err != RD_OK && err != RD_EOP ) {
                WARN("Error occured while reading packets\n");
                raw = pkt_list_next(list);
                while (raw != NULL) {
                        reader_deinit_pkt(raw);
                        mem_free(raw);
                        raw = pkt_list_next(list);
                }

                reader_delete(pkt->handle);
                pkt->handle = PKT_HANDLE_INVALID;
                return -1;
        } else {
                raw = pkt_list_next(list);
                while (raw != NULL) {
                        DBG("[%d] with %d bytes of data\n",
                                        raw->pkt_seq, raw->pkt_length);

                        pkt->total_packets++;
                        proto = check_packet(raw);
                        if (proto == INVALID_PACKET) {
                                pkt->malformed_packets++;
                        } else if (proto == IP_PROTO_TCP) {
                                pkt->tcp_packets++;
                        }

                        reader_deinit_pkt(raw);
                        mem_free(raw);
                        raw = pkt_list_next(list);
                }
        }
        pkt_list_deinit(list);
        if (err == RD_EOP) {
                reader_delete(pkt->handle);
                pkt->handle = PKT_HANDLE_INVALID;
                return 1;
        }else{
                return 0;
        }
}
