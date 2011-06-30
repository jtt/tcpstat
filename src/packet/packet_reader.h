/**
 * @file packet_reader.h 
 * @brief Type definitions for packet reading module.
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
#ifndef _PACKET_READER_H_
#define _PACKET_READER_H_

#ifdef OSX
#include <sys/time.h> /* struct timeval */
#endif /* OSX */

/**
 * handle to reader context.
 * All reader functions use this handle to access the active reader context.
 */
typedef int reader_handle_t;

/**
 * Invalid handle
 */
#define PKT_HANDLE_INVALID -1

/**
 * error valus returned by reader functions 
 */
enum reader_error {
        RD_OK = 0
        ,RD_ERROR = -1 /* Generic error */
        ,RD_CANT_OPEN = -2 /* can't open given file */
        ,RD_ERROR_HANDLE = -3 /* Invalid handle given */
        ,RD_EOP = -4 /* End Of Packets */
};

typedef uint16_t packet_flags_t; 
/**
 * Packet flag indicating that packet contains partial data. 
 * For partial packet not all of its contents were available.
 */
#define PKT_FLAG_PARTIAL 0x01

/**
 * A packet read from the network. 
 */
struct raw_packet {
        int pkt_length; /**< Number of bytes of data available */
        uint8_t *pkt_data; /**< Data for the packet */
        packet_flags_t pkt_flags; /**< Various flags containing info for the packet */
        struct timeval pkt_time; /**< Time when the packet was captured. */
        uint64_t pkt_seq; /**< Sequence number of the packet */
        /**
         * Payload pointer, points to the protocol payload data.
         */ 
        uint8_t *pkt_payload; 
        /**
         * Number of bytes of payload available.
         */
        int pkt_payload_len;
};
/**
 * Check if struct raw_pack contains partial data.
 */
#define PKT_IS_PARTIAL(p)((p)->pkt_flags & PKT_FLAG_PARTIAL)

enum reader_error reader_create( reader_handle_t *handle, const char *file, uint8_t flags);
enum reader_error reader_delete( reader_handle_t handle );
enum reader_error reader_read_packet( reader_handle_t handle, struct raw_packet *pkt);
void reader_deinit_pkt( struct raw_packet *pkt);

/**
 * A node in a list of packets 
 */
struct pkt_list_node {
        struct raw_packet *pkt; /**< Packet in this node */
        struct pkt_list_node *next; /**< Pointer to next node */
};

/**
 * List of raw packets, single packet can be at multiple lists at the same
 * time.
 * The list of packets can be accessed as a queue.
 */
struct pkt_list {
        struct pkt_list_node *first; /**< First node on the list */
        struct pkt_list_node *last; /**< Last node on the list */
        int count; /**< Number of nodes currently on the list */
};

struct pkt_list *pkt_list_init();
void pkt_list_deinit( struct pkt_list *list);

int pkt_list_clear( struct pkt_list *list );
int pkt_list_append(struct pkt_list *list, struct raw_packet *pkt);
struct raw_packet *pkt_list_next(struct pkt_list *list);

int pkt_list_count( struct pkt_list *list );
#endif /* _PACKET_READER_H_ */
