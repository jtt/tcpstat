/**
 * @file packet_reader.c 
 * @brief This module contains functions used to read raw packets. 
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
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pcap.h>

#define DBG_MODULE_NAME DBG_MODULE_READER

#include "defs.h"
#include "debug.h"
#include "packet_reader.h"

/**
 * Context holding the reader state. 
 */
struct own_context {
        pcap_t *pcap_handle; /**< pcap handle */
        uint64_t packet_count; /** Number of packets received.*/
        int no_more_packets; /**< 1 if we have read all available packets */
};

/**
 * Maximum number of simultaneous contexts
 */
#define MAX_CONTEXTS 5


/**
 * Table holding contexts 
 */
static struct own_context *contexts[MAX_CONTEXTS] = {
        NULL,NULL,NULL,NULL,NULL};


/**
 * Create new reader context
 * @param handle Pointer where the handle to the created context should be set.
 * If the context can not be created, the value of handle will be
 * PKT_HANDLE_INVALID.
 * @return Pointer to the allocated context.
 */
static struct own_context *new_context( reader_handle_t *handle )
{
        int i;

        *handle = PKT_HANDLE_INVALID;
        for (i = 0; i < MAX_CONTEXTS; i++ ) {
                if (contexts[i] == NULL ) {
                        *handle = i;
                        break;
                }
        }

        if (*handle == PKT_HANDLE_INVALID) 
                return NULL;

        TRACE("Creating new reader context for handle %d \n", *handle);
        contexts[*handle] = mem_zalloc( sizeof(struct own_context));

        return contexts[*handle];
}

/**
 * Delete context associated with given handle. 
 * @param handle Handle for the context.
 */
static void delete_context( reader_handle_t handle )
{
        TRACE("Deleting reader context with handle %d\n", handle);
        if (contexts[handle] != NULL )
                mem_free( contexts[handle] );

        contexts[handle] = NULL;
}

/**
 * Get context associated with given handle
 * @param handle for the context.
 */
static struct own_context *get_context( reader_handle_t handle)
{
        if (handle >= 0 && handle < MAX_CONTEXTS)
                return contexts[handle];
        else
                return NULL;
}


/**
 * Create new reader which can be used to read packets from given (pcap) file.
 * @param handle Pointer where the handle will be saved on success.
 * @param file Name of the file to open.
 * @param flags For future use.
 * return RD_OK on success, error code detailing the error on failure.
 */
enum reader_error reader_create( reader_handle_t *handle, const char *file, _UNUSED uint8_t flags)
{
        struct own_context *ctx; 
        char errbuf[PCAP_ERRBUF_SIZE];

        ctx = new_context(handle);
        if (ctx == NULL)
                return RD_ERROR;
        memset( ctx, 0,sizeof(*ctx)); 

        ctx->pcap_handle = pcap_open_offline(file, errbuf);
        if (ctx->pcap_handle == NULL ) {
                ERROR("Unable to open pcap file %s : %s\n", file,
                                errbuf);
                delete_context(*handle);
                return RD_CANT_OPEN;
        }
        TRACE("[%d] opened pcap file %s\n", *handle, file);
        ctx->no_more_packets = 0;
        ctx->packet_count = 0;
        return RD_OK;
}

/**
 * Delete the reader instance. All resources associated to the reader will be
 * closed and deallocated.
 * @param handle handle for the reader to delete.
 * @return RD_OK on success, error code otherwise.
 */
enum reader_error reader_delete( reader_handle_t handle )
{
        struct own_context *ctx;

        ctx = get_context(handle);
        if (ctx == NULL )
                return RD_ERROR_HANDLE;

        TRACE("[%d] deleting reader context\n",handle);

        if (ctx->pcap_handle != NULL) {
                pcap_close(ctx->pcap_handle);
                ctx->pcap_handle = 0;
        }

        delete_context(handle);
        return RD_OK;
}

/**
 * Read next available packet from the given session. 
 * If packet is available, the structure pointed by @a pkt is filled as 
 * follows:
 *  pkt_length : Number of bytes available on pkt_data (number of 
 *               captured bytes)
 *  pkt_data : Pointer to captured data (pkt_length bytes of data, allocated 
 *             from heap).
 *  pkt_flags: PKT_FLAG_PARTIAL is set if the capture is partial (does not contain
 *             all the data that was available).
 *  pkt_time : Timestamp when the packet was captured. 
 *  pkt_seq  : Sequence number of the captured packet on this session. This
 *             number is unique among all packet read from this session.
 *  pkt_payload and pkt_payload_len are initialized to NULL and 0. 
 *
 * @param handle The handle for the session to read data from.
 * @param pkt Pointer to the structure which will be filled with captured packet
 * @return RD_ERROR, if error occured, RD_OK if packet was read and RD_EOP if
 * no more packets are available (pkt will be untouched). 
 */
enum reader_error reader_read_packet( reader_handle_t handle, struct raw_packet *pkt)
{
        struct own_context *ctx;
        struct pcap_pkthdr *hdr;
        const u_char *data;
        int rv;

        ctx = get_context(handle);
        if (ctx == NULL)
                return RD_ERROR_HANDLE;

        if (ctx->no_more_packets) 
                return RD_EOP;

        ASSERT(ctx->pcap_handle != NULL);

        TRACE("[%d] Reading packet\n", handle);

        rv = pcap_next_ex( ctx->pcap_handle, &hdr, &data);
        switch(rv) {
                case 1: 
                        /* Packet read ok */
                        TRACE("Received %d/%d bytes of packet (seq %ld)\n",
                                        hdr->caplen, hdr->len,ctx->packet_count);
                        pkt->pkt_data = mem_zalloc(hdr->caplen * sizeof(uint8_t));
                        memcpy( pkt->pkt_data, data, hdr->caplen);
                        pkt->pkt_length = hdr->caplen;
                        if (hdr->caplen != hdr->len) 
                                pkt->pkt_flags = pkt->pkt_flags | PKT_FLAG_PARTIAL;
                        memcpy(&pkt->pkt_time,&hdr->ts, sizeof(struct timeval));
                        pkt->pkt_seq = ctx->packet_count;
                        pkt->pkt_payload = NULL;
                        pkt->pkt_payload_len = 0;
                        ctx->packet_count++;
                        break;
                case -2:
                        /* we have reached the end of packets */
                        ctx->no_more_packets = 1;
                        return RD_EOP;
                        break;
                case 0:
                        /* timeout, treat as error since we are reading from file */
                case -1:
                        WARN("Error while reading packets: %s\n",
                                        pcap_geterr(ctx->pcap_handle));
                        return RD_ERROR;
                        break;
                default :
                        WARN("Unexpected return value from pcap_next_ex(): %d\n",
                                        rv);
                        return RD_ERROR;
        }
        return RD_OK;
}

/**
 * Free any resources allocated for given raw packet structure. 
 * Any memory allocated for the packet is freed and the structure fields are
 * initialized to 0.
 *
 * @param pkt Pointer to raw packet structure to deinitialize.
 */
void reader_deinit_pkt( struct raw_packet *pkt)
{
        if (pkt == NULL)
                return;

        if (pkt->pkt_data)
                mem_free(pkt->pkt_data);

        memset(pkt, 0, sizeof(*pkt));
}

/*
 * PACKET LIST IMPLEMENTATION 
 */

/**
 * Create new packet list that is able to hold raw packets.
 * @return Pointer to the initialized list.
 */
struct pkt_list *pkt_list_init() 
{
        struct pkt_list *list;

        list = mem_zalloc(sizeof(*list));
        return list;
}

/**
 * Deinitialize packet list. Note that the list should be empty before 
 * it is deinitialized, the list is not cleared.
 * After this function, the pointer to the list is not valid. 
 *
 * @see pkt_list_clear()
 *
 * @param list Pointer to the list to deinitialize.
 */
void pkt_list_deinit( struct pkt_list *list) 
{
        if (!list)
                return;

        mem_free(list);
        return;
}

/**
 * Get next packet (that is, next packet as from a queue) available on the list.
 * Returns the next available packet, the oldest packet on the list.
 *
 * @param list Pointer to the list.
 * @return Pointer to the packet next on this list.
 */
struct raw_packet *pkt_list_next(struct pkt_list *list)
{
        struct raw_packet *pkt;
        struct pkt_list_node *node;

        if (!list)
                return NULL;

        if (!list->count) 
                return NULL; /* no elements */

        ASSERT(list->first);
        node = list->first;
        pkt = node->pkt;
        list->first = node->next;

        mem_free(node);
        list->count--;
        if (list->count == 0)
                list->last = NULL; /* ->first should be now null */

        return pkt;
}

/**
 * Add new packet to the list.
 * @param list Pointer to the list where the packet should be added.
 * @param pkt Pointer to the packet to add to the list.
 * @return Number of packets on the list after the addition.
 */
int pkt_list_append(struct pkt_list *list, struct raw_packet *pkt)
{
        struct pkt_list_node *node; 

        if (!list || !pkt)
                return 0;

        node = mem_zalloc(sizeof(*node));
        node->pkt = pkt;
        node->next = NULL;

        if (list->count == 0) {
                ASSERT( list->first == NULL && list->last == NULL);
                list->first = node;
        } else {
                ASSERT( list->last != NULL );
                list->last->next = node;
        }
        list->last = node;
        list->count++;

        return list->count;
}

/**
 * Clear the list from packets. 
 * All packets on this list are removed.
 *
 * @param list Pointer to the list.
 * @return Number of packets removed. 
 */
int pkt_list_clear( struct pkt_list *list )
{
        struct pkt_list_node *node, *node_iter;
        int count = 0;

        if (!list->count)
                return count;

        node_iter = list->first;
        while (node_iter != NULL) {
                node = node_iter;
                node_iter = node->next;
                mem_free(node);
        }
        count = list->count;
        list->first = NULL;
        list->last = NULL;
        list->count = 0;

        return count;
}

/**
 * Get the number of packets on this list.
 * @param list Pointer to the list.
 * @return Number of packets on this list.
 */
int pkt_list_count( struct pkt_list *list )
{
        return list->count;
}
