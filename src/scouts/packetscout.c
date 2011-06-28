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

#define NUM_PACKETS 10


int read_packet_stat( struct stat_context *ctx)
{
        struct packet_context *pkt = ctx->pkt;
        struct raw_packet *raw;
        struct pkt_list *list;
        enum reader_error err;

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
