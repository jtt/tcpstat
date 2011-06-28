/**
 * @file stat.h
 * @brief Header file containing the type definitions for the global context and some helper functions.
 *
 * This file contains the type definition of struct stat_context which is the
 * main context holding all the information together. This file also contains
 * declarations of some functions which are implemented in stat.c which holds
 * "general" functions not having any specific module.
 *
 *
 * Copyright (c) 2006 - 2009, J. Taimisto
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
 * @author Jukka Taimisto <jtaimisto@gmail.com>
 */ 

/* what statistics to collect */
/**
 * Collect both IPv4 and IPv6 stats
 */
#define STAT_ALL 0
/**
 * Collect only IPv4 stats
 */
#define STAT_V4_ONLY 1
/**
 * Collect only IPv6 stats
 */
#define STAT_V6_ONLY 2

/* Following flags can be manipulated with the OPERATION_
 * macros and they control some basic functionalities 
 * of the program.
 */
/**
 * Flag indicating that follow pid -mode is enabled
 */
#define OP_FOLLOW_PID 0x01
/**
 * Flag indicating that IP address name resolution
 * is enabled
 */
#define OP_RESOLVE 0x02
/**
 * Flag indicating that closed connections should
 * be lingered
 */
#define OP_LINGER 0x04
/**
 * Flag indicating that interface stas should be shown.
 */
#define OP_IFSTATS 0x08
/**
 * Flag indicating that listening connections should
 * be shown.
 */
#define OP_SHOW_LISTEN 0x10

/**
 * Try to get connections from pcap file instead of 
 * displaying current "real" status
 */
#define OP_PCAP 0x20

/**
 * typedef for the type holding the operation flags,
 */
typedef uint8_t operation_flags_t;

/**
 * The main context holding together all information.
 */ 
struct stat_context {

        int new_count; /**< Number of new connections on iteration */
        int total_count;/**< Total number of connections */
        int update_interval;/**< nr of secods between updates */
        int collected_stats; /**< what stats to collect */ 

        operation_flags_t ops; /** currently active operations */

        policy_flags_t common_policy; /**< Global grouping policy */
        
        struct glist *listen_groups;/**< Group of connections on LISTEN state */
        struct glist *out_groups;/**< Group of outgoing connections */
        struct cqueue *newq; /**< List of new connections */
        struct chashtable *chash; /**< Main hashtable for connections */

        struct ifinfo_tab *iftab;/**< Table containing interface information */
        struct pidinfo *pinfo; /**< Struct containing information for followed processes. */
        struct filter_list *filters; /**< Filters for new connections */
        struct packet_context *pkt;
};

void switch_grouping( struct stat_context *ctx, policy_flags_t new_grouping );
void rotate_new_queue( struct stat_context *ctx );
int purge_closed_connections( struct stat_context *ctx, int closed_cnt );
int insert_connection( struct sockaddr_storage *local_addr, struct sockaddr_storage *remote_addr,
                enum tcp_state state,
#ifdef ENABLE_FOLLOW_PID
                ino_t inode,
#endif /* ENABLE_FOLLOW_PID */
                struct stat_context *ctx );
void clear_metadata_flags( struct glist *list );
void group_clear_metadata_flags( struct group *grp );
void resolve_route_for_connection( struct stat_context *ctx, struct tcp_connection *conn_p);
int get_ignored_count( struct stat_context *ctx );

/**
 * Enable the given operation (turn the flag on)
 */
#define OPERATION_ENABLE(c,o) ( c->ops = c->ops | o )
/**
 * Disable the given operation (turn the flag off)
 */
#define OPERATION_DISABLE(c,o) (c->ops = c->ops & ~o)
/**
 * Check if the operation is enabled (is the flag on)
 */
#define OPERATION_ENABLED(c,o) (c->ops & o )
/**
 * Toggle the operation enabled status (toggle the flag off if it is 
 * on and on if it is off).
 */
#define OPERATION_TOGGLE(c,o) ( c->ops = c->ops ^ o )

