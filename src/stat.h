/**
 * @file stat.h
 * @brief Fill me in 
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


#define STAT_ALL 0
#define STAT_V4_ONLY 1
#define STAT_V6_ONLY 2

#define OP_FOLLOW_PID 0x01
#define OP_RESOLVE 0x02
#define OP_LINGER 0x04
#define OP_IFSTATS 0x08
#define OP_SHOW_LISTEN 0x10

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
};

void switch_grouping( struct stat_context *ctx, policy_flags_t new_grouping );
void rotate_new_queue( struct stat_context *ctx );
int purge_closed_connections( struct stat_context *ctx, int closed_cnt );
int insert_connection( struct sockaddr_storage *local_addr, struct sockaddr_storage *remote_addr,
                enum tcp_state state, ino_t inode, struct stat_context *ctx );
void clear_metadata_flags( struct glist *list );
void group_clear_metadata_flags( struct group *grp );
void resolve_route_for_connection( struct stat_context *ctx, struct tcp_connection *conn_p);
int get_ignored_count( struct stat_context *ctx );

#define OPERATION_ENABLE(c,o) ( c->ops = c->ops | o )
#define OPERATION_DISABLE(c,o) (c->ops = c->ops & ~o)
#define OPERATION_ENABLED(c,o) (c->ops & o )
#define OPERATION_TOGGLE(c,o) ( c->ops = c->ops ^ o )








