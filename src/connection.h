/**
 * @file connection.h
 * @brief Fill me in 
 *
 * Copyright (c) 2005,2006, J. Taimisto
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

#ifndef _CONNECTION_H_ 
#define _CONNECTION_H_

#include <netinet/in.h>


enum tcp_state { 
        TCP_DEAD = 0, /* Not really a state, for lingering */
        TCP_ESTABLISHED, 
        TCP_SYN_SENT,
        TCP_SYN_RECV,
        TCP_FIN_WAIT1,
        TCP_FIN_WAIT2,
        TCP_TIME_WAIT,
        TCP_CLOSE,
        TCP_CLOSE_WAIT,
        TCP_LAST_ACK,
        TCP_LISTEN,
        TCP_CLOSING
};

enum connection_dir {
        DIR_UNKNOWN,
        DIR_OUTBOUND,
        DIR_INBOUND
};


/**
 * Structure containing metadata information for connection.
 */
struct conn_metadata {
        time_t added; /**< Time the connection was added */
        enum connection_dir dir; /**< Direction of the connection. */
        uint8_t flags; /**< Metadata flags */
        const char *ifname; /**< Name of the interface, Can be NULL */
        ino_t inode; /**< Inode number for the local socket(?) */
        char rem_hostname[ADDRSTR_BUFLEN]; /**< name of the remote host */
        char rem_servname[ADDRSTR_BUFLEN]; /**< service name from remote port */
        /**
         * Text representation of local address (cached to avoid multiple calls
         * to inet_ntop).
         */
        char laddr_string[ADDRSTR_BUFLEN];
        /**
         * Text representation of remote address (cached to avoid multiple calls
         * to inet_ntop).
         */
        char raddr_string[ADDRSTR_BUFLEN];
        /**
         * Number of seconds this connection has been lingering.
         */
        int linger_secs;
        /**
         * Routing information for this connection, NULL if no route 
         * (i.e the connection is within the local net). 
         * NULL also if no routing info is gathered.
         */
        struct rtinfo *route;
};

/**
 * Flag indicating that state has changed 
 */
#define METADATA_STATE_CHANGED 0x01
/**
 * Flag indicating that connection is new 
 */
#define METADATA_NEW 0x02 
/**
 * FLag indicating that connection has been updated.
 */
#define METADATA_UPDATED 0x04
/**
 * Flag indicating that remote host lookup has been 
 * tried.
 */
#define METADATA_RESOLVED 0x10

/**
 * Mask for detecting if the connection has been 
 * touched during this update. Used to detect closed
 * connections.
 */
#define METADATA_TOUCHED_MASK 0x07

#define metadata_set_flag(m,f)( m.flags = m.flags | f )
#define metadata_is_new(m)( m.flags & METADATA_NEW )
#define metadata_is_state_changed(m)( m.flags & METADATA_STATE_CHANGED )
#define metadata_is_touched(m)( m.flags & METADATA_TOUCHED_MASK )  
#define metadata_clear_flags(m)( m.flags = m.flags & 0xF0 )






/**
 * TCP connection. The connection is identified by 4-tuple
 * &lt;sraddr,sport,dstaddr,dport&gt;. 
 * This struct holds also some metadata information that will be carried along
 * with the connection identifiers. The group pointer will point to group which
 * holds this connection (if connection is added to group).
 * @ingroup chashtbl
 */ 
struct tcp_connection {
        int family; /**< Address family for the connection */
        struct sockaddr_storage laddr; /**< Local address for the connection */
        struct sockaddr_storage raddr; /**< Remote address for the connection */

        enum tcp_state state; /**< State of the connection */

        struct conn_metadata metadata;/**< Metadata information for the connection */

        struct tcp_connection *next; /**< Pointer to next connection on linked list */
        struct tcp_connection *prev; /**< Pointer to previous connection on linked list */
        struct group *group; /**< Pointer to group this connection belongs to (or is a parent). */

};

/**
 * Connection queue holds arbitrary number of connections. One connection can
 * be only on one connection queue. The connections are held on a linked list,
 * with the next pointer in struct tcp_connection used as pointer to the next
 * element on the queue. No ordering is done for the elements. The connection
 * group uses cqueue internally and adds filtering capabilities.
 * @ingroup cq
 */ 
struct cqueue {
        int size; /**< Number of connection on the queue */
        struct tcp_connection *head; /**< Pointer to the first element. */
};  

/**
 * Node in a connection hashtable bucket. 
 */ 
struct chlist_node {
        struct chlist_node *next_node; /**< Pointer to next node */

        struct tcp_connection *connection; /**< Pointer to the connection */
};

/**
 * Typedef for the connection hashtable bucket list head.
 */ 
typedef struct chlist_node *chlist_head; 

/**
 * Connection hashtable.
 * Connection hashtable contains connections. Hashtable contains defined
 * ammount of buckets which can contain unlimited number of connections.
 * Buckets are a linked lists of chlist_nodes which in turn contain pointers to
 * connections. One connection can be in multiple hashtables.  
 * @ingroup chashtbl
 */ 
struct chashtable {
        int size; /**< Number of connections on the hashtable */
        int nrof_buckets;/**< Number of buckets on hashtable */
        
        chlist_head buckets[ CONNECTION_HASHTABLE_SIZE ]; /**< Buckets */
};




/**
 * Set a given policy on the flag.
 */ 
#define set_policy_flag(p,f)( p = p | f ) 


/**
 * Group holding a given set of connections.  Group can contain arbitrary
 * number of connections, but since groups use cqueue internally, one
 * connection can belong to only one group. Groups can use selectors to specify
 * rules on which connections can belong to the group.  Connection can hold
 * also pointer to "parent" connection, a connection that somehow groups the
 * other connections together. In groups holding incoming connections, the
 * parent is the listening "connection".
 * @ingroup cgrp
 */ 
struct group {

       struct filter *grp_filter; /**< Filter for this group */
       struct cqueue *group_q;/**< Queue for holding connections belonging to this group */
       struct tcp_connection *parent;/**< Parent connection (if it exists) for this group */

       struct group *next; /**< Pointer for next connection on a list */

};

/**
 * A list of groups. One group can belong only to one glist. 
 * @ingroup cglst
 */ 
struct glist {
        int size; /**< Number of elements on the list */ 
        struct group *head;/**< Pointer to the first group on list */ 
};


/* Function prototypes for connection utilities. */
void connection_deinit( struct tcp_connection *con_p );
int connection_resolve( struct tcp_connection *conn_p );
int connection_do_addrstrings( struct tcp_connection *con_p );
uint16_t connection_get_port( struct tcp_connection *conn, int local );
int is_v6addr_v4mapped( struct sockaddr_in6 *sin6 );


/* Function prototypes for the connection hash table */
struct chashtable *chash_init();
void chash_deinit( struct chashtable *table_p );
int chash_put( struct chashtable *connection_hash,
                struct tcp_connection *conn_p );
struct tcp_connection *chash_get( struct chashtable *connection_hash,
                struct sockaddr_storage *laddr_p, 
                struct sockaddr_storage *raddr_p );
struct tcp_connection *chash_remove( struct chashtable *connection_hash,
                struct sockaddr_storage *laddr_p,
                struct sockaddr_storage *raddr_p );
struct tcp_connection *chash_remove_connection( struct chashtable *connection_hash,
                struct tcp_connection *conn_p );
void chash_clear( struct chashtable *table_p );
#ifdef DEBUG 
void dump_hashtable( struct chashtable *connection_hash );
void dump_connection( struct tcp_connection *conn_p ); 
#endif 



/* Function prototypes for the cqueue lists */

struct cqueue *cqueue_init( void );
void cqueue_deinit( struct cqueue *queue_p, int free_connections );
int cqueue_push( struct cqueue *queue_p, struct tcp_connection *elem_p );
int cqueue_remove( struct cqueue *cqueue_p, struct tcp_connection *conn_p );
struct tcp_connection *cqueue_pop( struct cqueue *cqueue_p );
struct tcp_connection *cqueue_get_head( struct cqueue *cqueue_p ); 
int cqueue_get_size( struct cqueue *cqueue_p );

#ifdef DEBUG 
void dump_queue( struct cqueue *queue_p );
#endif 

/* Function prototypes for connection groups */
struct group *group_init( void );

void group_deinit( struct group *group_p, int free_connections );
void group_set_filter( struct group *group_p, struct filter *filt);
int group_match( struct group *group_p, struct tcp_connection *conn_p );
void group_add_connection( struct group *group_p, struct tcp_connection *conn_p );
void group_remove_connection( struct group *group_p, struct tcp_connection *conn_p );
int group_match_and_add( struct group *group_p, struct tcp_connection *conn_p );
struct tcp_connection *group_get_first_conn( struct group *group_p );
int group_get_size( struct group *group_p );
struct tcp_connection *group_get_parent( struct group *group_p );
void group_set_parent( struct group *group_p, struct tcp_connection *conn_p );
uint16_t group_get_policy( struct group *group_p ); 
struct cqueue *group_get_queue( struct group *group_p );
int group_get_newcount( struct group *group_p );

#ifdef DEBUG 
void dump_group( struct group *grp );
#endif 


/* Function prototypes for connection group lists */
struct glist *glist_init();
void glist_deinit( struct glist *list_p, int free_connections );
struct group *glist_delete_grp_if_empty( struct glist *list_p, struct group *grp );
int glist_add(struct glist *list_p, struct group *grp );
struct group *glist_remove( struct glist *list_p, struct group *grp );
int glist_get_size( struct glist *list_p );
struct group *glist_get_head( struct glist *list_p );
int glist_get_size_nonempty( struct glist *list_p ); 
int glist_connection_count( struct glist *list_p );
int glist_parent_count( struct glist *list_p );

#ifdef DEBUG 
void dump_glist( struct glist *list_p );
#endif 


#include "filter.h"












#endif /* _CONNECTION_H_ */
