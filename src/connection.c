/**
 * @file connection.c
 * @brief This module contains functions for handling connections and functions
 * storing connections to hastables and connection lists. 
 *
 * @author Jukka Taimisto 
 *
 * @par Copyright
 * Copyright (C) 2005 - 2008 Jukka Taimisto 
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
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <netdb.h>

#include <arpa/inet.h>


#define DBG_MODULE_NAME DBG_MODULE_CONN

#include "defs.h"
#include "debug.h"
#include "connection.h" 

#ifdef ENABLE_RESOLVE_POPUP
extern void resolve_popup( const char *addrstr);
void resolve_done_popup();
#endif /* ENABLE_RESOLVE_POPUP */



/**
 * @defgroup chashtbl Hashable for TCP connections. 
 */ 


/**
 * Initialize the connection hashtable.
 * This function should be called before anything else is done for the cache.
 * @ingroup chashtbl
 * @return Pointer to initialized hashtable
 */ 
struct chashtable *chash_init( void ) 
{
        struct chashtable *connection_hash = NULL;

        connection_hash = mem_alloc( sizeof( struct chashtable) );
        connection_hash->size = 0;
        connection_hash->nrof_buckets = CONNECTION_HASHTABLE_SIZE; 

        /*connection_hash->buckets = mem_alloc( CONNECTION_HASHTABLE_SIZE * sizeof( chlist_head ) );*/
        memset( connection_hash->buckets, 0, CONNECTION_HASHTABLE_SIZE * sizeof( chlist_head ) );

        DBG( "Allocated %d buckets for connection hashtable \n", CONNECTION_HASHTABLE_SIZE );
        return connection_hash;
}



/** 
 * @brief Deinitialize hashtable
 *
 * Memory allocated for the hashtable is freed. 
 * @note Connections are not deleted, only the hashtable.
 * @ingroup chashtbl
 * 
 * @param table_p Pointer to the hashtable.
 */
void chash_deinit( struct chashtable *table_p )
{
        DBG( "Deinitializing chashtable with %d connections\n", table_p->size );
        mem_free( table_p );
}

/** 
 * @brief Clear all connections from hashtable. 
 * All connections are removed from the hashtable, the connections are not
 * deinitialized. The hashtable is usable after calling this function, only
 * empty.
 *
 * @param table_p Pointer to the hashtable.
 */
void chash_clear( struct chashtable *table_p ) 
{
        int i;

        DBG( "Clearing hashtable with %d connections \n", table_p->size );
        for( i = 0; i < table_p->nrof_buckets; i++ ) {
                while ( table_p->buckets[i] != NULL ) {
                        TRACE( "Removing connection %p\n", table_p->buckets[i]->connection);
                        chash_remove_connection( table_p, table_p->buckets[i]->connection );
                }
        }
}
        

/**
 * Hash function for connection hashtable for IPv4 TCP connections. 
 *
 * Hash value is calculated for the 4-tuple <local ip, local port, remote ip,
 * remote port>.
 *
 * @note Mimics the INPCBHASH found on OpenBSD (sys/netinet/in_pcb.c)
 *
 * @param connection_hash Pointer to hashtable.
 * @param laddr Pointer to local address
 * @param raddr Pointer to remote address. 
 * @return Hash valua for the connection.
 */  
static int chash_fn4( struct chashtable *connection_hash, struct sockaddr_in *laddr,
                struct sockaddr_in *raddr )
{
        int h = ntohl(raddr->sin_addr.s_addr) + ntohs(laddr->sin_port) + ntohs(raddr->sin_port);
        TRACE( "chash_fn(<0x%.4x:0x%.2x, 0x%.4x:0x%.2x>)=0x%.2x\n", laddr->sin_addr.s_addr, 
                        laddr->sin_port, raddr->sin_addr.s_addr, raddr->sin_port, h & (connection_hash->nrof_buckets -1 ));
        
	return h & (connection_hash->nrof_buckets - 1);
}

/**
 * Hash function for connection hashtable for IPv6 connections 
 *
 * Hash value is calculated for the 4-tuple <local ip, local port, remote ip,
 * remote port>.
 *
 * @note Mimics the IN6PCBHASH found on OpenBSD (sys/netinet/in_pcb.c)
 *
 * @param connection_hash Pointer to hashtable.
 * @param laddr Pointer to local address
 * @param raddr Pointer to remote address. 
 * @return Hash valua for the connection.
 */  
static int chash_fn6( struct chashtable *connection_hash, struct sockaddr_in6 *laddr, 
                struct sockaddr_in6 *raddr )
{
        int h;

        h = ntohl( raddr->sin6_addr.s6_addr[0] ) ^ htonl( raddr->sin6_addr.s6_addr[3]);
        h += ntohs( raddr->sin6_port ) + ntohs( laddr->sin6_port );

        TRACE( "chash_fn6(<0x%.4x:0x%.2x, 0x%.4x:0x%.2x>)=0x%.2x\n", snip1, laddr->sin6_port, snip2, 
                        raddr->sin6_port, h & (connection_hash->nrof_buckets -1 ));
        return h & (connection_hash->nrof_buckets - 1 );
}

/** 
 * @brief Get pointer to right bucket for given connection.
 *
 * Since IPv4 and IPv6 connections are in the hashtable, some address family
 * checks have to be done. The hash function differs also for v4 vs. v6.
 * 
 * @param tab_p Pointer to hashtable.
 * @param conn_p Pointer to connection for resolving the bucket.
 * 
 * @return Pointer to the head of the correct bucket for given connection.
 */
static chlist_head *resolve_bucket( struct chashtable *tab_p, 
                struct tcp_connection *conn_p )
{
        int hash;
        if ( conn_p->family == AF_INET ) {
                hash =chash_fn4(tab_p, (struct sockaddr_in *)&conn_p->laddr,
                                (struct sockaddr_in *)&conn_p->raddr );
                return &tab_p->buckets[ hash ];
        } else {
                hash = chash_fn6(tab_p, (struct sockaddr_in6 *)&conn_p->laddr,
                                (struct sockaddr_in6 *)&conn_p->raddr );
                return &tab_p->buckets[ hash ];
        }
}

/** 
 * @brief Get pointer to right bucket for given addresses.
 *
 * Since IPv4 and IPv6 connections are in the hashtable, some address family
 * checks have to be done. The hash function differs also for v4 vs. v6.
 *
 * @see resolve_bucket()
 * 
 * @param tab_p Pointer to hashtable.
 * @param laddr_p Pointer to sockaddr_storage structure holding local address.
 * @param raddr_p Pointer to sockaddr_storage structure holding remote address.
 * 
 * @return Pointer to the head of the correct bucket for given connection.
 */
static chlist_head *resolve_bucket_sa( struct chashtable *tab_p,
                struct sockaddr_storage *laddr_p, struct sockaddr_storage *raddr_p)
{
        if ( laddr_p->ss_family == AF_INET ) {
                return &tab_p->buckets[ chash_fn4( tab_p, (struct sockaddr_in *)laddr_p,
                                (struct sockaddr_in *)raddr_p ) ];
        } else {
                return &tab_p->buckets[ chash_fn6( tab_p, (struct sockaddr_in6 *)laddr_p,
                                (struct sockaddr_in6 *)raddr_p ) ];
        }
}


/**
 * Add connection to hashtable. 
 * Connection is added to the hashtable, note that no check for duplicates is done.
 *
 * @ingroup chashtbl
 *
 * @param connection_hash Pointer to hashtable.
 * @param conn_p Pointer to the connection struct to add.
 * @return 0 on success.
 */ 
int chash_put( struct chashtable *connection_hash, struct tcp_connection *conn_p )
{
        chlist_head  *head_p = resolve_bucket( connection_hash, conn_p );
        struct chlist_node *node_p;

        ENTER_F();

        node_p = mem_alloc( sizeof( struct chlist_node ) );
        node_p->connection = conn_p;
        node_p->next_node = *head_p;
        *head_p = node_p;
        TRACE( "[%p -> %p]\n", node_p, node_p->next_node ); 
        connection_hash->size++;
        DPRINT( "Hashtable size %d \n", connection_hash->size );

        EXIT_F();
        return 0;
}

/**
 * Compare given IPv4 addresses to a node on the linked list. 
 *
 * This function checks if the given addresses are the key for the connection
 * on the given node. 
 *
 * @todo Simplify, simplify, simplify
 *
 * @param laddr_p Pointer to the local address structure.
 * @param raddr_p Pointer to the remote address structure.
 * @param node_p Pointer to the node to compare.
 * @return 1 if given addresses are the key for connection on the node, 0
 * otherwise.
 */ 
static int key_cmp_v4( struct sockaddr_in *laddr_p, struct sockaddr_in *raddr_p, 
                struct chlist_node *node_p ) 
{
        int rv = 0;

        struct sockaddr_in *nlinp = (struct sockaddr_in *)&(node_p->connection->laddr );
        struct sockaddr_in *nrinp = (struct sockaddr_in *)&(node_p->connection->raddr );

#if 0
        TRACE( "Laddr %s %d \n", inet_ntoa( linp->sin_addr ), linp->sin_port );
        TRACE( "Raddr %s %d \n", inet_ntoa( rinp->sin_addr ), rinp->sin_port );
        TRACE( "node Laddr %s %d \n", inet_ntoa( nlinp->sin_addr ), nlinp->sin_port );
        TRACE( "node Raddr %s %d \n", inet_ntoa( nrinp->sin_addr ), nrinp->sin_port );
#endif /* 0 */

        if ( laddr_p->sin_addr.s_addr == nlinp->sin_addr.s_addr &&
                        laddr_p->sin_port == nlinp->sin_port &&
                        raddr_p->sin_addr.s_addr == nrinp->sin_addr.s_addr &&
                        raddr_p->sin_port == nrinp->sin_port ) { 

                TRACE( "Equal\n" );
                rv = 1;
        }

        return rv;
}
/**
 * Compare given IPv6 addresses to a node on the linked list. 
 *
 * This function checks if the given addresses are the key for the connection
 * on the given node. 
 *
 * @todo Simplify, simplify, simplify
 *
 * @param laddr_p Pointer to the local address structure.
 * @param raddr_p Pointer to the remote address structure.
 * @param node_p Pointer to the node to compare.
 * @return 1 if given addresses are the key for connection on the node, 0
 * otherwise.
 */ 
static int key_cmp_v6( struct sockaddr_in6 *laddr_p, struct sockaddr_in6 *raddr_p, 
                struct chlist_node *node_p ) 
{
        int rv = 0;

        struct sockaddr_in6 *nlinp = (struct sockaddr_in6 *)&(node_p->connection->laddr );
        struct sockaddr_in6 *nrinp = (struct sockaddr_in6 *)&(node_p->connection->raddr );

        if ( memcmp( &(laddr_p->sin6_addr.s6_addr), &(nlinp->sin6_addr.s6_addr), 16) == 0 &&
             laddr_p->sin6_port == nlinp->sin6_port && 
             memcmp( &(laddr_p->sin6_addr.s6_addr), &(nlinp->sin6_addr.s6_addr), 16 ) == 0 &&
             raddr_p->sin6_port == nrinp->sin6_port ) {
                TRACE( "Equal\n" );
                rv = 1;
        }
        return rv;
}

/**
 * Compare given addresses to a node on the linked list. 
 *
 * This is address family independent wrapper function which calls the proper
 * comprison function for the address family.  This function checks if the
 * given addresses are the key for the connection on the given node. 
 *
 * @todo Simplify, simplify, simplify
 * @see key_cmp_v4(), key_cmp_v6()
 *
 * @param laddr_p Pointer to the local address structure.
 * @param raddr_p Pointer to the remote address structure.
 * @param node_p Pointer to the node to compare.
 * @return 1 if given addresses are the key for connection on the node, 0
 * otherwise.
 */ 
static int key_cmp( struct sockaddr_storage *laddr_p, 
                struct sockaddr_storage *raddr_p, struct chlist_node *node_p )
{
        ASSERT( laddr_p->ss_family == raddr_p->ss_family );
        
        if ( laddr_p->ss_family != node_p->connection->laddr.ss_family ) {
                TRACE("Not equal, address families don't match\n");
                return 0;
        }
        if ( laddr_p->ss_family == AF_INET ) {
                return key_cmp_v4( (struct sockaddr_in *)laddr_p,
                                (struct sockaddr_in *)raddr_p,
                                node_p );
        } else if ( laddr_p->ss_family == AF_INET6 ) {
                return key_cmp_v6( (struct sockaddr_in6 *)laddr_p,
                                (struct sockaddr_in6 *)raddr_p,
                                node_p );
        }
        WARN( "Unknown address family %d\n", laddr_p->ss_family );
        return 0;
}
                


/**
 * Get connection which has the key defined by the given addresses. 
 *
 * @ingroup chashtbl
 *
 * @param connection_hash Pointer to hashtable.
 * @param laddr_p Pointer to the local address structure.
 * @param raddr_p Pointer to the remote address structure. 
 * @return Pointer to the connection with key defined by the given addresses,
 * NULL if none is found.
 */ 
struct tcp_connection *chash_get( struct chashtable *connection_hash,
                struct sockaddr_storage *laddr_p, 
                struct sockaddr_storage *raddr_p ) 
{
        chlist_head *head_p = resolve_bucket_sa( connection_hash,
                        laddr_p, raddr_p );
        struct chlist_node *node_p = *head_p;
        struct tcp_connection *rv = NULL;

        ENTER_F();

        while ( node_p != NULL ) {
                if ( key_cmp( laddr_p, raddr_p, node_p ) == 1 ) {
                       rv = node_p->connection;
                       break;
                } 

                node_p = node_p->next_node;
        }

        EXIT_F();
        return rv;
} 

/**
 * Remove a connection keyed by given addresses from the hashtable. 
 *
 * @ingroup chashtbl
 *
 * @param connection_hash Pointer to hashtable.
 * @param laddr_p Pointer to the local address structure.
 * @param raddr_p Pointer to the remote address structure.
 * @return Pointer to the connection removed from the hashtable, or NULL if
 * none was removed.
 */ 
struct tcp_connection *chash_remove(struct chashtable *connection_hash,
                struct sockaddr_storage *laddr_p, 
                struct sockaddr_storage *raddr_p ) 
{
        chlist_head *head_p = resolve_bucket_sa( connection_hash, 
                        laddr_p, raddr_p );
        struct chlist_node *node_p;
        struct tcp_connection *rv = NULL;

        ENTER_F();
        node_p = *head_p;

        if ( node_p == NULL ) {
                WARN( "Trying to remove connection not in the hash!\n" );
                return NULL;
        }

        if ( key_cmp( laddr_p, raddr_p, node_p ) == 1 ) {
                TRACE( "Removing the connection from head\n" );
                rv = node_p->connection;
                *head_p = node_p->next_node;
                TRACE( "[%p -> %p]\n", node_p, *head_p );
                mem_free( node_p );
                connection_hash->size--;
                DPRINT( "Hashtable size %d \n", connection_hash->size );
                EXIT_F();
                return rv;
        }

        while ( node_p->next_node != NULL ) {

                if ( key_cmp( laddr_p, raddr_p, node_p->next_node ) == 1 ) {
                        struct chlist_node *removed;

                        TRACE( "Removing from the list \n" );
                        removed = node_p->next_node;
                        node_p->next_node = removed->next_node;

                        TRACE( "[%p -> %p]\n", removed, node_p->next_node );

                        rv = removed->connection;
                        connection_hash->size--;
                        DPRINT( "Hashtable size %d \n", connection_hash->size );

                        mem_free( removed );
                        break;
                }
                node_p = node_p->next_node;
        }

        EXIT_F();
        return rv;
}

/**
 * Remove given connection from the hashtable 
 *
 * @ingroup chashtbl
 *
 * @param connection_hash Pointer to hashtable.
 * @param conn_p Pointer to the connection to remove.
 * @return Pointer to the connection removed from the hashtable.
 */ 
struct tcp_connection *chash_remove_connection( struct chashtable *connection_hash,
                struct tcp_connection *conn_p )
{
        return chash_remove(connection_hash, &conn_p->laddr, &conn_p->raddr );
}
        

/**
 * @defgroup cq Queue for connections. 
 * @note The cqueue can hold different connections, one connection can be only at one
 * queue at time. 
 * 
 */ 

/**
 * Initialize the connection queue.
 *
 * @ingroup cq
 *
 * @return Pointer to new allocated queue structure.
 */ 
struct cqueue *cqueue_init( void ) 
{
        struct cqueue *new;

        new = mem_alloc( sizeof( struct cqueue ) );
        new->size = 0;
        new->head = NULL;

        return new;
}

/**
 * Remove all connections from the queue and free any memory allocated for it. 
 * 
 * If @a free_connections is set to 1 the connections on the queue will also be
 * deallocated. Note that if the connections are being freed, make sure that
 * there are not any pointers for the structure hanging around (mostly in the
 * hash table).
 *
 * @ingroup cq
 * 
 * @param cqueue_p Pointer to the queue structure. 
 * @param free_connections Set to 1 if also the tcp_connections strutures on
 * the queue should be deinitialized.
 */ 
void cqueue_deinit( struct cqueue *cqueue_p, int free_connections )
{
        struct tcp_connection *con_p;

        while ( cqueue_p->size != 0 ) {
                con_p = cqueue_pop( cqueue_p );
                if ( free_connections )
                        connection_deinit( con_p );
        }
        mem_free( cqueue_p );
}


/**
 * Add connection to the head of given queue.
 * Connection is added to the head of the queue. Using this function the cqueue
 * can be used as a stack. 
 *
 * @ingroup cq
 * @see cqueue_pop() 
 *
 * @param queue_p Pointer to the queue structure.
 * @param elem_p Pointer to the connection to be added. 
 * @return New size for the queue.
 */ 
int cqueue_push( struct cqueue *queue_p, struct tcp_connection *elem_p )
{
        struct tcp_connection *old_head = queue_p->head;

        elem_p->prev = NULL;
        if ( old_head != NULL ) {
                old_head->prev = elem_p;
        }
        elem_p->next = old_head;
        queue_p->head = elem_p;
        queue_p->size++;

        DBG( "Queue size grown to %d \n", queue_p->size );
        TRACE( "Head{%p}->{%p} \n", queue_p->head, queue_p->head->next ); 

        return queue_p->size;
}

/**
 * Remove connection from queue. 
 *
 * @ingroup cq
 *
 * @param cqueue_p Pointer to the queue structure.
 * @param conn_p Pointer to the connection to be removed.
 * @return New size for the queue.
 */ 
int cqueue_remove( struct cqueue *cqueue_p, struct tcp_connection *conn_p )
{
        struct tcp_connection *tmp;

        if ( conn_p->prev == NULL ) {
                TRACE( "Removing connection from head \n" );
                cqueue_p->head = conn_p->next;
                if ( cqueue_p->head != NULL ) 
                        cqueue_p->head->prev = NULL;
#ifdef DEBUG 
                if ( cqueue_p->head == NULL ) {
                        TRACE( "Head{%p}\n", cqueue_p->head );
                } else {

                        TRACE( "Head{%p}->{%p} \n", cqueue_p->head, cqueue_p->head->next );
                }
#endif 
        } else {
                tmp = conn_p->prev;
                tmp->next = conn_p->next;
                if ( conn_p->next != NULL ) {
                        conn_p->next->prev = tmp;
                }
                TRACE( "{%p}->{%p}\n", tmp, tmp->next );
        }
        conn_p->prev = NULL;
        conn_p->next = NULL;
        cqueue_p->size--;
        DBG( "Queue size %d \n", cqueue_p->size );
        return cqueue_p->size;
}

/**
 * Get the connection from the head of the queue. 
 * Using this function the cqueue cn be used as a stack.
 *
 * @ingroup cq
 * @see cqueue_push()
 *
 * @param cqueue_p Pointer to the queue.
 * @return Pointer to the connection on the head of the queue or NULL if queue is empty.
 */ 
struct tcp_connection *cqueue_pop( struct cqueue *cqueue_p )
{

        struct tcp_connection *rv = NULL;

        if ( cqueue_p->head != NULL ) {
                rv = cqueue_p->head;
                cqueue_remove( cqueue_p, rv );
        }

        return rv;
}

/**
 * Get pointer to the first element on the queue.
 * The element is not removed from the queue, if the element should 
 * be removed, then use cqueue_pop().
 *
 * @ingroup cq
 * @see cqueue_pop()
 *
 * @param cqueue_p Pointer to the queue.
 * @return The first element on the queue (can be NULL ).
 */ 
struct tcp_connection *cqueue_get_head( struct cqueue *cqueue_p )
{
        return cqueue_p->head;

}

/**
 * Get the number of elements on the queue.
 *
 * @ingroup cq
 *
 * @param cqueue_p Pointer to the queue.
 * @return Number of elements on the queue.
 */    
int cqueue_get_size( struct cqueue *cqueue_p )
{
        return cqueue_p->size;
}

/**
 * @defgroup conn_utils Connection utilities.
 * Miscellanious utility functions for working with tcp_connection structs. 
 */

/**
 * Free all data allocated for a tcp_connection structure. 
 * Metadata and addresses are freed with the structure itself, hence the
 * structure is not usable after calling this function. 
 * @ingroup conn_utils
 *
 * @param con_p Pointer to the structure to free. 
 */  
void connection_deinit( struct tcp_connection *con_p )
{
        /*mem_free( con_p->metadata ); */
        mem_free( con_p );

} 

/** 
 * @brief Resolve the service name for the given port.
 * 
 * @param port  The port number to resolve
 * @param meta_p  Pointer to the metadata struct where the resolved service
 * name should be added. 
 */
static void resolve_servname( uint16_t port, struct conn_metadata *meta_p )
{
        struct servent *sent_p;
        sent_p = getservbyport( port, "tcp" );
        if ( sent_p == NULL ) {
                DBG( "getservbyport() returned NULL, the port was %d \n", port );
                meta_p->rem_servname[0] = '\0';
        } else {
                strncpy( meta_p->rem_servname, sent_p->s_name, ADDRSTR_BUFLEN -1 );
                meta_p->rem_servname[ADDRSTR_BUFLEN-1] = '\0';
                DBG( "Resolved servname %s\n", meta_p->rem_servname );
        }

}

/**
 * Resolve the remote hostname for connection. The resolved hostname is copied
 * to metadata information. The connection is also flagged as resolved and new
 * calls to this function will not redo the host resolution.
 *
 * @ingroup conn_utils
 *
 * @bug Only the remote address is resolved currently.
 * @param conn_p Pointer to the connection to resolve.
 * @return 0.
 */
int connection_resolve( struct tcp_connection *conn_p )
{
        struct conn_metadata *meta_p;
        struct hostent *hent_p;
        void *addr_p;
        int len, family;
        uint16_t r_port;
	struct in_addr dummy;
        struct tcp_connection *first_conn = NULL;

        meta_p = &conn_p->metadata;
        TRACE( "entered; flags 0x%.2x\n", meta_p->flags );
        if ( meta_p->flags & METADATA_RESOLVED ) {
                /* We have already resolved the addresses, 
                 * bail out 
                 */
                TRACE( "Exit1\n" );
                return 0;
        }

        r_port = connection_get_port( conn_p, 0 );
        resolve_servname( r_port, meta_p );

        if ( conn_p->group != NULL && conn_p->group->grp_filter != NULL ) {
                if ( filter_has_policy( conn_p->group->grp_filter, POLICY_REMOTE | POLICY_ADDR )) {
                        /* the group is filtered according to address, check if we can get 
                         * the address strings from the first connection.
                         */
                        first_conn = cqueue_get_head( conn_p->group->group_q );
                        if ( first_conn != NULL && 
                                        (first_conn->metadata.flags & METADATA_RESOLVED)) {
                                DBG("Getting the names from resolved first connection\n");
                                strncpy(meta_p->rem_hostname, first_conn->metadata.rem_hostname,
                                                ADDRSTR_BUFLEN-1);
                                meta_p->rem_hostname[ADDRSTR_BUFLEN-1] = '\0';
                                DBG( "Resolved hostname %s\n", meta_p->rem_hostname );
                                metadata_set_flag(conn_p->metadata, METADATA_RESOLVED );
                                return 0;
                        }
                }
        }

        if ( conn_p->family == AF_INET ) {
                addr_p = &((struct sockaddr_in *)&(conn_p->raddr))->sin_addr;
                len = sizeof( struct in_addr );
		family = conn_p->family;

                if ( ((struct in_addr *)addr_p)->s_addr == INADDR_ANY ) 
                        return 0;

        } else {
		if ( is_v6addr_v4mapped( (struct sockaddr_in6 *)&(conn_p->raddr) )) {
			/* v4 mapped ipv6 address, try to get the host name by
			 * using the v4 address. Is ugly, but seems to work.
			 */
			DBG( "We have v4 mapped v6 address, should do something\n" );
			//dummy.s_addr = ntohl(((struct sockaddr_in6 *)&(conn_p->raddr))->sin6_addr.s6_addr32[3]);
			dummy.s_addr = ((struct sockaddr_in6 *)&(conn_p->raddr))->sin6_addr.s6_addr32[3];
			addr_p = &dummy;
			TRACE( "v4 mapped, trying 0x%x\n", dummy.s_addr );
			len = sizeof( struct in_addr );
			family = AF_INET;
		} else {
			addr_p = &((struct sockaddr_in6 *)&(conn_p->raddr))->sin6_addr;
			len = sizeof( struct in6_addr );
			family = conn_p->family;

                        if ( memcmp( addr_p, &in6addr_any, sizeof(in6addr_any)) == 0 ) 
                                return 0;
		}
        }
#ifdef ENABLE_RESOLVE_POPUP
        resolve_popup( conn_p->metadata.raddr_string );
#endif /* ENABLE_RESOLVE_POPUP */
        hent_p = gethostbyaddr( addr_p, len, family );
#ifdef ENABLE_RESOLVE_POPUP
        resolve_done_popup( );
#endif /* ENABLE_RESOLVE_POPUP */
        if ( hent_p == NULL ) {
                DBG( "gethostbyaddr() returned NULL, address was %s \n", conn_p->metadata.raddr_string );
                meta_p->rem_hostname[0] = '\0';
        } else {
                strncpy( meta_p->rem_hostname, hent_p->h_name, ADDRSTR_BUFLEN -1 );
                meta_p->rem_hostname[ADDRSTR_BUFLEN-1] = '\0';
                DBG( "Resolved hostname %s\n", meta_p->rem_hostname );
        }
        metadata_set_flag(conn_p->metadata, METADATA_RESOLVED );
        TRACE( "Exit2; flags 0x%.2x\n",meta_p->flags );

        return 0;
}

/**
 * @brief Check if given IPv6 address is v4 address mapped to IPv6 address. 
 *
 * @param sin6 Pointer to sockaddr_in6 struct which contains the address to check.
 * @return 0 if address is not v4 mapped addres, 1 if it is.
 */
int is_v6addr_v4mapped( struct sockaddr_in6 *sin6 )
{
	int rv = 0;
	if ( sin6->sin6_addr.s6_addr32[0] == 0 && sin6->sin6_addr.s6_addr32[1] == 0 
			&& ntohl(sin6->sin6_addr.s6_addr32[2]) == 0xffff ) {
		rv = 1;
	}
	return rv;
}

/** 
 * @brief Get port number from connection.
 * @note The port is returned on host byte order.
 * @ingroup conn_utils
 * 
 * @param conn Connection to get the port number from.
 * @param local 1 if local port number should be returned, 0 if remote.
 * 
 * @return Port number for the connection.
 */
uint16_t connection_get_port( struct tcp_connection *conn, int local )
{
        struct sockaddr_storage *ssp;
        uint16_t rv;

        if ( local ) {
                ssp = &conn->laddr;
        } else {
                ssp = &conn->raddr;
        }

        if ( ssp->ss_family == AF_INET ) {
                rv = ((struct sockaddr_in *)ssp)->sin_port;
        } else {
                rv = ((struct sockaddr_in6 *)ssp)->sin6_port;
        }

        return ntohs(rv);
}





/** 
 * @brief Generate cacheable address strings for connection address. 
 * The generated address strings are stored to metadata of the connection. In
 * case there is an error, the address strings on metadata will be empty
 * strings 
 * @ingroup conn_utils
 * 
 * @param conn_p  Pointer to connection 
 * @return -1 on error, 0 on success.
 */
int connection_do_addrstrings( struct tcp_connection *conn_p )
{
        struct conn_metadata *meta_p;

        meta_p = &conn_p->metadata;
        meta_p->laddr_string[0] = '\0';
        meta_p->raddr_string[0] = '\0';

        if ( conn_p->laddr.ss_family == AF_INET ) {
                struct sockaddr_in *addr_p = (struct sockaddr_in *)&conn_p->laddr;

                if ( inet_ntop( addr_p->sin_family, 
                                &addr_p->sin_addr, 
                                meta_p->laddr_string,
                                ADDRSTR_BUFLEN ) == NULL ) {
                        WARN( "inet_ntop() failed, bailing out! \n" );
                        return -1;
                }
                addr_p = (struct sockaddr_in *)&conn_p->raddr;


                if ( inet_ntop( addr_p->sin_family,
                                &addr_p->sin_addr, 
                                meta_p->raddr_string,
                                ADDRSTR_BUFLEN ) == NULL ) {
                        WARN( "inet_ntop() failed, bailing out! \n" );
                        return -1;
                }
        } else {
                struct sockaddr_in6 *addr_p = (struct sockaddr_in6 *)&conn_p->laddr;

                if ( inet_ntop( addr_p->sin6_family,
                                &addr_p->sin6_addr, 
                                meta_p->laddr_string,
                                ADDRSTR_BUFLEN ) == NULL ) {

                        WARN( "inet_ntop() failed, bailing out! \n" );
                        return -1;
                }
                addr_p = (struct sockaddr_in6 *)&conn_p->raddr;

                if ( inet_ntop( addr_p->sin6_family,
                                &addr_p->sin6_addr, 
                                meta_p->raddr_string,
                                ADDRSTR_BUFLEN ) == NULL ) {

                        WARN( "inet_ntop() failed, bailing out! \n" );
                        return -1;
                }
        }
        return 0;
}

