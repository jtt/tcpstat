/**
 * @file stat.c
 * @brief This module contains functions for handling the connections and
 * related info.
 * 
 * These functions usually are used when handling the information
 * gathered by the scouts. One can view them as general functions doing the
 * dirty work to keep the program running.
 * 
 * Copyright (c) 2005, J. Taimisto
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

#define DBG_MODULE_NAME DBG_MODULE_STAT

#include "defs.h"
#include "debug.h"
#include "parser.h"
#include "connection.h"
#include "stat.h"
#include "rtscout.h"
#include "ifscout.h"
#include "pidscout.h"

/*#define LINELEN 160 */

/** 
 * @brief Resolve the appropriate route for given connection.
 *
 * The resolved route is put to the metadata on the connection, note that the
 * routes should have been scanned before this function is called.
 *
 * No route will be resolved for connections on state TCP_LISTEN
 * 
 * @param ctx Pointer to the global context
 * @param conn_p  Pointer to the connection whose routing information should be printed.
 * 
 */
#ifdef ENABLE_ROUTES
void resolve_route_for_connection( struct stat_context *ctx,
                struct tcp_connection *conn_p)
{
        struct ifinfo *iinfo_p;

        if ( conn_p->state == TCP_LISTEN )
                return;

        iinfo_p = get_ifinfo_by_name( ctx->iftab,
                        conn_p->metadata.ifname );
        if ( iinfo_p != NULL ) { 
                if ( iinfo_p->routes == NULL ) {
                        WARN("No routes for interface %s \n", iinfo_p->ifname );
                } else {
                        conn_p->metadata.route = rtlist_find_info(
                                        iinfo_p->routes, conn_p );
                }
        }
        return;
}
#endif /* ENABLE_ROUTES */

/** 
 * @brief Add new connection to system.
 * Metadata information is filled and the new connection is added to the
 * hashtable. If the connection is not in LISTEN state, it is also added to the
 * new queue for rotating. 
 *
 * @note If @a info_p is not NULL, then connection is added to the group found on the
 * structure. Also listening connections. 
 * 
 * @param conn_p Pointer to the new connection to add.
 * @param inode Inode number for the connection (filled to metadata info).
 * @param info_p Pointer to pidinfo structure if we are following PIDs or NULL
 * if not.
 * @param ctx Pointer to the global context.
 */
static void insert_new_connection( struct tcp_connection *conn_p, 
#ifdef ENABLE_FOLLOW_PID
                ino_t inode, struct pidinfo *info_p, 
#endif /* ENABLE_FOLLOW_PID */
                struct stat_context *ctx )
{

        /* Fill in the metadata */
        conn_p->metadata.added = time( NULL );  
        metadata_set_flag( conn_p->metadata, METADATA_NEW );
#ifdef ENABLE_FOLLOW_PID
        conn_p->metadata.inode = inode;
#endif /* ENABLE_FOLLOW_PID */
        conn_p->metadata.ifname = ifname_for_addr( ctx->iftab, &(conn_p->laddr) );
#ifdef ENABLE_ROUTES 
        resolve_route_for_connection( ctx, conn_p );
#endif /* ENABLE_ROUTES */

        connection_do_addrstrings( conn_p );

        /* Put the connection to hashtable */

        chash_put(ctx->chash, conn_p );

        if ( metadata_is_ignored( conn_p->metadata ) )
                return;

#ifdef ENABLE_FOLLOW_PID
        if ( info_p != NULL ) {
                /* Add the connection to the group on pidinfo struct instead of
                 * pushing it to newq. Also connections on LISTEN state will be
                 * added to it.
                 */
                group_add_connection(info_p->grp, conn_p);
                return;
        }
#endif /* ENABLE_FOLLOW_PID */
        if ( conn_p->state == TCP_LISTEN ) {
                struct filter *filt;
                /* New listen connection, create group for it. */
                struct group *grp = group_init();
                group_set_parent( grp, conn_p );
                filt = filter_from_connection( conn_p, (POLICY_LOCAL | POLICY_PORT | POLICY_AF ),
                                FILTERACT_GROUP );
                group_set_filter( grp, filt );
                glist_add( ctx->listen_groups, grp );

        } else {
                /* Add to the new queue, to be compared against existing groups. */
                cqueue_push( ctx->newq, conn_p );
        }

}

                        
/** 
 * @brief Insert a connection with given properties to the system. 
 * The connection can be new, just found, or old one that has been detected
 * earlier. If connection is new, it is inserted to the hashtable and added to
 * the newqueue to be placed to right group when rotating the newqueue. If
 * connection has been detected earlier, its possible state change is observed.     
 *
 * @todo Has quite a lot of parameters, any better way to do this?
 * @todo Should this be void instead of returning 0.
 * 
 * @param local_addr Local address for the connection.
 * @param remote_addr Remote address for the connection. 
 * @param state State of the connection.
 * @param inode Inode for the socket allocated for this connection. 
 * @param ctx Context holding the tables etc. 
 * 
 * @return always 0.
 */
int insert_connection( struct sockaddr_storage *local_addr, struct sockaddr_storage *remote_addr,
                enum tcp_state state,
#ifdef ENABLE_FOLLOW_PID
                ino_t inode,
#endif /* ENABLE_FOLLOW_PID */
                struct stat_context *ctx )
{
        struct group *grp;
#ifdef ENABLE_FOLLOW_PID
        struct pidinfo *info_p = NULL;
#endif /* ENABLE_FOLLOW_PID */
        struct filter *filt;

        struct tcp_connection *conn_p = chash_get(ctx->chash, local_addr, remote_addr );
        
        if ( conn_p == NULL ) {
#ifdef ENABLE_FOLLOW_PID
                if ( OPERATION_ENABLED(ctx,OP_FOLLOW_PID) ) {
                        info_p = get_pidinfo_by_inode( inode, ctx->pinfo );
                        if (info_p == NULL ) {
                                /* Does not belong to process we are following. */
                                TRACE( "Discarding connection since inode doesn't match!\n" );
                                return 0;
                        } 
                }
#endif /* ENABLE_FOLLOW_PID */
                DBG( "New connection\n" );

                        
                ctx->new_count++;
                conn_p = mem_alloc( sizeof( struct tcp_connection ));
                memset( conn_p, 0, sizeof( struct tcp_connection ));
                memcpy( &(conn_p->laddr),local_addr, sizeof(*local_addr) );
                memcpy( &(conn_p->raddr),remote_addr, sizeof( *remote_addr ) );
                conn_p->state = state;
                conn_p->family = local_addr->ss_family;

                filt = filtlist_match( ctx->filters, conn_p );
                if ( filt != NULL ) {
                        if ( filt->action == FILTERACT_IGNORE ) {
                                metadata_set_flag( conn_p->metadata,
                                                METADATA_IGNORED );
                                group_add_connection( filt->group,
                                                conn_p );
                        } else if ( filt->action == FILTERACT_WARN ) {
                               metadata_set_flag( conn_p->metadata,
                                              METADATA_WARN );
                        } 
                }

#ifdef ENABLE_FOLLOW_PID
                insert_new_connection( conn_p, inode, info_p, ctx );
#else 
                insert_new_connection( conn_p, ctx );
#endif /* ENABLE_FOLLOW_PID */

        } else {
                TRACE( "Found connection data \n" );
                if ( metadata_is_touched( conn_p->metadata ) ) {
                        WARN( "Double entry in /proc/ !!!\n" );
                        /* We have handled this connection already, but its
                         * information might have changed. 
                         * XXX : Are all flags up-to-date..
                         */ 
                        ctx->total_count--;
                } 
                if ( conn_p->state != state ) {
                        grp = conn_p->group;
                        DBG( "State changed %d -> %d \n", conn_p->state, state );
                        conn_p->state = state;
                        metadata_set_flag( conn_p->metadata, METADATA_STATE_CHANGED );
                        if ( grp && ( group_get_policy( grp ) & POLICY_STATE ) ) {
                                /* The connection belongs to group
                                 * which is grouped by state, we need
                                 * to take the connection out from the
                                 * group
                                 */
                                group_remove_connection( grp, conn_p );
                                /* It will be added to proper group via newq. */
                                cqueue_push( ctx->newq, conn_p );
                        }
                }
        }  
        ctx->total_count++;
        metadata_set_flag( conn_p->metadata, METADATA_UPDATED );

        return 0;
}

/** 
 * @brief Add connection to suitable group on grouplist. 
 * 
 * Iterates through groups on grouplist and adds given connection to first
 * group that has selector matching for the connection.
 * 
 * @param list_p Pointer to the grouplist.
 * @param con_p Connection to try to add. 
 * 
 * @return 0, if no group with matching selectors found, 1 if group is found.  
 */
static int iterate_glist_with_connection( struct glist *list_p, struct tcp_connection *con_p )
{
        struct group *grp_p;
        int found = 0; /* Set to 1 if found a matching group */

        glist_foreach_group( list_p, grp_p ) {
                if ( group_match_and_add( grp_p, con_p ) == 1 ) {
                        found = 1;
                        TRACE( "Found match!\n" );
                        break;
                }
        }

        return found;
}


/** 
 * @brief Go through all connection on newqueue and add them to proper groups. 
 * All connections are either added to groups with matching selectors or new
 * group for the connection is created. First all listen groups are iterated,
 * if no match is found it is assumed that the connection is outbound. 
 * 
 * @param ctx Pointer to the context holding the newqueue and the grouplists.  
 */
void rotate_new_queue( struct stat_context *ctx )
{
        struct tcp_connection *con_p;
        struct group *grp_p;
        struct filter *filt;

        con_p = cqueue_pop( ctx->newq );
        while ( con_p != NULL ) {

                /* Check for incoming connection to any port we have listening
                 * socket
                 */ 
                TRACE( "Iterating listen_groups \n" );
                if ( iterate_glist_with_connection( ctx->listen_groups, con_p ) ) {
                        con_p->metadata.dir = DIR_INBOUND;
                        con_p = cqueue_pop( ctx->newq );
                        continue;
                }
                TRACE( "Done\n" );
                /* This is not incoming connection, hence set the metadata
                 * info..
                 * XXX: Not 100% accurate.
                 */ 
                con_p->metadata.dir = DIR_OUTBOUND;
                TRACE( "Iterating outgoing groups \n" );
                if ( iterate_glist_with_connection( ctx->out_groups, con_p ) ) {
                        con_p = cqueue_pop( ctx->newq );
                        continue;
                }
                TRACE( "Done\n" );

               /* No match for any groups we have, create a new group for this
                * connection 
                */ 
                TRACE( "Generating new group for the connection \n" );
                grp_p = group_init();
                filt = filter_from_connection( con_p, ctx->common_policy, FILTERACT_GROUP );
                group_set_filter( grp_p, filt );
                group_add_connection( grp_p, con_p );

                glist_add( ctx->out_groups, grp_p );
                con_p = cqueue_pop( ctx->newq );

        }

}

#define LINGER_MAX_TIME 5

/** 
 * @brief Handle lingerin issues of dead connection. 
 * The connection is put into TCP_DEAD state and will be held there for a
 * while.
 *
 * @param con_p Pointer to a connection which is dead and should be lingered. 
 * @return 0 if the connection should not be yet removed, non-zero if the
 * connection can be dropped. 
 */
static int do_lingering( struct tcp_connection *con_p ) 
{
        int rv = 0;
        time_t now = time( NULL );
        if ( con_p->state != TCP_DEAD ) {
                DBG( "Starting to linger connection\n" );
                con_p->metadata.linger_secs = now + LINGER_MAX_TIME;
                con_p->state = TCP_DEAD;
        } else {
                if ( con_p->metadata.linger_secs < now ){
                        rv = 1;
                        DBG( "Connection linger timed out" );
                }
        }
        return rv;
}



/** 
 * @brief Delete closed connections from given group.
 * Deletes all connections that are assumed closed (metadata doesn't have any
 * update) from given group. 
 * @note The connections removed are also deleted.
 *
 * @param table_p Pointer to hashtable from where the connection should also be
 * deleted (NULL if connection should not be deleted from any hashtable ).
 * @param grp Pointer to group from where the closed connections are searched.
 * @param do_linger nonzero if dead connections should be lingered. 
 * 
 * @return Number of connections removed or lingering.
 */
static int purge_closed_from_group( struct chashtable *table_p, struct group *grp,
               int do_linger )
{ 

        int cnt = 0;
        struct tcp_connection *con_p = group_get_first_conn( grp );
        /* Iterate though all connections */
        while ( con_p != NULL ) {
                if ( ! metadata_is_touched( con_p->metadata ) ) {
                        cnt++; 
                        if ( do_linger && !do_lingering( con_p ) ) {
                                con_p = con_p->next;
                                continue;
                        }
                        struct tcp_connection *tmp_con;
                        DBG( "Removing closed connection {%p} \n", con_p );
                        DBG( "Removing connection with state %d\n", con_p->state );
                        /* Save pointer to next before we remove the
                         * connection.
                         */
                        tmp_con = con_p->next;

                        group_remove_connection( grp, con_p );
                        if ( table_p != NULL ) {
                                chash_remove_connection(table_p, con_p );
                        }
                        connection_deinit( con_p );
                        con_p = tmp_con;
                } else {
                        con_p = con_p->next;
                }
        }
        return cnt;
}


/** 
 * @brief Delete all connections assumed closed.
 *
 * All groups (listen and outgoing) are looked and all connections whose
 * metadata has not been touched will be deleted. Groups who lose all
 * connections will be deleted. 
 * 
 * @param ctx Pointer to the main context.
 * @param closed_cnt Number of closed connections.
 * 
 * @return Number of connections that could not be deleted.
 */
int purge_closed_connections( struct stat_context *ctx, int closed_cnt )
{
        struct group *grp;
#ifdef ENABLE_FOLLOW_PID
        struct pidinfo *info_p;
#endif /* ENABLE_FOLLOW_PID */
        struct filter *filt;

        TRACE( "Purging %d connections \n", closed_cnt );

        /* first, lets see if there are any on filtered connections */
        filtlist_foreach_filter( ctx->filters, filt ) {
                closed_cnt = closed_cnt - purge_closed_from_group(
                                ctx->chash, filt->group, 
                                OPERATION_ENABLED(ctx,OP_LINGER) );
        }



        /* if we are follwing PIDs connections are stored to groups on pidinfo*/
#ifdef ENABLE_FOLLOW_PID
        if ( OPERATION_ENABLED(ctx, OP_FOLLOW_PID) ) {
                info_p = ctx->pinfo;
                while (info_p != NULL && closed_cnt > 0) {
                        closed_cnt = closed_cnt - purge_closed_from_group(
                                        ctx->chash, info_p->grp, 
                                        OPERATION_ENABLED(ctx,OP_LINGER) );
                        info_p = info_p->next;
                }
                return closed_cnt;
        }
#endif /* ENABLE_FOLLOW_PID */
         
        grp = glist_get_head( ctx->out_groups );
        while ( grp != NULL  && closed_cnt > 0 ) {
                closed_cnt = closed_cnt - purge_closed_from_group(ctx->chash, 
                                grp, OPERATION_ENABLED(ctx,OP_LINGER) );
                grp = glist_delete_grp_if_empty(ctx->out_groups, grp );
        }

        TRACE( "Purging %d connections from incoming \n", closed_cnt );
        grp = glist_get_head( ctx->listen_groups );
        while ( grp != NULL && closed_cnt > 0 ) {
                struct tcp_connection *con_p = group_get_parent( grp );
                if ( con_p && (! metadata_is_touched( con_p->metadata )) ) {
                        DBG( "Purging listening parent! {%p} \n", con_p );
                        grp->parent = NULL;
                        chash_remove_connection(ctx->chash, con_p );
                        connection_deinit( con_p );
                        closed_cnt--;
                }
                closed_cnt = closed_cnt - purge_closed_from_group(ctx->chash, 
                                grp, OPERATION_ENABLED(ctx,OP_LINGER) );
                grp = glist_delete_grp_if_empty(ctx->listen_groups, grp );
        }

        TRACE( "closed_cnt = %d \n", closed_cnt );
        return closed_cnt;
}

/** 
 * @brief Switch the common grouping policy of outgoing connections. 
 *
 * The grouping policy of outgoing connections is changed to given one and all
 * existig connections are regrouped. This essentially means that all existing
 * outgoing groups are deleted and new groups matching the new grouping are
 * generated. 
 *
 * @note Uses rotate_new_queue(), hence any rewrites there might affect the
 * behaviour here.
 * 
 * @param ctx Pointer to the main context. 
 * @param new_grouping Flags for new grouping. 
 */
void switch_grouping( struct stat_context *ctx, policy_flags_t new_grouping )
{
        struct tcp_connection *conn_p;
        struct group *grp;
        struct cqueue *queue_p;

        if ( ctx->common_policy == new_grouping ) 
                return;

        /* We go through all outgoing groups, remove all connections, add them
         * to newqueue and then rotate the newqueue. This way (hopefully) all
         * outgoing connections get regrouped and no stale conn_p->group
         * pointers are left hanging. 
         */
        glist_foreach_group( ctx->out_groups, grp ) {

                queue_p = group_get_queue(grp);
                while ( cqueue_get_size( queue_p ) > 0 ) {
                        conn_p = cqueue_pop( queue_p );
                        conn_p->group = NULL;
                        cqueue_push( ctx->newq, conn_p );
                }
        }
#ifdef DEBUG
        /* This is just to make sure */
        if ( glist_get_size_nonempty( ctx->out_groups ) != 0 ) {
                ERROR( "Connections left behind while regrouping, crash is imminent\n" );
        }
#endif /* DEBUG */

        glist_deinit( ctx->out_groups,0 );
        ctx->common_policy = new_grouping;
        TRACE("Changed the default grouping to 0x%x\n", new_grouping );
        ctx->out_groups = glist_init();
        rotate_new_queue( ctx );
}


/** 
 * @brief Clear metadata flags from all the connections on given group.
 *
 * The flags in metadata which are used to determine active connections
 * are cleared from all the connections on the given group. 
 *
 * @see clear_metadata_flags()
 * @see metadata_clear_flags()
 * 
 * @param grp The group whose connections should be cleared.
 */
void group_clear_metadata_flags( struct group *grp )
{
        struct tcp_connection *conn;

        conn = group_get_parent( grp );
        if ( conn != NULL )
                metadata_clear_flags( conn->metadata );

        conn = group_get_first_conn( grp );
        while ( conn != NULL ) {
                metadata_clear_flags( conn->metadata );
                conn = conn->next;
        }
}



/** 
 * @brief Clear the metatda from all the connections on all the groups on given
 * list.
 *
 * Since we use the connection metadta flags to determine those connections
 * which are not yet active, every update round all the metadata flags from
 * active connections have to be cleared. 
 * 
 * @param list Pointer to the list containing the groups whose connections
 * should be cleared.
 */
void clear_metadata_flags( struct glist *list )
{
        struct group *grp;

        glist_foreach_group( list, grp ) {
                group_clear_metadata_flags( grp );
        }
}

/** 
 * @brief Get the number of connections that are currently being ignored. 
 * 
 * @param ctx Pointer to the global context.
 * 
 * @return Number of connections that are currently being ingored.
 */
int get_ignored_count( struct stat_context *ctx )
{
        struct filter *filt; 
        int count = 0;

        filtlist_foreach_filter( ctx->filters, filt ) {
                if ( filt->action == FILTERACT_IGNORE ) 
                        count += filter_get_connection_count( filt );
        }

        return count;
}




        



