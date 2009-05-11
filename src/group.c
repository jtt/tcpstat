/**
 * @file group.c 
 * @brief This module holds functions for handling connection groups and 
 * group lists.
 *
 *  Copyright (c) 2006, J. Taimisto
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
 * $Id: group.c 169 2008-06-01 07:16:22Z jtt $
 */ 
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>

#define DBG_MODULE_NAME DBG_MODULE_GRP

#include "defs.h"
#include "debug.h"
#include "parser.h"
#include "connection.h"


/** @defgroup cgrp Group holding a set of connections. */

/** 
 * @brief Initialize a connection group.
 * @ingroup cgrp
 * 
 * @return Pointer to new connection group.
 */
struct group *group_init( void )
{
        struct group *group_p;

        group_p = mem_alloc( sizeof( struct group ) );
        memset( group_p, 0, sizeof( *group_p ));

        group_p->grp_filter = NULL;
        group_p->group_q = NULL;
        group_p->parent = NULL;
        group_p->next = NULL;

        return group_p;
}

/** 
 * @brief Free all memory allocated for connection group.
 * @ingroup cgrp
 * The memory allocated for the group is freed, the internal connection queue
 * is emptied and if @a free_connection is 1 the connections (also the parent
 * connection if one is set) are deinited.
 * 
 * @param group_p Pointer to the group to deinit.
 * @param free_connections 1 if all connections on this group should be deleted
 * too.
 */
void group_deinit( struct group *group_p, int free_connections )
{
        if ( free_connections && group_p->parent != NULL ) {
                connection_deinit( group_p->parent );
        }

        if ( group_p->group_q != NULL ) {
                cqueue_deinit( group_p->group_q, free_connections );
        }
        if ( group_p->grp_filter != NULL ) {
                filter_deinit( group_p->grp_filter, 0 );
        }
        mem_free( group_p );
}

/** 
 * @brief Set filter for the group.
 *
 * As a side effect the group pointer in filter will be set to point to the
 * group.
 * 
 * @param group_p Pointer to the group to set the filter.
 * @param filt Filter to set.
 */
void group_set_filter( struct group *group_p, struct filter *filt )
{
#ifdef DEBUG
        if ( group_p->grp_filter != NULL ) 
                WARN("There is already filter set for the group!\n");
#endif /* DEBUG */
        group_p->grp_filter = filt;
        filt->group = group_p;
}

         

/** 
 * @brief Match a given connection against group filter. 
 * Connection is considered to match if it matches against all policies set on
 * the filter. If no filter is set to the group the connection is considered to
 * have matched.
 * 
 * @param group_p Pointer to group to match to.
 * @param conn_p Pointer to the connection to match.
 * @ingroup cgrp
 * 
 * @return 1 in case of match, 0 otherwise.
 */
int group_match( struct group *group_p, struct tcp_connection *conn_p )
{
        /* Match if no filter is set */
        int rv = 1;

        if( group_p->grp_filter != NULL ) 
                rv = filter_match( group_p->grp_filter, conn_p );

        TRACE( "returning %d \n", rv );
        return rv;
}

/** 
 * @brief Add connection to group.
 * @ingroup cgrp
 * @note The connection is not matched against group selector.
 * @param group_p Pointer to the group to add to.
 * @param conn_p Pointer to the connection to add.
 */
void group_add_connection( struct group *group_p, struct tcp_connection *conn_p ) 
{
        if ( group_p->group_q == NULL ) {
                /* Lazy init of the queue */
                group_p->group_q = cqueue_init();
        }
        cqueue_push( group_p->group_q, conn_p );
        conn_p->group = group_p;
}   

/** 
 * @brief Remove connection from group.
 * @note the group pointer in connection is set to NULL.
 *
 * @bug what if the connection is not in this group, the group pointer will be
 * set to NULL anyway.
 *
 * @ingroup cgrp
 * @param group_p Pointer to the group to remove from. 
 * @param conn_p Connection to remove from the group.
 */
void group_remove_connection( struct group *group_p, struct tcp_connection *conn_p )
{
        if ( group_p->group_q == NULL ) {
                ERROR( "Trying to remove from NULL queue \n" );
        } else {
                cqueue_remove( group_p->group_q, conn_p );
                conn_p->group = NULL;
        }
} 

/** 
 * @brief Match connection against groups selector and add connection if it
 * matches.
 * @ingroup cgrp
 * @see group_add_connection()
 * @see group_match() 
 * @param group_p Pointer to the group to add to.
 * @param conn_p Pointer to the connection to match and add.
 * 
 * @return 1 if the group mathced and was added. 0 otherwise.
 */
int group_match_and_add( struct group *group_p, struct tcp_connection *conn_p )
{
        int rv;

        rv = group_match( group_p, conn_p );
        if ( rv == 1 ) {
                group_add_connection( group_p, conn_p );
        }

        return rv;
}

/** 
 * @brief Get the first connection on the group.
 * @ingroup cgrp
 * 
 * @param group_p Pointer to the group
 * 
 * @return Pointer to the first connection on the group, or NULL if no
 * connections are on the group.
 */
struct tcp_connection *group_get_first_conn( struct group *group_p ) 
{
        struct tcp_connection *conn_p = NULL;

        if ( group_p->group_q != NULL ) {
                conn_p = cqueue_get_head( group_p->group_q );
        }

        return conn_p;
}

/** 
 * @brief Get the number of connections on the group.
 * 
 * @ingroup cgrp
 * @param group_p Pointer to the group.
 * 
 * @return Number of connections on the group.
 */
int group_get_size( struct group *group_p )
{
        if ( group_p->group_q != NULL ) {
                return cqueue_get_size( group_p->group_q );
        } else {
                return 0;
        }
}

/**
 * @brief Get the number of new connections on the group
 *
 * @ingroup cgrp
 * @param group_p Pointer to the group
 * @return Number of new connections on the group.
 */
int group_get_newcount( struct group *group_p ) {
        
        struct tcp_connection *conn_p;
        int count = 0;

        if ( group_get_size( group_p ) == 0 )
                return 0;

        conn_p = group_get_first_conn( group_p );
        while ( conn_p != 0 ) {
                if ( metadata_is_new( conn_p->metadata ) )
                        count++;
                conn_p = conn_p->next;
        }

        return count;
}



/** 
 * @brief Get pointer to the groups internal queue.
 * 
 * @ingroup cgrp
 * @param group_p Pointer to the group.
 * 
 * @return Pointer to the cqueue holding connections for this group.
 */
struct cqueue *group_get_queue( struct group *group_p )
{
        return group_p->group_q;
}



/** 
 * @brief Get the parent connection (if one is set) for given group 
 * 
 * @ingroup cgrp
 * @param group_p Pointer to the group.
 * 
 * @return Pointer to the parent connection, if one is set. NULL otherwise.
 */
struct tcp_connection *group_get_parent( struct group *group_p )
{
        return group_p->parent;
}

/** 
 * @brief Set the parent connection.
 * 
 * @ingroup cgrp
 * @param group_p Pointer to the group to set the parent connection to.
 * @param conn_p Pointer to the connection to set as parent.
 */
void group_set_parent( struct group *group_p, struct tcp_connection *conn_p )
{
        group_p->parent = conn_p;
}

/** 
 * @brief Get the policy flags for the groups selector.
 * 
 * @ingroup cgrp
 * @param group_p Pointer to the group. 
 * 
 * @return Policy flags for the groups selector.
 */
uint16_t group_get_policy( struct group *group_p )
{
        if ( group_p->grp_filter ) 
                return group_p->grp_filter->policy;

        return 0;
}

/**@defgroup cglst List holding connection groups. */

/** 
 * @brief Initialize connection list.
 * @ingroup cglst
 * 
 * @return Pointer to fresh connection group list.
 */
struct glist *glist_init()
{
        struct glist *list_p = mem_alloc( sizeof( struct glist));
        list_p->size = 0;
        list_p->head = NULL;

        return list_p;
}

                

/** 
 * @brief Add group to list.
 * @ingroup cglst
 * 
 * @param list_p Pointer to the list.
 * @param grp Pointer to the group to add.
 * 
 * @return number if groups on the list.
 */
int glist_add(struct glist *list_p, struct group *grp )
{
        grp->next = list_p->head;
        list_p->head = grp;

        DBG( "Added group[%p], ->[%p]\n", grp, grp->next );

        list_p->size++;

        return list_p->size;
}

/** 
 * @brief Remove given group from list.
 * 
 * @ingroup cglst
 * @param list_p Pointer to the list.
 * @param grp Pointer to the group to remove.
 * 
 * @return Pointer to the removed group, or NULL on error.
 */
struct group *glist_remove( struct glist *list_p, struct group *grp )
{
        struct group *rv = NULL;

        if ( list_p->head  != NULL && list_p->head == grp ) {
                DBG( "Removing group from the head\n" );
                list_p->head = grp->next;
                DBG( "new head [%p] \n" );
                rv = grp;
                list_p->size--; 
                return rv;
        } 
        rv = list_p->head;
        while ( rv != NULL ) {
               if ( rv->next == grp ) {
                      DBG( "Found group, removing\n" );
                      rv->next = grp->next;
                      rv = grp;
                      list_p->size--; 
                      break;
               }
               rv = rv->next;
        }

        return rv;
}

/** 
 * @brief Delete a group from list if the group is empty.
 * 
 * Deletes, removes and deinitializes, a group from the list if it is empty.
 * Group is considered to be empty if it does not have any connections and has
 * no parent set.
 *
 *@see glist_remove()
 *@note Pointer to next group is returned. Also if @a grp is not empty. 

 *@bug NULL is returned on error, NULL can also be a return value in success. 
 *
 *@ingroup cglst
 *
 * @param list_p Pointer to the list
 * @param grp Connection to delete.
 * 
 * @return Pointer to the next group on the list (can be NULL) or NULL on error.
 */
struct group *glist_delete_grp_if_empty( struct glist *list_p, struct group *grp )
{
        struct group *rv = grp->next;

        if ( group_get_size(grp) == 0 && group_get_parent(grp) == NULL ) {
                DBG("Deleting empty group from glist\n" );
                if ( glist_remove(list_p, grp) == NULL ) {
                        WARN("Could not remove group from list!\n" );
                        return NULL;
                }
                /* Can be NULL, hence NULL is also valid return value */
                group_deinit(grp, 0);
        } 
        return rv;
}

/**
 * Get the number of connections on all groups on the list.
 * @note Parent connections are not counted. 
 * @ingroup cglst
 *
 * @param list_p Pointer to the list.
 * @return Number of connections on all the groups on the list.
 */
int glist_connection_count( struct glist *list_p ) 
{
        struct group *iter;
        int size = 0;

        if ( list_p->size == 0 )
                return 0;

        iter = list_p->head;

        while( iter != NULL ) {
                size = size + group_get_size( iter );
                iter = iter->next;
        }

        return size;
}

/** 
 * @brief Get the number of parents on all groups on the list.
 * 
 * @see glist_connection_count()
 * @ingroup cglst
 * @param list_p Pointer to the list
 * @return Number of parents on connections of the list.
 */
int glist_parent_count( struct glist *list_p ) 
{
        struct group *iter;
        int size = 0;

        if ( list_p->size == 0 )
                return 0;

        iter = list_p->head;

        while( iter != NULL ) {
                if ( iter->parent ) 
                        size++;

                iter = iter->next;
        }

        return size;
}
        


/** 
 * @brief Deinitialize connection group list and free all allocated memory.
 * Every group on the list is deinitialized and connections on those groups will be freed. 
 * If @a free_connections is 1, then all connections on the groups will be
 * deinitialized. 
 * 
 * @ingroup cglst
 * @param list_p Pointer to the list to deinit.
 * @param free_connections 1 if also connections on the groups should be freed.
 */
void glist_deinit( struct glist *list_p, int free_connections )
{
        struct group *grp;

        while ( list_p->size != 0 ) {
                grp = glist_remove( list_p, list_p->head );
                if ( grp != NULL ) {
                        group_deinit( grp, free_connections );
                }
        } 

        mem_free( list_p );
}

/** 
 * @brief Get the number of groups on the list.
 * 
 * @ingroup cglst
 * @param list_p Pointer to the list.
 * 
 * @return Number of connections on the list.
 */
int glist_get_size( struct glist *list_p ) 
{
        return list_p->size;
} 

/** 
 * @brief Get the number of non-empty groups on the list. 
 * 
 * Get the number of groups that contain any elements. On this case, parents
 * are not counted as elements. Hence even if this function returns 0, the
 * groups may contain parents. 
 *
 * @ingroup cglst
 * @param list_p Pointer to the list
 * 
 * @return Number of groups containing any elements. 
 */
int glist_get_size_nonempty( struct glist *list_p ) 
{
        struct group *grp;
        int count = 0;

        glist_foreach_group( list_p, grp ) {

                if ( group_get_size( grp ) != 0 ) 
                        count++;
        }

        return count;
}


/** 
 * @brief Get pointer to the first group on the list.
 * 
 * @ingroup cglst
 * @param list_p Pointer to the list.
 * 
 * @return Pointer to the first group on list.
 */
struct group *glist_get_head( struct glist *list_p )
{
        return list_p->head;
}


