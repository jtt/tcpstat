/**
 * @file filter.c 
 * @brief This module contains the functions for filtering connections based on
 * selectors like address and port.
 *
 * Filters can be grouped together to form a ordered set, a ruleset. Ruleset
 * can be used to fnd connections matching given selectors and define actions
 * for matching connections. 
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
 * $Id$
 */ 
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>

#define DBG_MODULE_NAME DBG_MODULE_FILTER

#include "defs.h"
#include "debug.h"
#include "connection.h"
//#include "filter.h"


/**
 * @defgroup filter_api API for using filters
 *
 * Filters can be used to filter connections based on some criteria. Currently
 * avaialable criterias are:
 *  - Source or destination address
 *  - Source or destination port
 *  - State of the connection
 *
 * The filter has a <i>policy</i> which defines what criterias are active in
 * the filter. The policy is set with the POLICY flags. Flags can be combined
 * to have desired policy.
 */

/** 
 * @brief Initialize new filter with given policy and action. 
 *
 * If @a init_group is non-zero, the associated connection group for the filter
 * is also initialized. 
 * 
 * @ingroup filter_api
 * 
 * @param policy Policy for the filter
 * @param act Action for the filter
 * @param init_group If non-zero, the associated group is also initialized.
 * 
 * @return New filter.
 */
struct filter *filter_init( policy_flags_t policy, enum filter_action act,
                int init_group )
{
        struct filter *filt;

        filt = mem_alloc( sizeof( *filt));
        memset( filt, 0, sizeof( *filt ));
        filt->action = act;
        filt->policy = policy;
        if ( init_group )
                filt->group = group_init();

        return filt;
}

/** 
 * @brief Deinitialize the given filter. 
 *
 * If @a deinit_group is non-zero, then the associated group is also deinitialized.
 * @note If the associated group is deinitialized, then the connections on the
 * group are also deinitialized. This might lead into all kinds of nastiness if
 * there are pointers to these groups around (especially in the hash table).
 * 
 * @ingroup filter_api
 *
 * @param filt Filter to deinitialize
 * @param deinit_group If non-zero, deinitialize also the associated group.
 */
void filter_deinit( struct filter *filt, int deinit_group )
{
        if ( deinit_group && filt->group != NULL )
                group_deinit( filt->group, 1 );

        mem_free( filt );
}

/**
 * Create new filter that should match given connection. Filter is created to
 * match the given connection with selectors given in @a selector_flags.
 *
 * @ingroup filter_api
 * @param conn_p Pointer to connection to create filter from. 
 * @param selector_flags Flags for policy according to which the filter will be
 * formed. The filter will have these selectors set. 
 * @param act The action for this filter. 
 * @return New filter that would match the connection given with the given selectors.
 */
struct filter *filter_from_connection( struct tcp_connection *conn_p,
                policy_flags_t selector_flags, enum filter_action act )
{
        struct filter *filt;

        filt = filter_init( selector_flags, act, 0 );

        if ( selector_flags & POLICY_LOCAL ) {
                memcpy( &filt->laddr, &conn_p->laddr, sizeof( struct sockaddr_storage ));
        }
        if ( selector_flags & POLICY_REMOTE || selector_flags & POLICY_CLOUD ) {
                memcpy( &filt->raddr, &conn_p->raddr, sizeof( struct sockaddr_storage));
        }
        if ( selector_flags & POLICY_STATE ) {
                filt->state = conn_p->state;
        }
        if ( selector_flags & POLICY_AF ) 
                filt->af = conn_p->family; 
        if ( selector_flags & POLICY_CLOUD ) 
                filt->cloud_stamp = time(NULL);
        if ( selector_flags & POLICY_IF ) 
          filt->ifname = conn_p->metadata.ifname;


        return filt;
}

/** 
 * @brief Match sockaddr structures according to policy.
 *
 * The sockaddr structures are matched according to the policy. If both address
 * and port are defined in the policy, the whole sockaddr_storage structures
 * are compared.
 *
 * @note If neither POLICY_ADDR not POLICY_PORT is defined on the
 * policy, 1 is returned.
 *
 * @param filt_addr Pointer to filters address structure.
 * @param conn_addr Pointer to the connections address structure.
 * @param pol Policy flags indicating which parts of the sockaddr struture
 * should be checked.
 * 
 * @return 1 if the socket addresses match (according to the policy), 0 if not. 
 */
static int match_saddr( struct sockaddr_storage *filt_addr, 
                struct sockaddr_storage *conn_addr, policy_flags_t pol )
{
        int rv = 0;
        int port1, port2;

        if ( (pol & ( POLICY_ADDR | POLICY_PORT )) == 0 ) {
                TRACE( "Match, no addr or port on policy \n" );
                return 1;
        }


        switch( pol & (POLICY_ADDR | POLICY_PORT) ) {

                case (POLICY_ADDR|POLICY_PORT) :
                        TRACE( "Matching address and port\n");
                        if ( filt_addr->ss_family != conn_addr->ss_family ) {
                                TRACE( "No match, address families differ!\n" );
                                return 0;
                        }
                        if( (memcmp(filt_addr, conn_addr, 
                                             sizeof(struct sockaddr_storage))) == 0 ) {
                                rv = 1;
                        }
                        break;
                case POLICY_ADDR :
                        TRACE("Matching address\n");
                        if ( filt_addr->ss_family != conn_addr->ss_family ) {
                                TRACE( "No match, address families differ!\n" );
                                return 0;
                        }
                        if ( filt_addr->ss_family == AF_INET ) {
                                if( memcmp( ss_get_addr( filt_addr), ss_get_addr( conn_addr ),
                                               sizeof( struct in_addr ) ) == 0) {
                                        rv = 1;
                                }
                        } else {
                                if (memcmp( ss_get_addr6(filt_addr), ss_get_addr6(conn_addr),
                                               sizeof( struct in6_addr ) ) == 0 ) {
                                        rv  = 1;
                                }
                        }

                        break;
                case POLICY_PORT :
                        TRACE("Matching port\n" );
                        if ( filt_addr->ss_family == AF_INET ) {
                                port1 = ((struct sockaddr_in *)filt_addr)->sin_port;
                        } else {
                                port1 = ((struct sockaddr_in6 *)filt_addr)->sin6_port;
                        }
                        if ( conn_addr->ss_family == AF_INET ) {
                                port2 = ((struct sockaddr_in *)conn_addr)->sin_port;
                        } else {
                                port2 = ((struct sockaddr_in6 *)conn_addr)->sin6_port;
                        }

                        if ( port1 == port2 ) 
                                rv = 1;
                        break;
        }

        TRACE( "Match result %d \n", rv );
        return rv;
}

#define CLOUD_TIME_LIMIT 2

/**
 * Match the gonnection against the filter. The seletor flags in the filter are
 * used to determine which selectors are matched.
 *
 * As a side effect the evaluation (and match in case of match) counters of the
 * filter are increased.
 *
 * @ingroup filter_api
 * @param filt Pointer to filter to match the connection.
 * @param conn_p The connection to match.
 * @return 0 if the connection does not match the filter, non-zero if it
 * matches.
 */
int filter_match( struct filter *filt, struct tcp_connection *conn_p )
{
        int rv = 0;

        filt->evals++;

        if ( filt->policy & POLICY_AF ) {
                if ( conn_p->laddr.ss_family != filt->af ||
                     conn_p->raddr.ss_family != filt->af ) {
                        rv = 0;
                        TRACE("Address family didn't match!\n");
                        return rv;
                }
        }

        if ( filt->policy & POLICY_IF ) {
          if ( conn_p->metadata.ifname == NULL || 
              filt->ifname == NULL ) {
            WARN("Filtering by IF, yet NULL ifname\n" );
            rv = 1;
          } else if ( strcmp(conn_p->metadata.ifname, filt->ifname) == 0 ) {
            TRACE("interface name matched\n" );
            rv = 1;
          } else {
            return rv;
          }
        }

        if ( filt->policy & POLICY_CLOUD ) {
                TRACE("Cloud stamps, filter: %ld, conn %ld \n", filt->cloud_stamp, conn_p->metadata.added );
                if ( conn_p->metadata.added - filt->cloud_stamp< CLOUD_TIME_LIMIT ) {
                        TRACE("Difference %ld \n",filt->cloud_stamp - conn_p->metadata.added);
                        TRACE("Cloud timestamp in the limit\n");
                        rv = 1;
                } else {
                        TRACE("Cloud didn't match");
                        return 0;
                }
        }

        if ( filt->policy & POLICY_LOCAL ) {
                rv = match_saddr( &filt->laddr, &conn_p->laddr, filt->policy );
                if ( rv == 0 ) {
                        TRACE("Local saddr didn't match!\n");
                        return rv;
                }
        }
        if ( filt->policy & POLICY_REMOTE ) {
                rv = match_saddr( &filt->raddr, &conn_p->raddr, filt->policy );
                if ( rv == 0 ) {
                        TRACE("Local saddr didn't match!\n");
                        return rv;
                }
        }

        if ( filt->policy & POLICY_STATE ) {
                if ( filt->state == conn_p->state ) 
                        rv = 1;
        }

        TRACE( "Match result %d\n", rv );
        if ( rv )
                filt->matches++;
        return rv;
}

/**
 * Check if the filter has the given policy flags set on.
 * Note that this check may return 1 if there are also other flags than the
 * specified set on.
 *
 * @ingroup filter_api
 *
 * @param filt Pointer to the filter.
 * @param flags Flags to check.
 * @return 1 if the given flags are set on, 0 if not.
 */ 
int filter_has_policy( struct filter *filt, policy_flags_t flags )
{
  int rv = 0;

  if ( filt == NULL )
    return rv;

  if ( (filt->policy & flags) == flags ) 
    rv = 1;

  return rv;
}

/** 
 * @brief Get the number of connections on the associated group.
 *
 * If thre is no group associated with this filter 0 is returned.
 *
 * @ingroup filter_api
 * 
 * @param filt Pointer to the filter whose connection count is needed.
 * 
 * @return  Number of connections on the group associated with this filter.
 */
int filter_get_connection_count( struct filter *filt )
{
        if ( filt->group == NULL )
                return 0;

        return group_get_size( filt->group );
}


/** 
 * @brief Initialize a filter list.
 *
 * @ingroup filter_api
 * @param the matching policy used for this list
 * @return New initialized filter list.
 */
struct filter_list *filtlist_init( enum filtlist_policy policy )
{
        struct filter_list *rv;

        rv = mem_alloc( sizeof( struct filter_list ));
        rv->policy = policy;
        rv->first = NULL;
        return rv;
}

/**
 * Deinitialize the given filter list. All memory associated with the filters
 * on this list is freed as is the list itself.
 *
 * Note that the group associated with a filter on this list is also
 * deinitialized.
 *
 * @ingroup filter_api
 * @param list Pointer to the list to deinitialize.
 */
void filtlist_deinit( struct filter_list *list )
{
        struct filter *filt, *tmp;

        filt = list->first;
        while ( filt != NULL ) {
                tmp = filt->next;
                filter_deinit( filt, 1 ); /* deinitializes the group! */
                filt = tmp;
        }
        mem_free( list );
}

/**
 * Add filter to filter list.
 *
 * @ingroup filter_api
 * @param list Pointer to the list where items should be added.
 * @param filt Filter to add to the list
 * @param pol The policy stating where in the list the filter should be added. 
 */
void filtlist_add( struct filter_list *list, struct filter *filt,
                enum filtlist_add_policy pol )
{
        struct filter *iter;

        if ( pol == ADD_FIRST ) {
                filt->next = list->first;
                list->first = filt;
        } else {

                filt->next = NULL;
                iter = list->first;
                if ( iter == NULL ) {
                        list->first = filt;
                        return;
                }

                while ( iter->next != NULL )
                        iter = iter->next;

                iter->next = filt;

        }
}

/**
 * Match the given connection against the filters on the list and return pointer 
 * to matching filter.
 *
 * The match whose action is returned depends on the policy of the list. If the
 * policy is FIRST_MATCH, then the filter who matches the given connection is
 * declared as the match, if the policy is LAST_MATCH, then the filter who
 * matched last is the Match. Hence traversing LAST_MATCH policy lists takes
 * longer since all the filters on the list have to be looked before the best
 * match is found.
 *
 * @ingroup filter_api
 * @param list Pointer to the filter list.
 * @param conn Pointer to the connection to match.
 * @return Pointer to filter matching the connection or NULL if no match is found.
 */
struct filter *filtlist_match( struct filter_list *list, struct tcp_connection *conn)
{
        struct filter *filt, *rv = NULL;
        
        filt = list->first;
        while ( filt != NULL ) {
                if ( filter_match( filt, conn ) ) {
                        rv = filt;
                        if ( list->policy == FIRST_MATCH )
                                break;
                }
                filt = filt->next;
        }
        return rv;
}


/**
 * Get the action for given connection from the matched filter. If no filter is
 * matched then FILTERACT_NONE is returned (this is also, naturally, returned
 * if the matching filter has this action.
 *
 * @ingroup filter_api
 * @see filtlist_match
 * @param list Pointer to the list.
 * @param conn Connectiont to match agains the filters on this list.
 * @return Action from the filter which matched (best) the given connection.
 */
enum filter_action filtlist_action_for( struct filter_list *list, 
                struct tcp_connection *conn)
{
        enum filter_action rv = FILTERACT_NONE;
        struct filter *filt = filtlist_match( list, conn );

        if ( filt != NULL )
                rv = filt->action;

        return rv;
}
