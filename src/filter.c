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

        filt = mem_alloc( sizeof(struct filter));
        memset( filt, 0, sizeof( struct filter ));

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

        filt->policy = selector_flags;
        filt->action = act;


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
                                if( memcmp( &((struct sockaddr_in *)filt_addr)->sin_addr,
                                               &((struct sockaddr_in *)conn_addr)->sin_addr,
                                               sizeof( struct in_addr ) ) == 0) {
                                        rv = 1;
                                }
                        } else {
                                if (memcmp( &((struct sockaddr_in6 *)filt_addr)->sin6_addr,
                                               &((struct sockaddr_in6 *)conn_addr)->sin6_addr,
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
