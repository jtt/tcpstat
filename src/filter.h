/**
 * @file filter.h 
 * @brief  This file contains all type definitions and API function
 * declarations for filter module. 
 *
 *
 * Copyright (c) 2007, J. Taimisto
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

/* Policy flags */
/**
 * FLag for indicating that filter selectors are for local (addr or port).
 * @ingroup filter_api
 */
#define POLICY_LOCAL 0x01
/**
 * Flag for indicating that filter selectors are for remote (addr or port)
 * @ingroup filter_api
 */
#define POLICY_REMOTE (0x01 << 1)
/**
 * Flag for indication that selector is for address
 * @ingroup filter_api
 */
#define POLICY_ADDR (0x01 << 2)
/**
 * Flag for indication that selector is for port
 * @ingroup filter_api
 */
#define POLICY_PORT (0x01 << 3)
/**
 * Flag for indication that selector is for state.
 * @ingroup filter_api
 */
#define POLICY_STATE (0x01 << 4)
/**
 * Flag for indicating that group is embedded in filterinfo, no real selector
 * flag.
 * @ingroup filter_api
 *
 */
#define POLICY_PID (0x01 << 5 )

/**
 * Flag for indication that selector is for address family.
 * @ingroup filter_api
 */
#define POLICY_AF (0x01 << 6)

/**
 * Flag for indicating that selector is for generating clouds 
 * of connections
 */
#define POLICY_CLOUD (0x01 << 7)

/**
 * Flag for indicating that selector is for filtering 
 * according to interface
 */
#define POLICY_IF (0x01 << 8 )


typedef uint16_t policy_flags_t;



/**
 * Actions defined for filters. Every filter should carry one action to inform
 * what should be done to connection matching the filter. 
 */
enum filter_action {
        FILTERACT_NONE, /**< No action */
        FILTERACT_GROUP, /**< Group matching connections */
        FILTERACT_WARN,/**< Warn about matching connections */
        FILTERACT_LOG,/**< Log open and closing of matcing connections. */
        FILTERACT_IGNORE/**< Ignore the mathching connections */
};


/**
 * A filter that can be used to filter connections. Filter holds selectors for
 * (local and remote) address and port and connection state. At least one of
 * the selectors has to be "active", that is not "any". 
 */
struct filter {
        struct filter *next;/**< Pointer to next filter on list */

        enum filter_action action; /**< What to do with the match */

        /* Filter selectors */

        int af; /**<Address family for the addresses */
        /** 
         * Policy bits for the selectors. Policy bits tell which selectors are
         * active in this filter.
         */
        policy_flags_t policy;
        /**
         * Number of valid bytes on the local address. 
         */
        uint8_t localaddr_bytes;
        struct sockaddr_storage laddr;/**< Local address selector. */
        /**
         * Number of valid bytes on the remote address. 
         */
        uint8_t remteaddr_bytes;
        struct sockaddr_storage raddr;/**< Remote address selector */

        enum tcp_state state; /**< State selector */

        const char *ifname; /**< Name of the interface to filter with */

        /* misc metadata */

        /**
         * Pointer to group this filter is associated with, if any. 
         * If the action is FILTERACT_GROUP then matching connections 
         * should be added to this group. NULL if filter is not 
         * associated with any group.
         */
        struct group *group;

        /**
         * Number of times this filter has been evaluated 
         */
        uint32_t evals;
        /**
         * Number of times this filter has been matched.
         */
        uint32_t matches;

        /**
         * Timestamp for generating clouds
         */
        time_t cloud_stamp;
};

/**
 * Match policy for traversing the filter list
 */
enum filtlist_policy {
        LAST_MATCH, /**< Last match wins */
        FIRST_MATCH /**< First match wins */
};

enum filtlist_add_policy {
        ADD_FIRST,
        ADD_LAST
};

/**
 * Structure defining the a list of filters. 
 */
struct filter_list {
        enum filtlist_policy policy; /**< Match policy for the list */
        struct filter *first; /**< Pointer to the first element */
};


struct filter *filter_init( policy_flags_t policy, enum filter_action act,
                int init_group );
void filter_deinit( struct filter *filt, int deinit_group );

struct filter *filter_from_connection( struct tcp_connection *conn_p,
                policy_flags_t selector_flags, enum filter_action act );
int filter_match( struct filter *filt, struct tcp_connection *conn_p );
int filter_has_policy( struct filter *filt, policy_flags_t flags );
int filter_get_connection_count( struct filter *filt );

struct filter_list *filtlist_init( enum filtlist_policy policy );
void filtlist_deinit( struct filter_list *list );
void filtlist_add( struct filter_list *list, struct filter *filt,
                enum filtlist_add_policy pol );
struct filter *filtlist_match( struct filter_list *list, struct tcp_connection *conn);
enum filter_action filtlist_action_for( struct filter_list *list, 
                struct tcp_connection *conn);
void filtlist_clear_grp_metadata( struct filter_list *list );

#define filtlist_foreach_filter(list, item) \
        for( item = list->first; item != NULL; item=item->next )

