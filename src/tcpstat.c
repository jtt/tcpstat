/**
 * @file tcpstat.c 
 * @brief Main module for the program. 
 *
 * Here all pieces come together. This module does not contain any GUI logic,
 * but handles all information gathering, and making sure all connection
 * information is sound and in right place. 
 *
 *  Copyright (c) 2005-2008, J. Taimisto
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
 * 
 */ 

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <signal.h>

#include <errno.h>
#include <netdb.h> /* getaddrinfo() */


#include "defs.h"
#include "debug.h"
#include "connection.h"
#include "stat.h"
#include "ui.h"
#include "scouts.h"

#define STATFILE "/proc/net/tcp"
#define PROGNAMELEN 20
#define DEFAULT_UPDATE_INT 1
/**
 * Default start-up policy
 */
#define DEFAULT_POLICY  POLICY_REMOTE | POLICY_ADDR

static char progname[ PROGNAMELEN ];


/** 
 * @brief Check if any process we are following has died. 
 *
 * The scan_inodes() sets <code>->pid</code> to -1 if it detects that process
 * has died. Remove all those pidinfo structures. If the connection group
 * inside pidinfo is not empty, then there are some connections still in the
 * system for the dead process and such pidinfo is not removed. 
 * 
 * @see scan_inodes()
 * 
 * @param ctx Pointer to the main context.
 * 
 * @return Number of still alive connections. 
 */
#ifdef ENABLE_FOLLOW_PID
static int check_dead_processes( struct stat_context *ctx )
{
        struct pidinfo *info_p, *prev;
        int alive_count = 0;

        prev = NULL;
        info_p = ctx->pinfo;

        while ( info_p != NULL ) {
                if ( info_p->pid == -1 ) {
                        DBG( "Found dead process\n" );
                        if ( group_get_size( info_p->grp ) == 0 ) {
                                if ( prev == NULL ) {
                                        ctx->pinfo = info_p->next;
                                } else {
                                        prev->next = info_p->next;
                                }
                                free_pidinfo( info_p );
                                info_p = info_p->next;
                        } else {
                                DBG( "Connections on dead processes group!\n" );
                                /* we cheat, on purpose */
                                alive_count++;
                                prev = info_p;
                                info_p = info_p->next;
                                /* We just have to wait for these connections
                                 * to die out 
                                 */
                        }
                } else {
                        alive_count++;
                        prev = info_p;
                        info_p = info_p->next;
                }
        }
        return alive_count;
}
#endif /* ENABLE_FOLLOW_PID */

#ifdef ENABLE_FOLLOW_PID
/**
 * Clear the metadata from the connections stored into pidinfo 
 * structures. 
 *
 * In follow pid -mode we do not hold the connections in the
 * listen_groups and out_groups, instead they are in the pidinfos. 
 *
 * @param ctx Pointer to the global context.
 */
static void clear_pid_metadata( struct stat_context *ctx ) 
{
        struct pidinfo *info_p = ctx->pinfo;

        while( info_p != NULL ) {
                group_clear_metadata_flags( info_p->grp );
                info_p = info_p->next;
        }
}
#endif /* ENABLE_FOLLOW_PID */

        
static void print_help( char *name  )
{
#ifdef BUILDID
        printf( "%s %s Build:%s (c) J. Taimisto 2005-2010 \n", name, VERSION, BUILDID );
#else
        printf( "%s %s (c) J. Taimisto 2005-2010 \n", name, VERSION );
#endif /* BUILDID */
        printf( "Usage %s [options], where options are: \n",name );
        printf( "\t--help or -h:\t Print this text \n" );
        printf( "\t--group <grp> or -g <grp>: Set grouping for connections\n" );
        printf( "\t  Possible Groupings are \n" );
        printf( "\t   \"ip\"    -- Group by destination IP address \n" );
        printf( "\t   \"port\"  -- Group by destination port\n" );
        printf( "\t   \"state\" -- Group by connection state\n" );
        printf( "\t   \"if\"    -- Group by interface\n" ); 
#if 0 /* not yet */
        printf( "\t   \"cloud\" -- Group related connections (based on address) (EXPERIMENTAL)\n");
        printf( "\t   \"cloudp\"-- Group related connections (based on port) (EXPERIMENTAL)\n\n"); 
#endif 
#ifdef ENABLE_FOLLOW_PID
        printf( "\t--pid <pid> or -p <pid> : Show only connection for process\n\t  with pid <pid>\n" );
#endif /* ENABLE_FOLLOW_PID */
        printf( "\t--delay <sec> or -d <sec> : Set delay betveen updates to \n\t  <sec> seconds. Default is %d sec\n",DEFAULT_UPDATE_INT );
        printf( "\t--numeric or -n : Don't resolve hostnames\n" );
        printf( "\t--listen or -l  : Print information about listening connections\n" );
        printf( "\t--linger or -L  : Linger closed connections for a while\n" );
#ifdef ENABLE_IFSTATS
        printf( "\t--ifstat or -i  : Collect and display interface statistics\n");
#endif /* ENABLE_IFSTATS */
        printf( "\t--ipv4 or -4    : Collect only IPv4 TCP connection statistics\n" ); 
        printf( "\t--ipv6 or -6    : Collect only IPv6 TCP connection statistics\n" ); 
        printf( "\tFiltering options : \n");
        printf( "\t--ignore-rport <port>[,<port>,<port>] : Ignore connections with given\n\t  remote port(s)\n" );
        printf( "\t--ignore-raddr <addr>[:port] : Ignore connections with given remote\n\t  address (and port)\n" );
        printf( "\t--warn-raddr <addr>[:port] : Warn about (mark with !) connections with\n\t  given remote address (and port)\n" );
        printf( "\t--warn-rport <port>[,<port>,<port>] : Warn (mark with !) about\n\t  connections with given  remote port(s)\n");
#ifdef DEBUG
        printf( "\t--debug <lvl> or -D <lvl> : Set debug level (0,1,2,3)\n" );
#endif /* DEBUG */
}

/**
 * Set the grouping policy according to command line parameters. 
 * @param ctx Pointer to the working context.
 * @param modifier String containing the grouping policy modifier. 
 * @return -1 if modifier contains error, 0 on success.
 */ 
static int set_grouping( struct stat_context *ctx, char *modifier )
{
        int rv = 0;

        TRACE( "Doing grouping, modifier |%s| \n", modifier ); 
        if ( strcmp( modifier, "ip" ) == 0 ) {
                DBG( "Grouping POLICY_REMOTE | POLICY_ADDR \n" );
                ctx->common_policy = POLICY_REMOTE | POLICY_ADDR;
        } else if ( strcmp( modifier, "port" ) == 0 ) {
                DBG( "Grouping POLICY_REMOTE | POLICY_PORT \n" );
                ctx->common_policy = POLICY_REMOTE | POLICY_PORT;
        } else if ( strcmp( modifier, "state" ) == 0 ) {
                DBG( "Grouping POLICY_STATE\n" );
                ctx->common_policy = POLICY_STATE;
        } else if ( strcmp( modifier, "cloud" ) == 0 ) {
                DBG("Grouping POLICY_CLOUD\n");
                ctx->common_policy = POLICY_CLOUD | POLICY_REMOTE | POLICY_ADDR;
        } else if ( strcmp( modifier, "cloudp" ) == 0 ) {
                DBG("Grouping POLICY_CLOUD (port)\n");
                ctx->common_policy = POLICY_CLOUD | POLICY_REMOTE | POLICY_PORT;
        } else if ( strcmp( modifier, "if" ) == 0 ) {
                ctx->common_policy = POLICY_IF;
        } else {
                ERROR("Unkonwn grouping %s! \n", modifier );
                rv = -1;
        }

        return rv;
}  

/**
 * Parse comma separated process ID's from given string and initialize pidinfo
 * structure for each PID.
 * Pidinfo structure is initialized and added to the list of pidinfos on main
 * context.
 * @param ctx Pointer to working context.
 * @param argstr String containing the PIDs.
 * @return number of PIDs found.
 */
#ifdef ENABLE_FOLLOW_PID
static int parse_pids( struct stat_context *ctx, char *argstr )
{
        char *str_p;
        struct pidinfo *pinfo_p;
        int pid,count;

        count = 0;
        if (!argstr || strlen(argstr) == 0){
                return count;
        }

        str_p = strtok(argstr, "," );
        while( str_p != NULL ) {
                TRACE( "Got token:%s\n", str_p );
                pid = strtol( str_p, NULL, 10 );
                pinfo_p = init_pidinfo( pid );
                scan_cmdline(pinfo_p);
                pinfo_p->next = ctx->pinfo;
                ctx->pinfo = pinfo_p;
                TRACE( "Tracing for process with pid %d\n", pinfo_p->pid );
                count++;
                str_p = strtok(NULL,",");
        } 

        return count;
}
#endif /* ENABLE_FOLLOW_PID */

/**
 * Parse a value for port from given string. 
 *
 * Some checks are made to make sure the value is valid.
 *
 * @param str Pointer to the string from where the value is to be parsed.
 * @param port Pointer where the parsed port value is set.
 * @return -1 if error occurs while parsing the port value, 0 on success.
 */
static int parse_port_value( char *str, in_port_t *port) 
{
        long val;

        val = strtol( str, NULL, 10 );
        if (( errno == ERANGE || (errno != 0 && val == 0 ))) {
                return -1;
        }

        if ( val < 0 || val > 0xFFFF ) {
                WARN("Invalid value for port %d \n", val );
                return -1;
        }

        *port = (in_port_t)val;
        return 0;
}

/** 
 * @brief Create a set of filters which will filter on ports specified on given string. 
 * The string should contain the number of ports separated by commas.
 *
 * @bug Adds only filter for AF_INET
 * 
 * @param ctx Pointer to the local context.
 * @param policy Policy to set to the filter.
 * @param act Action to set to the filter
 * @param argstr String containing the ports 
 * 
 * @return 0 if the filters were created properly, < 0 on error.
 */
static int parse_port_filter( struct stat_context *ctx, policy_flags_t policy,
                enum filter_action act, char *argstr )
{
        char *str_p;
        struct filter *filt;
        in_port_t port;
        struct sockaddr_storage ss;

        if ( ! argstr || strlen( argstr ) == 0 ) 
                return -1;

        str_p = strtok(argstr,",");
        while( str_p != NULL ) {
                if ( parse_port_value(str_p, &port) != 0 ) {
                        return -1;
                }

                TRACE("Adding filtering for port %d \n", port );

                memset( &ss, 0, sizeof(ss));
                /* Even if the address family is AF_INET, the port
                 * filter will match on both address families
                 */
                ss.ss_family = AF_INET;
                ss_set_port( &ss, htons(port));

                filt = filter_init( policy, act, 1 );
                filter_set_raddr( filt, &ss );
                filtlist_add( ctx->filters, filt, ADD_LAST);

                str_p = strtok(NULL,",");
        }

        return 0;
}

/** 
 * @brief Create a filter which will filter on address given as argument. 
 *
 * The string given as parameter can either contain only address or
 * address followed by ':' and port number or service name. 
 *
 * The policy should not contain POLICY_ADDR or POLICY_PORT, those 
 * will be set by the function depending on if port information was
 * submitted.
 *
 * @param ctx Pointer to the global context.
 * @param policy Policy to set for the filter.
 * @param act Action to set for the filter.
 * @param argstr String containing the address or address and port to filter.
 * 
 * @return 0 on success, -1 on error.
 */
static int parse_addr_filter( struct stat_context *ctx, policy_flags_t policy,
                enum filter_action act, char *argstr )
{
        struct filter *filt;
        struct addrinfo *ainfo, *ait;
        int ret;
        char *portstr = NULL;

        if ( !argstr || strlen( argstr ) == 0 ) 
                return -1;

        /* check for <addr>:<port> */
        portstr = strchr( argstr, ':');
        if ( portstr != NULL ) {
                *portstr = '\0'; /* XXX are we allowed to modify this */
                portstr++;
                if ( *portstr == '\0' )  /* check for "<addr>:" */
                        portstr = NULL;
        }

        ret = getaddrinfo( argstr, portstr, NULL, &ainfo );
        if ( ret != 0 ) {
                WARN("Unable to resolve the filter address");
                return -1;
        }

        ait = ainfo;
        if ( portstr != NULL ) 
                policy = policy | POLICY_ADDR | POLICY_PORT;
        else
                policy = policy | POLICY_ADDR;

        while ( ait != NULL ) {
                filt = filter_init( policy, act, 1 );
                DBG("Got address with family %s \n", ait->ai_family == AF_INET ? "INET" : "INET6" );
                filter_set_raddr( filt, (struct sockaddr_storage *)(ait->ai_addr));
                filtlist_add( ctx->filters, filt, ADD_LAST );

                ait = ait->ai_next;
        }

        freeaddrinfo( ainfo );
        return 0;
}

/** 
 * @brief Do graceful exit of the program.
 *
 * The GUI is deinitialized and all memory allocated freed.
 * 
 * @param ctx Pointer to the global context.
 * @param exit_msg Message to be printed out on exit (NULL for no message).
 * @param success zero for exiting with EXIT_SUCCESS, other for failure.
 */
void do_exit( struct stat_context *ctx, char *exit_msg, int success )
{
#ifdef ENABLE_FOLLOW_PID
        struct pidinfo *info_p;
#endif /* ENABLE_FOLLOW_PID */

        DBG( "Exiting!\n" );
        ui_deinit();

        if ( ctx->iftab != NULL ) 
                deinit_ifinfo_tab( ctx->iftab );
        /* Hashtable has to be cleared befor any connections are deleted. Else
         * we end up with pointers to freed connections on hashtable. 
         */
        chash_clear( ctx->chash );
        /* Free all pidinfo structures */
#ifdef ENABLE_FOLLOW_PID
        info_p = ctx->pinfo;
        while (info_p != NULL ) {
                struct pidinfo *tmp = info_p->next;
                free_pidinfo( info_p );
                info_p = tmp;
        }
#endif /* ENABLE_FOLLOW_PID */
        filtlist_deinit( ctx->filters );

        cqueue_deinit( ctx->newq, 1 );
        glist_deinit( ctx->listen_groups,1  );
        glist_deinit( ctx->out_groups,1 );
        chash_deinit( ctx->chash );

        mem_free( ctx );

        if ( exit_msg )
                printf("\n%s\n", exit_msg );

        if (success)
                exit(EXIT_SUCCESS);
        else
                exit(EXIT_FAILURE);
}

/** 
 * @brief Handle (terminating( signals 
 * 
 * Receiving a signal is taken as error and the program will be 
 * terminated, the GUI is deinitialized in order to have the terminal usable
 * after signal is received.
 *
 * @param sig Signal received.
 */
#ifdef DEBUG
void do_sighandler( int sig ) 
#else 
void do_sighandler( _UNUSED int sig ) 
#endif

{
        ERROR( "Exiting on signal %d \n", sig );

        ui_deinit();
        exit(EXIT_FAILURE);
}

/**
 * Print error message to user (before we have initialized any UI.
 *
 * @param msg The message to print.
 */
static void print_user_error( char *msg )
{
        fprintf( stderr, "ERROR: %s\n", msg );
}


/**
 * Handle command line arguments. 
 * @param argc Integer containing number of arguments (parameter to main)
 * @param argv Table holding command line parameters (parameter to main).
 * @param ctx Pointer to the working context.
 */ 
static void parse_args( int argc, char **argv, struct stat_context *ctx )
{
       int c;
       int option_index;
       struct option sw_long_options[] = {
               { "help", 0 ,0, 'h' },
               { "group",1,0,'g'},
               { "pid",1,0,'p' },
               { "delay",1,0,'d'},
               { "numeric",0,0,'n'},
               { "listen",0,0,'l'},
               { "linger",0,0,'L'},
               { "ifstats",0,0,'i'},
               { "ipv4", 0,0, '4'},
               { "ipv6", 0,0, '6'},
               { "ignore-rport", 1,0,'R'},
               { "ignore-raddr",1,0,'A'},
               { "warn-raddr",1,0,'w' },
               { "warn-rport",1,0,'W' },
#ifdef DEBUG
               { "debug",1,0,'D'},
#endif /* DEBUG */    
               { 0,0,0,0 }
       };      

       while( 1 ) {
              c = getopt_long( argc, argv, "hlnLi46rg:d:p:R:A:", sw_long_options, &option_index );
              if ( c == -1 ) {
                     break;
              }
              switch( c ) {

                      case 'h' :
                             print_help( argv[0] );
                             mem_free( ctx );
                             exit( EXIT_SUCCESS ); 
                             break;
                      case 'n' :
                             OPERATION_DISABLE(ctx,OP_RESOLVE);
                             break;
                      case 'l' :
                             OPERATION_ENABLE(ctx, OP_SHOW_LISTEN);
                             break;
                      case 'L' :
                             OPERATION_ENABLE(ctx,OP_LINGER);
                             break;
#ifdef ENABLE_IFSTATS
                      case 'i' :
                             OPERATION_ENABLE(ctx, OP_IFSTATS);
                             break;
#endif /* ENABLE_IFSTATS */
                      case '4' :
                             ctx->collected_stats = STAT_V4_ONLY;
                             break;
                      case '6' :
                             ctx->collected_stats = STAT_V6_ONLY;
                             break;
#ifdef DEBUG 
                      case 'D' :
                             DBG_LEVEL( atoi( optarg ) );
                             break;
#endif /* DEBUG */

                      case 'g' :
                             if ( set_grouping( ctx, optarg ) != 0 ) {
                                     print_user_error("Unknown grouping specified");
                                     mem_free( ctx );
                                     exit( EXIT_FAILURE );
                             }
                             break;

                      case 'd' :
                             ctx->update_interval = strtol( optarg, NULL, 10 );
                             if ( ctx->update_interval <= 0 ) {
                                     print_user_error( "Invalid value for update interval");
                                     exit( EXIT_FAILURE);
                             }
                             TRACE( "Update interval set to %d sec.\n", ctx->update_interval );
                             break;
#ifdef ENABLE_FOLLOW_PID
                      case 'p' :
                             if (parse_pids( ctx, optarg) < 1 ) {
                                     print_user_error( "Unable to parse process ID's");
                                     exit( EXIT_FAILURE );
                             }
                             OPERATION_ENABLE(ctx, OP_FOLLOW_PID);
                             break;
#endif /* ENABLE_FOLLOW_PID */
                      case 'R' :
                             if ( parse_port_filter( ctx, POLICY_REMOTE | POLICY_PORT, FILTERACT_IGNORE, 
                                                     optarg ) < 0 ) {
                                    print_user_error("Invalid port for ignore-port");
                                    exit( EXIT_FAILURE );
                             }
                             break;
                      case 'A' :
                             if ( parse_addr_filter( ctx, POLICY_REMOTE, FILTERACT_IGNORE,
                                                     optarg ) < 0 ) {
                                     print_user_error("Invalid address for ignore-address" );
                                     exit( EXIT_FAILURE );
                             }
                             break;
                      case 'w' :
                             if ( parse_addr_filter(ctx, POLICY_REMOTE, FILTERACT_WARN,
                                                     optarg) < 0 ) {
                                     print_user_error("Invalid address for warn-address");
                                     exit(EXIT_FAILURE);
                             }
                             break;
                      case 'W' :
                             if ( parse_port_filter( ctx, POLICY_REMOTE | POLICY_PORT, FILTERACT_WARN,
                                                     optarg) < 0 ) {
                                     print_user_error("Invalid port for warn-port");
                                     exit(EXIT_FAILURE);
                             }
                             break;
                      default :
                             print_help( argv[0] );
                             mem_free( ctx );
                             exit( EXIT_SUCCESS ); 
                             break;
              }
       }

}




int main( int argc, char *argv[] ) 
{
        struct stat_context *ctx;
        struct filter *filt;
        int round =0,rv;


        if ( signal( SIGTERM, do_sighandler ) == SIG_ERR ) {
                fprintf(stderr,"signal() failed : %s\n", strerror(errno) );
                return -1;
        }
        if ( signal( SIGINT, do_sighandler ) == SIG_ERR ) {
                fprintf(stderr,"signal() failed : %s\n", strerror(errno) );
                return -1;
        }
        if ( signal( SIGQUIT, do_sighandler ) == SIG_ERR ) {
                fprintf(stderr,"signal() failed : %s\n", strerror(errno) );
                return -1;
        }

        DBG_INIT( "debug.txt" );


#if 0
        DBG_MODULE_LEVEL( DBG_MODULE_FILTER, DBG_L_TRACE );
        DBG_MODULE_LEVEL( DBG_MODULE_RT, DBG_L_TRACE );
#endif 

        ctx = mem_alloc( sizeof( struct stat_context) );
        memset( ctx,0, sizeof( *ctx));
        ctx->ops = 0;
        ctx->listen_groups = glist_init();
        ctx->out_groups = glist_init();
        ctx->newq = cqueue_init();
        ctx->chash = chash_init();
        ctx->new_count = 0;
        ctx->total_count = 0;
        ctx->common_policy = DEFAULT_POLICY;
        ctx->update_interval = DEFAULT_UPDATE_INT;
        ctx->pinfo = NULL;
        ctx->collected_stats = STAT_ALL;
        ctx->filters = filtlist_init(FIRST_MATCH);
        
        OPERATION_ENABLE( ctx, OP_RESOLVE);

        strncpy( progname, argv[0], PROGNAMELEN );

        parse_args( argc, argv, ctx );

        
        ctx->iftab = scout_ifs();
        if ( ctx->iftab == NULL ) {
                ERROR( "Error in initializing the interface stats!\n" );
                return -1;
        }
        DBG( "Scouted %d interfaces\n", ctx->iftab->size );

#ifdef ENABLE_ROUTES
        DBG("Adding routing info\n");
        parse_routing_info(ctx->iftab);
#endif /* ENABLE_ROUTES */


        ui_init( ctx );
        while ( 1 )  {
#ifdef ENABLE_FOLLOW_PID
                if ( OPERATION_ENABLED(ctx,OP_FOLLOW_PID) ) 
                        scan_inodes( ctx->pinfo );
#endif /* ENABLE_FOLLOW_PID */

#ifdef ENABLE_IFSTATS
                if ( OPERATION_ENABLED(ctx, OP_IFSTATS ))
                        read_interface_stat( ctx );
#endif /* ENABLE_IFSTATS */
                
                if ( ctx->collected_stats != STAT_V4_ONLY ) {
                        rv = read_tcp6_stat( ctx );
                        if ( rv != 0 ) {
                                ERROR( "Error while reading stats from TCP6" );
                                break;
                        }
                }
                if ( ctx->collected_stats != STAT_V6_ONLY ) {
                        rv = read_tcp_stat( ctx );
                        if ( rv != 0 ) {
                                ERROR( "Error while reading stats from TCP" );
                                break;
                        }
                }

#ifdef ENABLE_FOLLOW_PID
                if ( ! OPERATION_ENABLED(ctx, OP_FOLLOW_PID)) {
                        rotate_new_queue( ctx );
                }
#else
                rotate_new_queue(ctx);
#endif /* ENABLE_FOLLOW_PID */
                round++;

                if ( ctx->total_count != ctx->chash->size ) {
                        int count = ctx->chash->size - ctx->total_count;
                        TRACE( "Going to purge connections (total %d, hash %d)\n", ctx->total_count, ctx->chash->size );
                        /* Some connections have to be deleted. */
                        if ( count > 0 ) {
                                if ( purge_closed_connections( ctx, count ) != 0 ) {
                                        WARN( "Purge closed blew it \n" );
                                        do_exit( ctx, "Fatal internal error!\n",-1 );
                                }
                        }
                }  
#ifdef ENABLE_FOLLOW_PID
                if ( OPERATION_ENABLED( ctx, OP_FOLLOW_PID) ) {
                        if ( check_dead_processes( ctx ) == 0 ) {
                                /* XXX - Some message is needed */
                                do_exit( ctx, "No more processes to follow!\n",0 );
                        }
                }
#endif /* ENABLE_FOLLOW_PID */
                ui_update_view( ctx );

                /* clear metadata flags from all the connections, 
                 * this way we'll notice new connections (and dead) 
                 * on next round...
                 */
#ifdef ENABLE_FOLLOW_PID 
                if ( OPERATION_ENABLED( ctx, OP_FOLLOW_PID )) {
                        clear_pid_metadata( ctx );
                } else {
                        clear_metadata_flags( ctx->listen_groups );
                        clear_metadata_flags( ctx->out_groups );
                }
#else /* ENABLE_FOLLOW_PID */
                clear_metadata_flags(ctx->listen_groups);
                clear_metadata_flags(ctx->out_groups);
#endif /* ENABLE_FOLLOW_PID */

                /* clear the metadata flags from the filtered connections */
                filtlist_foreach_filter( ctx->filters, filt ) {
                        if ( filt->group != NULL )
                                group_clear_metadata_flags( filt->group );
                }

                ctx->new_count = 0;
                ctx->total_count = 0;
                /*sleep( ctx->update_interval );*/
                ui_input_loop( ctx );
        }

        WARN( "Should not come here!\n" );
        do_exit( ctx, "Bang; not here\n",-1 );


        return 0;
}
