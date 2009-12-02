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

#include <arpa/inet.h> /* inet_pton() */
#include <errno.h>
#include <netdb.h> /* getaddrinfo() */


#include "defs.h"
#include "debug.h"
#include "connection.h"
#include "pidscout.h"
#include "stat.h"
#include "rtscout.h"
#include "ifscout.h"
#include "ui.h"
#include "tcpscout.h"

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

        
static void print_help( char *name  )
{
#ifdef BUILDID
        printf( "%s %s Build:%s (c) J. Taimisto 2005-2008 \n", name, VERSION, BUILDID );
#else
        printf( "%s %s (c) J. Taimisto 2005-2008 \n", name, VERSION );
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
        printf( "\t--pid <pid> or -p <pid> : Show only connection for process\n\t  with pid <pid>\n" );
        printf( "\t--delay <sec> or -d <sec> : Set delay betveen updates to \n\t  <sec> seconds. Default is %d sec\n",DEFAULT_UPDATE_INT );
        printf( "\t--numeric or -n : Don't resolve hostnames\n" );
        printf( "\t--listen or -l  : Print information about listening connections\n" );
        printf( "\t--linger or -L  : Linger closed connections for a while\n" );
        printf( "\t--ifstat or -i  : Collect and display interface statistics\n");
        printf( "\t--ipv4 or -4    : Collect only IPv4 TCP connection statistics\n" ); 
        printf( "\t--ipv6 or -6    : Collect only IPv6 TCP connection statistics\n" ); 
        printf( "\tFiltering options : \n");
        printf( "\t--ignore-rport <port>[,<port>,<port>] : Ignore connections with given remote port(s)\n" );
        printf( "\t--ignore-raddr <addr> : Ignore connections with given remote address\n" );
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

/** 
 * @brief Create a set of filters which will filter on ports specified on given string. 
 * The string should contain the number of ports separated by commas.
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
        int port; 

        if ( ! argstr || strlen( argstr ) == 0 ) 
                return -1;

        str_p = strtok(argstr,",");
        while( str_p != NULL ) {
                port = strtol( str_p, NULL, 10 );
                filt = filter_init( policy, act, 1 );

                TRACE("Adding filtering for port %d \n", port );
                ((struct sockaddr_in *)&filt->raddr)->sin_port = htons(port);
                filt->raddr.ss_family = AF_INET; /* XXX */

                filtlist_add( ctx->filters, filt, ADD_LAST);
                str_p = strtok(NULL,",");
        }

        return 0;
}

/** 
 * @brief Create a filter which will filter on address given as argument. 
 *
 * The policy and action for the filter are set as given.
 *
 * @param ctx Pointer to the global context.
 * @param policy Policy to set for the filter.
 * @param act Action to set for the filter.
 * @param argstr String containing the (IPv4) address to filter.
 * 
 * @return 0 on success, -1 on error.
 */
static int parse_addr_filter( struct stat_context *ctx, policy_flags_t policy,
                enum filter_action act, char *argstr )
{
        struct filter *filt;
#if 0
        struct sockaddr_in *sin_p;
        struct sockaddr_in6 *sin6_p;
#endif 
        struct addrinfo *ainfo, *ait;
        int ret;

        if ( !argstr || strlen( argstr ) == 0 ) 
                return -1;

        ret = getaddrinfo( argstr, NULL, NULL, &ainfo );
        if ( ret != 0 ) {
                WARN("Unable to resolve the filter address");
                return -1;
        }

        ait = ainfo;

        while ( ait != NULL ) {
                filt = filter_init( policy, act, 1 );
                DBG("Got address with family %s \n", ait->ai_family == AF_INET ? "INET" : "INET6" );
                memcpy( &filt->raddr, ait->ai_addr, ait->ai_addrlen );
                filtlist_add( ctx->filters, filt, ADD_LAST );

                ait = ait->ai_next;
        }

        freeaddrinfo( ainfo );

#if 0
        sin_p = (struct sockaddr_in *) &filt->raddr;
        ret = inet_pton( AF_INET, argstr, &sin_p->sin_addr );
        if ( ret > 0 ) { 
                sin_p->sin_family = AF_INET;
                sin_p->sin_port = 0;
        } else {
               DBG("Not IPv4 Address, trying IPv6\n");
               sin6_p = (struct sockaddr_in6 *) &filt->raddr;
               ret = inet_pton( AF_INET6, argstr, &sin6_p->sin6_addr );
               if ( ret <= 0 ) {
                       WARN("Given address is neither IPv4 nor IPv6\n");
                       mem_free( filt );
                       return -1;
               }
               sin6_p->sin6_family = AF_INET6;
               sin6_p->sin6_port = 0;
        }

        filtlist_add( ctx->filters, filt, ADD_LAST );
#endif

        return 0;
}



        




/** 
 * @brief Do graceful exit of the program.
 *
 * The GUI is deinitialized and all memory allocated freed.
 * 
 * @param ctx Pointer to the global context.
 * @param exit_msg Message to be printed out on exit (NULL for no message).
 */
void do_exit( struct stat_context *ctx, char *exit_msg )
{
        struct pidinfo *info_p;

        DBG( "Exiting!\n" );
        ui_deinit();

        if ( ctx->iftab != NULL ) 
                deinit_ifinfo_tab( ctx->iftab );
        /* Hashtable has to be cleared befor any connections are deleted. Else
         * we end up with pointers to freed connections on hashtable. 
         */
        chash_clear( ctx->chash );
        /* Free all pidinfo structures */
        info_p = ctx->pinfo;
        while (info_p != NULL ) {
                struct pidinfo *tmp = info_p->next;
                free_pidinfo( info_p );
                info_p = tmp;
        }
        filtlist_deinit( ctx->filters );

        cqueue_deinit( ctx->newq, 1 );
        glist_deinit( ctx->listen_groups,1  );
        glist_deinit( ctx->out_groups,1 );
        chash_deinit( ctx->chash );

        mem_free( ctx );

#ifdef DEBUG_MEM
        dump_alloc_table();
#endif 
        DBG_DEINIT();

        if ( exit_msg )
                printf("\n%s\n", exit_msg );

        exit(0);
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
void do_sighandler( int sig ) 
{
        ERROR( "Exiting on signal %d \n", sig );

        ui_deinit();
        exit( 0 );
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
                      case 'i' :
                             OPERATION_ENABLE(ctx, OP_IFSTATS);
                             break;
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
                                     mem_free( ctx );
                                     exit( EXIT_FAILURE );
                             }
                             break;

                      case 'd' :
                             ctx->update_interval = strtol( optarg, NULL, 10 );
                             TRACE( "Update interval set to %d sec.\n", ctx->update_interval );
                             break;
                      case 'p' :
                             if (parse_pids( ctx, optarg) < 1 ) {
                                     ERROR( "Unable to parse process ID's\n");
                                     exit( EXIT_FAILURE );
                             }
                             OPERATION_ENABLE(ctx, OP_FOLLOW_PID);
                             break;
                      case 'R' :
                             if ( parse_port_filter( ctx, POLICY_REMOTE | POLICY_PORT, FILTERACT_IGNORE, 
                                                     optarg ) < 0 ) {
                                    ERROR(" Unable to create filter!\n");
                                   exit( EXIT_FAILURE );
                             }
                             break;
                      case 'A' :
                             if ( parse_addr_filter( ctx, POLICY_REMOTE | POLICY_ADDR, FILTERACT_IGNORE,
                                                     optarg ) < 0 ) {
                                     ERROR("Invalid address for ignore-address\n" );
                                     exit( EXIT_FAILURE );
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

        DBG("Adding routing info\n");
        parse_routing_info(ctx->iftab);


        ui_init( ctx );
        while ( 1 )  {
                if ( OPERATION_ENABLED(ctx,OP_FOLLOW_PID) ) 
                        scan_inodes( ctx->pinfo );

                if ( OPERATION_ENABLED(ctx, OP_IFSTATS ))
                        read_interface_stat( ctx );
                
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

                if ( ! OPERATION_ENABLED(ctx, OP_FOLLOW_PID)) {
                        rotate_new_queue( ctx );
                }
                round++;

                if ( ctx->total_count != ctx->chash->size ) {
                        int count = ctx->chash->size - ctx->total_count;
                        TRACE( "Going to purge connections (total %d, hash %d)\n", ctx->total_count, ctx->chash->size );
                        /* Some connections have to be deleted. */
                        if ( count > 0 ) {
                                if ( purge_closed_connections( ctx, count ) != 0 ) {
                                        WARN( "Purge closed blew it \n" );
                                        do_exit( ctx, "Fatal internal error!\n" );
                                }
                        }
                }  
                if ( OPERATION_ENABLED( ctx, OP_FOLLOW_PID) ) {
                        if ( check_dead_processes( ctx ) == 0 ) {
                                /* XXX - Some message is needed */
                                do_exit( ctx, "No more processes to follow!\n" );
                        }
                }
                ui_update_view( ctx );

                /* clear metadata flags from all the connections, 
                 * this way we'll notice new connections (and dead) 
                 * on next round...
                 */
                if ( OPERATION_ENABLED( ctx, OP_FOLLOW_PID )) {
                        clear_pid_metadata( ctx );
                } else {
                        clear_metadata_flags( ctx->listen_groups );
                        clear_metadata_flags( ctx->out_groups );
                }

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
        do_exit( ctx, "Bang; not here\n" );


        return 0;
}
