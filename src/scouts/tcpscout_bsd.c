/**
 * @file tcpscout_bsd.c Read TCP connection stats in BSD Systems.
 *
 * Copyright (c) J. Taimisto <jtaimisto@gmail.com>, 2011
 * All rights reserved.
 *
 * The functionality in this module mimics the way things are done in OpenBSD's
 * netstat. If you look at /usr/src/usr.bin/netstat/inet.c, there might be some
 * familiarity there.
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
#ifdef OPENBSD
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <arpa/inet.h>

#include <kvm.h>
#include <limits.h> /* _POSIX2_LINE_MAX */
#include <nlist.h>

#define DBG_MODULE_NAME DBG_MODULE_TCP

#include "defs.h"
#include "debug.h"
#include "connection.h"
#include "stat.h"

#define TCBTABLE_NAME "_tcbtable"

static struct nlist nl[] = {
        {.n_name = TCBTABLE_NAME,
        .n_type = 0, .n_value = 0},
        {.n_name = NULL, .n_type = 0, .n_value = 0}
};
/**
 * Table which can be used to convert the OpenBSD tcp
 * control block state number into the enum we use. 
 */
static enum tcp_state tcp_state_table[] = {
        TCP_DEAD, /* TCPS_CLOSED */
        TCP_LISTEN, /* TCPS_LISTEN */
        TCP_SYN_SENT, /* TCPS_SYN_SENT */
        TCP_SYN_RECV, /* TCPS_SYN_RECEIVED */
        TCP_ESTABLISHED, /* TCPS_ESTABLISHED */
        TCP_CLOSE_WAIT, /* TCPS_CLOSE_WAIT */
        TCP_FIN_WAIT1, /* TCPS_FIN_WAIT_1 */
        TCP_CLOSING, /* TCPS_CLOSING */
        TCP_LAST_ACK,  /* TCPS_LAST_ACK */
        TCP_FIN_WAIT2, /* TCPS_FIN_WAIT_2 */
        TCP_TIME_WAIT /* TCPS_TIME_WAIT */
};

/**
 * Extract the necessary information from given protocol control block and add it
 * to the system.
 * @param kv The kvm handle which can be used to read further data.
 * @param inpcb Pointer to the current protocol control block.
 * @param ctx Pointer to the global context.
 */
static int handle_connection(kvm_t *kv, struct inpcb *inpcb, struct stat_context *ctx)
{
        struct tcpcb tcpcb;
        struct sockaddr_storage local, remote;
        size_t rd;

        rd = kvm_read(kv, (u_long)inpcb->inp_ppcb, &tcpcb, sizeof(tcpcb));
        if (rd < sizeof(tcpcb)) {
                ERROR("Unable to read tcpcb: %s \n",
                                kvm_geterr(kv));
                return -1;
        }

        memset( &local, 0, sizeof(local));
        memset( &remote, 0, sizeof(remote));

        if (inpcb->inp_flags & INP_IPV6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&local; 
                sin6->sin6_family = AF_INET6;
                memcpy( &sin6->sin6_addr, &inpcb->inp_laddr6, sizeof(struct sockaddr_in6));
                sin6->sin6_port = inpcb->inp_lport;

                sin6 = (struct sockaddr_in6 *)&remote;
                sin6->sin6_family = AF_INET6;
                memcpy(&sin6->sin6_addr, &inpcb->inp_faddr6, sizeof(struct sockaddr_in6));
                sin6->sin6_port = inpcb->inp_fport;
        } else {
                struct sockaddr_in *sin = (struct sockaddr_in *)&local;

                sin->sin_family = AF_INET;
                memcpy(&sin->sin_addr, &inpcb->inp_laddr,sizeof(struct sockaddr_in));
                sin->sin_port = inpcb->inp_lport;

                sin = (struct sockaddr_in *)&remote;
                sin->sin_family = AF_INET;
                memcpy(&sin->sin_addr, &inpcb->inp_faddr, sizeof(struct sockaddr_in));
                sin->sin_port = inpcb->inp_fport;
        }

        ASSERT(tcpcb.t_state <= TCPS_TIME_WAIT);

        insert_connection( &local,&remote, tcp_state_table[tcpcb.t_state], ctx);
        return 0;
}

int read_tcp_stat( struct stat_context *ctx )
{
        kvm_t *kv;
        char err[_POSIX2_LINE_MAX];
        int ret;
        struct inpcb *next;
        struct inpcb inpcb;
        struct inpcbtable table;
        size_t rd;

        kv = kvm_openfiles(NULL,NULL,NULL, O_RDONLY, err);
        if (kv == NULL) {
                ERROR( "kvm_openfiles() failed : %s \n", err);
                return -1;
        }

        ret = kvm_nlist( kv, nl);
        ASSERT(ret == 0);
        TRACE(" %s : type %d, value %x \n", 
                        nl[0].n_name, nl[0].n_type,
                        nl[0].n_value);
        if (nl[0].n_type == 0) {
                ERROR("Unable to read namelist!\n");
                return -1;
        }

        rd = kvm_read(kv,nl[0].n_value, &table, sizeof table);
        if (rd < sizeof table) {
                ERROR("Unable to read inpcbtable: %s \n",
                                kvm_geterr(kv));
                kvm_close(kv);
                return -1;
        }

        if ( CIRCLEQ_EMPTY(&table.inpt_queue)) {
                WARN("No connections, inpt_queue empty\n");
                kvm_close(kv);
                return 0;
        }
        next = CIRCLEQ_FIRST(&table.inpt_queue);
        while (next != CIRCLEQ_LAST(&table.inpt_queue)) {
                rd = kvm_read(kv, (u_long)next, &inpcb, sizeof inpcb);
                if (rd  < sizeof inpcb){
                        ERROR("Unable to read next inpcb: %s \n", 
                                        kvm_geterr(kv));
                        kvm_close(kv);
                        return -1;
                }
                next = CIRCLEQ_NEXT(&inpcb, inp_queue); 

                if (inpcb.inp_flags & INP_IPV6 ) {
                        if (ctx->collected_stats == STAT_V4_ONLY)
                                continue;
                } else {
                        /* assuming this is IPv4 connection */
                        if (ctx->collected_stats == STAT_V6_ONLY)
                                continue;
                }

                handle_connection(kv, &inpcb, ctx);
        }
        
        kvm_close(kv);
        return 0;
}

int read_tcp6_stat( _UNUSED struct stat_context *ctx )
{
        return 0;
}
#endif /* OPENBSD */
