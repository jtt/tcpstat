/**
 * @file tcpscout_osx.c Read available TCP connections on OS X.
 *
 * Copyright (c) J. Taimisto <jtaimisto@gmail.com>, 2011
 * All rights reserved.
 *
 * The functionality in this module mimics the way things are done in OS X's
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
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/sysctl.h>
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

#define DBG_MODULE_NAME DBG_MODULE_TCP

#include "defs.h"
#include "debug.h"
#include "connection.h"
#include "stat.h"

#define SYSCTL_NAME "net.inet.tcp.pcblist64"

static enum tcp_state get_tcp_state( short state )
{
	enum tcp_state ret = TCP_DEAD;

	switch(state) {
		case TCPS_CLOSED :
			ret = TCP_DEAD;
			break;
		case TCPS_LISTEN :
			ret = TCP_LISTEN;
			break;
		case TCPS_SYN_SENT :
			ret = TCP_SYN_SENT;
			break;
		case TCPS_SYN_RECEIVED :
			ret = TCP_SYN_RECV;
			break;
		case TCPS_ESTABLISHED :
			ret = TCP_ESTABLISHED;
			break;
		case TCPS_CLOSE_WAIT :
			ret = TCP_CLOSE_WAIT;
			break;
		case TCPS_FIN_WAIT_1 :
			ret = TCP_FIN_WAIT1;
			break;
		case TCPS_CLOSING :
			ret = TCP_CLOSING;
			break;
		case TCPS_LAST_ACK :
			ret = TCP_LAST_ACK;
			break;
		case TCPS_FIN_WAIT_2 :
			ret = TCP_FIN_WAIT2;
			break;
		case TCPS_TIME_WAIT :
			ret = TCP_TIME_WAIT;
			break;
		default :
			ASSERT(0);
			break;
	}
	return ret;
}




int read_tcp_stat( struct stat_context *ctx)
{
        int ret, got_connection;
        char *sysctl_buf;
        size_t len = 0;
        struct xinpgen *xip;
        struct xtcpcb64 *tcpcb;
        struct xinpcb64 *inpcb;
        struct xsocket64 *sock;
        struct sockaddr_storage local;
        struct sockaddr_storage remote;
        struct sockaddr_in *sin;
        struct sockaddr_in6 *sin6;

        ret = sysctlbyname(SYSCTL_NAME, NULL, &len, NULL, 0);
        if (ret < 0) {
                WARN("sysctlbyname(%s ..) failed %d \n",
                                SYSCTL_NAME, ret);
                return -1;
        }
        TRACE("Required lenght for buffer is %d \n",len);
        sysctl_buf = mem_alloc( len * sizeof(char));
        ret = sysctlbyname(SYSCTL_NAME, sysctl_buf, &len, NULL, 0);
        if (ret < 0) {
                WARN("sysctlbyname(%s ..) failed %d \n", 
                                SYSCTL_NAME, ret);
                mem_free(sysctl_buf);
                return -1;
        }
        if (len < sizeof(struct xinpgen)) {
                WARN("Did not get enough data (%d bytes)\n",
                                len);
                mem_free(sysctl_buf);
                return -1;
        }

        xip = (struct xinpgen *)sysctl_buf;
        for (xip = (struct xinpgen *)((char *)xip + xip->xig_len);
                        xip->xig_len > sizeof(struct xinpgen);
                        xip = (struct xinpgen *)((char *)xip + xip->xig_len)) {

                got_connection = 0;
                tcpcb = (struct xtcpcb64 *)xip;
                inpcb = &tcpcb->xt_inpcb;
                sock =  &inpcb->xi_socket;

                if (sock->xso_protocol != 6 ) 
                        continue;

                if (inpcb->inp_vflag & INP_IPV4 ) {
                        if (ctx->collected_stats == STAT_V6_ONLY)
                                continue;

                        sin = (struct sockaddr_in *)&local;
                        sin->sin_family = AF_INET;
                        memcpy( &sin->sin_addr, &inpcb->inp_laddr, sizeof(struct in_addr));
                        sin->sin_port = inpcb->inp_lport;

                        sin = (struct sockaddr_in *)&remote;
                        sin->sin_family = AF_INET;
                        memcpy( &sin->sin_addr, &inpcb->inp_faddr, sizeof(struct in_addr));
                        sin->sin_port = inpcb->inp_fport;
                        got_connection = 1;
                } else if (inpcb->inp_vflag & INP_IPV6) {
                        if (ctx->collected_stats == STAT_V4_ONLY) 
                                continue;

                        sin6 = (struct sockaddr_in6 *)&local;
                        sin6->sin6_family = AF_INET6;
                        memcpy( &sin6->sin6_addr, &inpcb->inp_laddr, sizeof(struct in6_addr));
                        sin6->sin6_port = inpcb->inp_lport;

                        sin6 = (struct sockaddr_in6 *)&remote;
                        sin6->sin6_family = AF_INET6;
                        memcpy( &sin6->sin6_addr, &inpcb->inp_faddr, sizeof(struct in6_addr));
                        sin6->sin6_port = inpcb->inp_fport;
                        got_connection = 1;
                } else {
                        continue;
                }
                if (got_connection) 
                        insert_connection( &local, &remote, get_tcp_state(tcpcb->t_state), ctx);

        }
        mem_free(sysctl_buf);
        return 0;
}
