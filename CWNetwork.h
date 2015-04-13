/*******************************************************************************************
 * Copyright (c) 2006-7 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
 *                      Universita' Campus BioMedico - Italy                               *
 *                                                                                         *
 * This program is free software; you can redistribute it and/or modify it under the terms *
 * of the GNU General Public License as published by the Free Software Foundation; either  *
 * version 2 of the License, or (at your option) any later version.                        *
 *                                                                                         *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY         *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 	       *
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.                *
 *                                                                                         *
 * You should have received a copy of the GNU General Public License along with this       *
 * program; if not, write to the:                                                          *
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,                    *
 * MA  02111-1307, USA.                                                                    *
 *                                                                                         *
 * In addition, as a special exception, the copyright holders give permission to link the  *
 * code of portions of this program with the OpenSSL library under certain conditions as   *
 * described in each individual source file, and distribute linked combinations including  * 
 * the two. You must obey the GNU General Public License in all respects for all of the    *
 * code used other than OpenSSL.  If you modify file(s) with this exception, you may       *
 * extend this exception to your version of the file(s), but you are not obligated to do   *
 * so.  If you do not wish to do so, delete this exception statement from your version.    *
 * If you delete this exception statement from all source files in the program, then also  *
 * delete it here.                                                                         *
 * 
 * --------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                        *
 *                                                                                         *
 * Author :  Ludovico Rossi (ludo@bluepixysw.com)                                          *  
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                    *
 *           Giovannini Federica (giovannini.federica@gmail.com)                           *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                    *
 *           Mauro Bisson (mauro.bis@gmail.com)                                            *
 *******************************************************************************************/

 
#ifndef __CAPWAP_CWNetwork_HEADER__
#define __CAPWAP_CWNetwork_HEADER__

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netdb.h>

#include "CWStevens.h"

typedef int CWSocket;

typedef struct sockaddr_storage CWNetworkLev4Address;

typedef enum {
	CW_IPv6,
	CW_IPv4
} CWNetworkLev3Service;

extern CWNetworkLev3Service gNetworkPreferredFamily;

#define	CW_COPY_NET_ADDR_PTR(addr1, addr2)  	sock_cpy_addr_port(((struct sockaddr*)(addr1)), ((struct sockaddr*)(addr2)))
#define	CW_COPY_NET_ADDR(addr1, addr2)		CW_COPY_NET_ADDR_PTR(&(addr1), &(addr2))

#define CWUseSockNtop(sa, block) 		{ 						\
							char __str[128];			\
							char *str; str = sock_ntop_r(((struct sockaddr*)(sa)), __str);\
							{block}					\
						}

#define CWNetworkRaiseSystemError(error)	{						\
							char buf[256];				\
							if(strerror_r(errno, buf, 256) < 0) {	\
								CWErrorRaise(error, NULL);	\
								return CW_FALSE;		\
							}					\
							CWErrorRaise(error, NULL);		\
							return CW_FALSE;			\
						}

#define		CWNetworkCloseSocket(x)		{ shutdown(SHUT_RDWR, x); close(x); }

int CWNetworkGetAddressSize(CWNetworkLev4Address *addrPtr);
CWBool CWNetworkSendUnsafeConnected(CWSocket sock, const char *buf, int len);
CWBool CWNetworkSendUnsafeUnconnected(CWSocket sock, CWNetworkLev4Address *addrPtr, const char *buf, int len);
CWBool CWNetworkReceiveUnsafe(CWSocket sock, char *buf, int len, int flags, CWNetworkLev4Address *addrPtr, int *readBytesPtr);
CWBool CWNetworkReceiveUnsafeConnected(CWSocket sock, char *buf, int len, int *readBytesPtr);
CWBool CWNetworkInitSocketClient(CWSocket *sockPtr, CWNetworkLev4Address *addrPtr);
CWBool CWNetworkInitSocketClientDataChannel(CWSocket *sockPtr, CWNetworkLev4Address *addrPtr);

/*
 * Elena Agostini - 04/2014: specify port number to bind socket
 */
CWBool CWNetworkInitSocketClientWithPort(CWSocket *sockPtr, CWNetworkLev4Address *addrPtr, int portSocket);
CWBool CWNetworkInitSocketClientDataChannelWithPort(CWSocket *sockPtr, CWNetworkLev4Address *addrPtr, int portSocket);

CWBool CWNetworkTimedPollRead(CWSocket sock, struct timeval *timeout);
CWBool CWNetworkGetAddressForHost(char *host, CWNetworkLev4Address *addrPtr);


//CWBool CWNetworkInitLib(void);
//CWBool CWNetworkInitSocketServer(CWSocket *sockPtr, int port);
//CWBool CWNetworkSendUnsafeConnected(CWSocket sock, const char *buf, int len);

#endif
