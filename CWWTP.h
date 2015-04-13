/*******************************************************************************************
 * Copyright (c) 2006-7 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
 *                      Universita' Campus BioMedico - Italy                               *
 *                                                                                         *
 * This program is free software; you can redistribute it and/or modify it under the terms *
 * of the GNU General Public License as published by the Free Software Foundation; either  *
 * version 2 of the License, or (at your option) any later version.                        *
 *                                                                                         *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY         *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 	   *
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


#ifndef __CAPWAP_CWWTP_HEADER__
#define __CAPWAP_CWWTP_HEADER__

/*_______________________________________________________*/
/*  *******************___INCLUDE___*******************  */

#include "CWCommon.h"
#include "WTPBinding.h"
//Elena Agostini - 07/2014
//#include "NL80211.h"


/*______________________________________________________*/
/*  *******************___DEFINE___*******************  */
//extern char * WTP_LOG_FILE_NAME;
//Elena Agostini: now it is useless - TODO remove from WTP this const
#define WTP_LOG_FILE_NAME	"/var/log/wtp.log.txt"

/*_____________________________________________________*/
/*  *******************___TYPES___*******************  */

typedef struct {
	char *address;
	CWBool received;
	int seqNum;
} CWACDescriptor;


#include "WTPProtocol.h"

/*_____________________________________________________________*/
/*  *******************___WTP VARIABLES___*******************  */
extern char* gInterfaceName;
extern char* gEthInterfaceName;
extern char* gBridgeInterfaceName;
extern char* gRadioInterfaceName_0;
extern char* gBaseMACInterfaceName;
extern char gBoardReversionNo;
extern char **gCWACAddresses;
extern int gCWACCount;

//Elena Agostini - 07/2014: nl80211 support
extern int gPhyInterfaceCount;
extern char ** gPhyInterfaceName;
extern int * gPhyInterfaceIndex;

/*
 * Elena Agostini - 02/2014
 *
 * QoS Static Values variables
 */
extern int qosStaticFreq;
extern int qosStaticBitRate;
extern int qosStaticFrag;
extern int qosStaticTxPower;
extern int qosStaticCwMin;
extern int qosStaticCwMax;
extern int qosStaticAifs;
extern int qosStaticWmeCwMin;
extern int qosStaticWmeCwMax;
extern int qosStaticWmeAifsn;

/*
 * Elena Agostini - 02/2014
 *
 * ECN Support Msg Elem MUST be included in Join Request/Response Messages
 */
extern int gWTPECNSupport;

extern int gHostapd_port;
extern char*  gHostapd_unix_path;
extern char  gRADIO_MAC[6];
extern pthread_mutex_t gRADIO_MAC_mutex;


extern char *gWTPLocation;
extern char *gWTPName;
extern char gWTPSessionID[16];
extern int gIPv4StatusDuplicate;
extern int gIPv6StatusDuplicate;
extern char *gWTPForceACAddress;
extern CWAuthSecurity gWTPForceSecurity;

extern CWSocket gWTPSocket;
extern CWSocket gWTPDataSocket;

extern int gWTPPathMTU;

extern CWACDescriptor *gCWACList;
extern CWACInfoValues *gACInfoPtr;

extern int gEchoInterval;
extern int gWTPStatisticsTimer;
extern WTPRebootStatisticsInfo gWTPRebootStatistics;
extern CWWTPRadiosInfo gRadiosInfo;
extern CWSecurityContext gWTPSecurityContext;
extern CWSecuritySession gWTPSession;
/*
 * Elena Agostini - 03/2014
 * 
 * DTLS Data Session WTP
 */
extern CWSecurityContext gWTPSecurityContextData;
extern CWSecuritySession gWTPSessionData;

extern CWPendingRequestMessage gPendingRequestMsgs[MAX_PENDING_REQUEST_MSGS];

extern CWSafeList gPacketReceiveList;
extern CWSafeList gFrameList;
extern CWThreadCondition gInterfaceWait;
extern CWThreadMutex gInterfaceMutex;

//Elena Agostini: Mutex and Cond dedicated to Data Packet List
extern CWSafeList gPacketReceiveDataList;
extern CWThreadCondition gInterfaceWaitData;
extern CWThreadMutex gInterfaceMutexData;

/*
 * Elena Agostini - 02/2014: OpenSSL params variables
 */
extern char *gWTPCertificate;
extern char *gWTPKeyfile;
extern char *gWTPPassword;

/*
 * Elena Agostini - 02/2014
 * Port number params config.wtp
 */
extern int WTP_PORT_CONTROL;
extern int WTP_PORT_DATA;

#define MAC_ADDR_LEN 6


extern int wtpInRunState;

/*__________________________________________________________*/
/*  *******************___PROTOTYPES___*******************  */

/* in WTP.c */
CWBool CWWTPLoadConfiguration();
CWBool CWWTPInitConfiguration();
void CWWTPResetRadioStatistics(WTPRadioStatisticsInfo *radioStatistics);
CWBool CWReceiveMessage(CWProtocolMessage *msgPtr);
/*
 * Elena Agostini - 03/2014
 * DTLS Data Session WTP
 */
CWBool CWReceiveDataMessage(CWProtocolMessage *msgPtr);
CWBool CWWTPSendAcknowledgedPacket(int seqNum,
				   CWList msgElemlist, 
				   CWBool (assembleFunc)(CWProtocolMessage **, int *, int, int, CWList),
				   CWBool (parseFunc)(char*, int, int, void*),
				   CWBool (saveFunc)(void*),
				   void *valuesPtr);
void CWWTPDestroy();

/* in WTPRunState.c */
CWBool CWAssembleWTPDataTansferRequest(CWProtocolMessage **messagesPtr,
				       int *fragmentsNumPtr,
				       int PMTU,
				       int seqNum,
				       CWList msgElemList);

CWBool CWAssembleWTPEventRequest(CWProtocolMessage **messagesPtr,
				 int *fragmentsNumPtr,
				 int PMTU,
				 int seqNum,
				 CWList msgElemList,
				 CWMsgElemDataDeleteStation * infoDeleteStation);

CW_THREAD_RETURN_TYPE CWWTPReceiveDtlsPacket(void *arg);
CW_THREAD_RETURN_TYPE CWWTPReceiveDataPacket(void *arg);
CWBool CWWTPCheckForBindingFrame();

/* in WTPProtocol_User.c */
CWBool CWWTPGetACNameWithIndex (CWACNamesWithIndex *ACsInfo);
int getInterfaceMacAddr(char* interface, unsigned char* macAddr);
int initWTPSessionID(char * sessionID);
int CWWTPGetStatisticsTimer ();
void CWWTPGetIPv6Address(struct sockaddr_in6* myAddr);
CWBool CWGetWTPRadiosAdminState(CWRadiosAdminInfo *valPtr);
CWBool CWGetDecryptErrorReport(int radioID, CWDecryptErrorReportInfo *valPtr);

/* in WTPRetransmission.c */
int CWSendPendingRequestMessage(CWPendingRequestMessage *pendingRequestMsgs,
				CWProtocolMessage *messages,
				int fragmentsNum);

int CWFindPendingRequestMsgsBox(CWPendingRequestMessage *pendingRequestMsgs,
				const int length,
				const int msgType,
				const int seqNum);

void CWResetPendingMsgBox(CWPendingRequestMessage *pendingRequestMsgs);
CWBool CWUpdatePendingMsgBox(CWPendingRequestMessage *pendingRequestMsgs,
			     unsigned char msgType,
			     int seqNum,
			     int timer_sec,
			     CWTimerArg timer_arg,
			     void (*timer_hdl)(CWTimerArg),
			     int retransmission,
			     CWProtocolMessage *msgElems,
			     int fragmentsNum);
			     
//in WTPDriverInteraction.c

/*
 * Elena Agostini - 02/2014
 * 
 * No more ioctl() on wireless drivers.
 * API coming soon..
 */

//#ifdef SOFTMAC
int set_wme_cwmin(int acclass,int value);
int set_wme_cwmax(int acclass,int value);
int set_wme_aifsn(int acclass,int value);
//#else
int set_cwmin(int sock, struct iwreq wrq, int acclass, int sta, int value);
int get_cwmin(int sock, struct iwreq* wrq, int acclass, int sta);
int set_cwmax(int sock, struct iwreq wrq, int acclass, int sta, int value);
int get_cwmax(int sock, struct iwreq* wrq, int acclass, int sta);
int set_aifs(int sock, struct iwreq wrq, int acclass, int sta, int value);
int get_aifs(int sock, struct iwreq* wrq, int acclass, int sta);
//#endif

/* in WTPDiscoveryState.c */
CWStateTransition CWWTPEnterDiscovery();
void CWWTPPickACInterface();

CWStateTransition CWWTPEnterSulking();
CWStateTransition CWWTPEnterJoin();
CWStateTransition CWWTPEnterConfigure();
CWStateTransition CWWTPEnterDataCheck();
CWStateTransition CWWTPEnterRun();

CWBool CWStartHeartbeatTimer();
CWBool CWStopHeartbeatTimer();

/*
 * Elena Agostini - 03/2014
 * 
 * DataChannel Dead Timer
 */
CWBool CWStartDataChannelDeadTimer();
CWBool CWStopDataChannelDeadTimer();
CWBool CWResetDataChannelDeadTimer();
CWBool CWStartKeepAliveTimer();
CWBool CWStopKeepAliveTimer();

/*
 * Elena Agostini - 03/2014
 * 
 * Echo Request Timer
 */
CWBool CWStartEchoRequestTimer();
CWBool CWStopEchoRequestsTimer();
CWBool CWResetEchoRequestRetransmit();
void CWWTPEchoRequestTimerExpiredHandler(void *arg);

CWBool CWStartNeighborDeadTimer();
CWBool CWStopNeighborDeadTimer();
void CWWTPNeighborDeadTimerExpired();

void CWWTPHeartBeatTimerExpiredHandler(void *arg); 
void CWWTPRetransmitTimerExpiredHandler(CWTimerArg arg);

				   
extern CWBool WTPExitOnUpdateCommit;

#endif
