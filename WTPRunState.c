/************************************************************************************************
 * Copyright (c) 2006-2009 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica	*
 *                          Universita' Campus BioMedico - Italy								*
 *																								*
 * This program is free software; you can redistribute it and/or modify it under the terms		*
 * of the GNU General Public License as published by the Free Software Foundation; either		*
 * version 2 of the License, or (at your option) any later version.								*
 *																								*
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY				*
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A				*
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.						*
 *																								*
 * You should have received a copy of the GNU General Public License along with this			*
 * program; if not, write to the:																*
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,							*
 * MA  02111-1307, USA.																			*
 *												
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
 * -------------------------------------------------------------------------------------------- *
 * Project:  Capwap																				*
 *																								*
 * Authors : Ludovico Rossi (ludo@bluepixysw.com)												*  
 *           Del Moro Andrea (andrea_delmoro@libero.it)											*
 *           Giovannini Federica (giovannini.federica@gmail.com)								*
 *           Massimo Vellucci (m.vellucci@unicampus.it)											*
 *           Mauro Bisson (mauro.bis@gmail.com)													*
 *	         Antonio Davoli (antonio.davoli@gmail.com)											*
 * 	         Elena Agosini (elena.ago@gmail.com)												*
 ************************************************************************************************/
#include <sys/socket.h>
#include <sys/types.h>  
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include "CWWTP.h"
#include "CWVendorPayloads.h"
#include "common.h"
#include "ieee802_11_defs.h"
#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

CWBool CWWTPManageGenericRunMessage(CWProtocolMessage *msgPtr);

CWBool CWWTPCheckForBindingFrame();

CWBool CWWTPCheckForWTPEventRequest(int eventType, CWMsgElemDataDeleteStation * infoDeleteStation);
CWBool CWParseWTPEventResponseMessage(char *msg,
				      int len,
				      int seqNum,
				      void *values);

CWBool CWSaveWTPEventResponseMessage(void *WTPEventResp);

CWBool CWAssembleEchoRequest(CWProtocolMessage **messagesPtr,
			     int *fragmentsNumPtr,
			     int PMTU,
			     int seqNum,
			     CWList msgElemList);

CWBool CWParseConfigurationUpdateRequest (char *msg,
										  int len,
										  CWProtocolConfigurationUpdateRequestValues *valuesPtr, 
										  int *updateRequestType);

CWBool CWSaveConfigurationUpdateRequest(CWProtocolConfigurationUpdateRequestValues *valuesPtr,
										CWProtocolResultCode* resultCode,
										int *updateRequestType);

CWBool CWAssembleConfigurationUpdateResponse(CWProtocolMessage **messagesPtr,
					     int *fragmentsNumPtr,
					     int PMTU,
					     int seqNum,
					     CWProtocolResultCode resultCode,
						 CWProtocolConfigurationUpdateRequestValues values);

CWBool CWSaveClearConfigurationRequest(CWProtocolResultCode* resultCode);

CWBool CWAssembleClearConfigurationResponse(CWProtocolMessage **messagesPtr,
					    int *fragmentsNumPtr,
					    int PMTU,
					    int seqNum,
					    CWProtocolResultCode resultCode);

CWBool CWAssembleStationConfigurationResponse(CWProtocolMessage **messagesPtr,
					      int *fragmentsNumPtr,
					      int PMTU,
					      int seqNum,
					      CWProtocolResultCode resultCode);

					      
CWBool CWParseStationConfigurationRequest (char *msg, int len, int * BSSIndex, int * STAIndex, int * typeOp);

void CWConfirmRunStateToACWithEchoRequest();
void CWWTPKeepAliveDataTimerExpiredHandler(void *arg);

CWTimerID gCWHeartBeatTimerID;
CWTimerID gCWEchoRequestTimerID;
CWTimerID gCWKeepAliveTimerID;
CWTimerID gCWNeighborDeadTimerID;
/*
 * Elena Agostini - 03/2014: DataChannel Dead Timer
 */
CWTimerID gCWDataChannelDeadTimerID;
CWBool gDataChannelDeadTimerSet=CW_FALSE;
int gDataChannelDeadInterval = CW_DATACHANNELDEAD_INTERVAL_DEFAULT;
CWBool gWTPDataChannelDeadFlag = CW_FALSE;
int gWTPThreadDataPacketState = 0;

/*
 * Elena Agostini - 03/2014: Echo Retransmission Count
 */
int gWTPEchoRetransmissionCount=0;
int gWTPMaxRetransmitEcho=CW_ECHO_MAX_RETRANSMIT_DEFAULT;
CWBool gWTPExitRunEcho=CW_FALSE;

CWBool gNeighborDeadTimerSet=CW_FALSE;
	
int gEchoInterval = CW_ECHO_INTERVAL_DEFAULT;
int gDataChannelKeepAlive = CW_DATA_CHANNEL_KEEP_ALIVE_DEFAULT;
CWBool gEchoTimerSet=CW_FALSE;

/* 
 * Manage DTLS packets.
 */
CW_THREAD_RETURN_TYPE CWWTPReceiveDtlsPacket(void *arg) {

	int 			readBytes;
	char 			buf[CW_BUFFER_SIZE];
	CWSocket 		sockDTLS = (CWSocket)arg;
	CWNetworkLev4Address	addr;
	char* 			pData;
	CWBool gWTPDataChannelLocalFlag=CW_FALSE, gWTPExitRunEchoLocal=CW_FALSE;

	CWLog("THREAD Receiver Control channel start");
	
	CW_REPEAT_FOREVER 
	{
		CWThreadMutexLock(&gInterfaceMutex);
		gWTPDataChannelLocalFlag = gWTPDataChannelDeadFlag;
		gWTPExitRunEchoLocal=gWTPExitRunEcho;
		CWThreadMutexUnlock(&gInterfaceMutex);
		
		if(gWTPDataChannelLocalFlag == CW_TRUE)
		{
			CWLog("Data Channel is dead... so receiver Control Packet must die!");
			break;
		}
		
		if(gWTPExitRunEchoLocal == CW_TRUE)
		{
			CWLog("Control Channel is dead... so receiver Control Packet must die!");
			break;
		}
		
		if(!CWErr(CWNetworkReceiveUnsafe(sockDTLS,
						 buf, 
						 CW_BUFFER_SIZE - 1,
						 0,
						 &addr,
						 &readBytes))) {

			if (CWErrorGetLastErrorCode() == CW_ERROR_INTERRUPTED)
				continue;
			
			break;
		}
		
		/* Clone data packet */
		CW_CREATE_OBJECT_SIZE_ERR(pData, readBytes, { CWLog("Out Of Memory"); return NULL; });
		memcpy(pData, buf, readBytes);

		CWLockSafeList(gPacketReceiveList);
		CWAddElementToSafeListTailwitDataFlag(gPacketReceiveList, pData, readBytes,CW_FALSE);
		CWUnlockSafeList(gPacketReceiveList);		
	}
	
	CWLog("THREAD Receiver Control channel exit");
	
/*
 *  If there is a channel error, manager threads stop without the use of this flag *
	CWThreadMutexLock(&gInterfaceMutex);
	gWTPExitRunEcho=CW_TRUE;
	CWThreadMutexUnlock(&gInterfaceMutex);
*/
	CWNetworkCloseSocket(sockDTLS);
	
	return NULL;
}

extern int gRawSock;
/* 
 * Manage data packets.
 */
#define HLEN_80211	24

CW_THREAD_RETURN_TYPE CWWTPReceiveDataPacket(void *arg) {

	int 			n,readBytes;
	char 			buf[CW_BUFFER_SIZE];
	struct sockaddr_ll 	rawSockaddr;	
	CWSocket 		sockDTLS = (CWSocket)arg;
	CWNetworkLev4Address	addr;
	char* 			pData;
	CWBool gWTPDataChannelLocalFlag=CW_FALSE, gWTPExitRunEchoLocal=CW_FALSE;
	
	CWLog("THREAD Receiver Data channel start on socket %d", sockDTLS);
	
	CW_REPEAT_FOREVER 
	{
		CWThreadMutexLock(&gInterfaceMutex);
		gWTPDataChannelLocalFlag = gWTPDataChannelDeadFlag;
		gWTPExitRunEchoLocal=gWTPExitRunEcho;
		CWThreadMutexUnlock(&gInterfaceMutex);
		
		if(gWTPDataChannelLocalFlag == CW_TRUE)
		{
			CWLog("Data Channel is dead... so receiver Data Packet must die!");
			goto manager_data_failure;
		}
		
		if(gWTPExitRunEchoLocal == CW_TRUE)
		{
			CWLog("Control Channel is dead... so receiver Data Packet must die!");
			goto manager_data_failure;
		}
	
		if(!CWErr(CWNetworkReceiveUnsafe(sockDTLS,
							buf, 
							CW_BUFFER_SIZE - 1,
							0,
							&addr,
							&readBytes))) {

				if (CWErrorGetLastErrorCode() == CW_ERROR_INTERRUPTED)
					continue;
				CWLog("CWErrorGetLastErrorCode(): %d",CWErrorGetLastErrorCode());
				break;
		}
		
		/* Clone data packet */
		CW_CREATE_OBJECT_SIZE_ERR(pData, readBytes, { CWLog("Out Of Memory"); return NULL; });
		memcpy(pData, buf, readBytes);
		CWLockSafeList(gPacketReceiveDataList);
		CWAddElementToSafeListTailwitDataFlag(gPacketReceiveDataList, pData, readBytes, CW_TRUE);
		CWUnlockSafeList(gPacketReceiveDataList);
	}
/*
 * 	If there is a channel error, manager threads stop without the use of this flag *
	CWThreadMutexLock(&gInterfaceMutex);
	gWTPDataChannelDeadFlag=CW_TRUE;
	CWThreadMutexUnlock(&gInterfaceMutex);
*/
manager_data_failure:

	CWLog("THREAD Receiver Data channel exit");	
	CWNetworkCloseSocket(sockDTLS);

	return NULL;
}

/*
 * Elena Agostini - 03/2014: Manage RUN State WTPDataChannel + DTLS Data Channel
 */
 CW_THREAD_RETURN_TYPE CWWTPManageDataPacket(void *arg) {
	
	int 			n,readBytes;
	struct sockaddr_ll 	rawSockaddr;	
	CWProtocolMessage 	msgPtr;
	CWBool			gWTPDataChannelLocalFlag = CW_FALSE;
	CWBool			gWTPExitRunEchoLocal = CW_FALSE;
	int msg_len;
	int gWTPThreadDataPacketStateLocal=0;
	CWBool bReceivePacket;
	
	CWLog("THREAD Manager Data channel start");


	/* Elena Agostini - 07/2014: data packet thread alive flag */
	CWThreadMutexLock(&gInterfaceMutex);
	gWTPThreadDataPacketState = 1;
	CWThreadMutexUnlock(&gInterfaceMutex);

#ifdef CW_DTLS_DATA_CHANNEL

	struct sockaddr_in *tmpAdd = (struct sockaddr_in *) &(gACInfoPtr->preferredAddress);
	CWNetworkLev4Address * gACAddressDataChannel = (CWNetworkLev4Address *)tmpAdd;
	tmpAdd->sin_port = htons(5247);
	CWLog("[DTLS] Start Data Session with AC %s:%d", inet_ntoa(tmpAdd->sin_addr), ntohs(tmpAdd->sin_port));

	if(!CWErr(CWSecurityInitSessionClient(gWTPDataSocket,
					      gACAddressDataChannel,
					      gPacketReceiveDataList,
					      gWTPSecurityContext,
					      &gWTPSessionData,
					      &gWTPPathMTU))) {
		
		//Elena Agostini - 07/2014
		goto CLEAR_DATA_RUN_STATE;
	}
	
#endif

	CWThreadMutexLock(&gInterfaceMutex);
	gWTPDataChannelDeadFlag=CW_FALSE;
	CWThreadMutexUnlock(&gInterfaceMutex);
	
	CWWTPKeepAliveDataTimerExpiredHandler(NULL);

	CW_REPEAT_FOREVER
	{
		/*
		 * Flag DataChannel & ControlChannel Dead
		 */
		bReceivePacket = CW_FALSE;
		CWThreadMutexLock(&gInterfaceMutex);
		gWTPDataChannelLocalFlag = gWTPDataChannelDeadFlag;
		gWTPExitRunEchoLocal=gWTPExitRunEcho;
		gWTPThreadDataPacketStateLocal=gWTPThreadDataPacketState;
		CWThreadMutexUnlock(&gInterfaceMutex);
		
		if(gWTPDataChannelLocalFlag == CW_TRUE)
		{
			CWLog("Data Channel is dead.. Thread CWWTPManageDataPacket exit");
			break;
		}
		if(gWTPExitRunEchoLocal == CW_TRUE)
		{
			CWLog("Control Channel is dead.. Thread CWWTPManageDataPacket exit");
			break;
		}
		if(gWTPThreadDataPacketStateLocal == 2)
		{
			CWLog("Data Packet Thread must die.. Thread CWWTPManageDataPacket exit");
			break;
		}
	
		msgPtr.msg = NULL;
		msgPtr.offset = 0;
		
		CWThreadMutexLock(&gInterfaceMutex);
		bReceivePacket = ((CWGetCountElementFromSafeList(gPacketReceiveDataList) != 0) ? CW_TRUE : CW_FALSE);
		CWThreadMutexUnlock(&gInterfaceMutex);
		
		if (bReceivePacket) {
			
			/* Elena Agostini - 03/2014: DTLS Data Session WTP */
			if(!CWReceiveDataMessage(&msgPtr))
			{
				CW_FREE_PROTOCOL_MESSAGE(msgPtr);
				CWLog("Failure Receiving Data Message");
				break;
				//continue;
			}

			if (msgPtr.data_msgType == CW_DATA_MSG_KEEP_ALIVE_TYPE) {

					char *valPtr=NULL;
					unsigned short int elemType = 0;
					unsigned short int elemLen = 0;

					msgPtr.offset=0;	
					CWParseFormatMsgElem(&msgPtr, &elemType, &elemLen);
					valPtr = CWParseSessionID(&msgPtr, 16);
					
					/*
					 * Elena Agostini - 03/2014
					 * Reset DataChannel Dead Timer
					 */
					if (!CWResetDataChannelDeadTimer()) {
						CW_FREE_PROTOCOL_MESSAGE(msgPtr);
						break;
					}
				}else if (msgPtr.data_msgType == CW_IEEE_802_3_FRAME_TYPE) {

					CWDebugLog("DATA Frame 802.3 (%d bytes) received from AC",msgPtr.offset);
					
					/*MAC - begin*/
					rawSockaddr.sll_addr[0]  = msgPtr.msg[0];		
					rawSockaddr.sll_addr[1]  = msgPtr.msg[1];		
					rawSockaddr.sll_addr[2]  = msgPtr.msg[2];
					rawSockaddr.sll_addr[3]  = msgPtr.msg[3];
					rawSockaddr.sll_addr[4]  = msgPtr.msg[4];
					rawSockaddr.sll_addr[5]  = msgPtr.msg[5];
					/*MAC - end*/
					rawSockaddr.sll_addr[6]  = 0x00;/*not used*/
					rawSockaddr.sll_addr[7]  = 0x00;/*not used*/
					
					rawSockaddr.sll_hatype   = htons(msgPtr.msg[12]<<8 | msgPtr.msg[13]);
					
					struct sockaddr_ll addr;
					int gRawSockLocal;
					
					if ((gRawSockLocal=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0) 	{
						CWDebugLog("THR FRAME: Error creating socket");
						CWExitThread();
					}

					memset(&addr, 0, sizeof(addr));
					addr.sll_family = AF_PACKET;
				//	addr.sll_protocol = htons(ETH_P_ALL);
				//	addr.sll_pkttype = PACKET_HOST;
					addr.sll_ifindex = if_nametoindex("monitor0"); //if_nametoindex(gRadioInterfaceName_0);
				 
					 
					if ((bind(gRawSockLocal, (struct sockaddr*)&addr, sizeof(addr)))<0) {
						CWDebugLog("THR FRAME: Error binding socket");
						CWExitThread();
					}
				 
					n = sendto(gRawSockLocal,msgPtr.msg ,msgPtr.offset,0,(struct sockaddr*)&rawSockaddr, sizeof(rawSockaddr));
					
				}else if(msgPtr.data_msgType == CW_IEEE_802_11_FRAME_TYPE) {
				
#ifdef SPLIT_MAC
					int offsetFrameReceived;
					short int frameControl;
					char * frameResponse=NULL;
					u64 cookie_out;
					
					if(!CW80211ParseFrameIEControl(msgPtr.msg, &(offsetFrameReceived), &(frameControl)))
						return NULL;
					
					if( WLAN_FC_GET_TYPE(frameControl) == WLAN_FC_TYPE_DATA ){
						unsigned char buffer[CW_BUFFER_SIZE];
						unsigned char buf80211[CW_BUFFER_SIZE];
						unsigned char staAddr[ETH_ALEN];
						struct ieee80211_radiotap_header * radiotapHeader;
						int frameRespLen=0;
						struct CWFrameDataHdr dataFrame;
						int tmpOffset;
						struct ifreq ethreq;
						WTPSTAInfo * thisSTA;
						int offsetFrameReceived;
						int indexBSS;
						
							if(rawInjectSocket < 0)
							{
								CWLog("ERROR INJECT SOCKET. You must restart WTP");
								return CW_FALSE;
							}

							if(!CW80211ParseDataFrameFromDS(msgPtr.msg, &(dataFrame)))
							{
								CWLog("CW80211: Error parsing data frame");
								return CW_FALSE;
							}
						/*	CWLog("*** Ricevuto Data Frame da AC ***");
							CWLog("FrameControl: %02x", dataFrame.frameControl);
							CWLog("DA: %02x: --- :%02x: --", (int) dataFrame.DA[0], (int) dataFrame.DA[4]);
							CWLog("SA: %02x: --- :%02x: --", (int) dataFrame.SA[0], (int) dataFrame.SA[4]);
							CWLog("BSSID: %02x: --- :%02x: --", (int) dataFrame.BSSID[0], (int) dataFrame.BSSID[4]);
							*/
							if(checkAddressBroadcast(dataFrame.DA))
							{
						//		CWLog("Broadcast destination");
								CWInjectFrameMonitor(rawInjectSocket, msgPtr.msg, msgPtr.offset, 0, 0);
							}
							else
							{
								nodeAVL *tmpNodeSta=NULL;
								//---- Search AVL node
								CWThreadMutexLock(&mutexAvlTree);
								tmpNodeSta = AVLfind(dataFrame.DA, avlTree);
								//AVLdisplay_avl(avlTree);
								CWThreadMutexUnlock(&mutexAvlTree);
								if(tmpNodeSta == NULL)
									CWPrintEthernetAddress(dataFrame.DA, "Destination STA not associated. Ignored");
								else
								{
									//NB. Controllo anche il BSSID?
						//			CWLog("STA trovata [%02x:%02x:%02x:%02x:%02x:%02x] destinataria.", (int) tmpNodeSta->staAddr[0], (int) tmpNodeSta->staAddr[1], (int) tmpNodeSta->staAddr[2], (int) tmpNodeSta->staAddr[3], (int) tmpNodeSta->staAddr[4], (int) tmpNodeSta->staAddr[5]);
									CWInjectFrameMonitor(rawInjectSocket, msgPtr.msg, msgPtr.offset, 0, 0);
								}
								//----
							}
					}
					
					if(WLAN_FC_GET_STYPE(frameControl) == WLAN_FC_STYPE_AUTH)
					{
						CWLog("Received From AC Authentication Response");
						
						struct CWFrameAuthResponse authResponse;
						if(!CW80211ParseAuthResponse(msgPtr.msg, &authResponse))
						{
							CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
							return NULL;
						}
						
						int radioIndex = 0, wlanIndex = 0, BSSIndex=0, trovato=0; 
						for(radioIndex=0; radioIndex<WTP_RADIO_MAX; radioIndex++)
						{
							for(wlanIndex=0; wlanIndex<WTP_MAX_INTERFACES; wlanIndex++)
							{
								BSSIndex=getBSSIndex(radioIndex, wlanIndex);
								if(
									(WTPGlobalBSSList[BSSIndex]->interfaceInfo->BSSID != NULL) && 
									(!strcmp(WTPGlobalBSSList[BSSIndex]->interfaceInfo->BSSID, authResponse.BSSID))
								)
								{
									trovato=1;
									break;
								}
							}
							
							if(trovato == 1)
								break;
						}
						
						if(trovato == 1)
						{
							if(!CW80211SendFrame(WTPGlobalBSSList[BSSIndex], 0, CW_FALSE, msgPtr.msg, MGMT_FRAME_FIXED_LEN_AUTH, &(cookie_out), 1,1))
									CWLog("NL80211: Errore CW80211SendFrame");

							WTPSTAInfo * thisSTA = findSTABySA(WTPGlobalBSSList[BSSIndex], authResponse.DA);
							if(!CWStartAssociationRequestTimer(thisSTA, WTPGlobalBSSList[BSSIndex]))
									CWLog("[CW80211] Problem starting timer association request");
						}			
					}
					
					if(WLAN_FC_GET_STYPE(frameControl) == WLAN_FC_STYPE_ASSOC_RESP)
					{
						CWLog("Received from AC Association Response");
						
						struct CWFrameAssociationResponse assResponse;
						if(!CW80211ParseAssociationResponse(msgPtr.msg, &assResponse))
						{
							CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
							return NULL;
						}
						int radioIndex = 0, wlanIndex = 0, BSSIndex=0, trovato=0; 
						for(radioIndex=0; radioIndex<WTP_RADIO_MAX; radioIndex++)
						{
							for(wlanIndex=0; wlanIndex<WTP_MAX_INTERFACES; wlanIndex++)
							{
								BSSIndex=getBSSIndex(radioIndex, wlanIndex);
								if(
									WTPGlobalBSSList[BSSIndex] &&
									(WTPGlobalBSSList[BSSIndex]->interfaceInfo) &&
									(WTPGlobalBSSList[BSSIndex]->interfaceInfo->BSSID != NULL) && 
									(!strcmp(WTPGlobalBSSList[BSSIndex]->interfaceInfo->BSSID, assResponse.BSSID))
								)
								{
									trovato=1;
									break;
								}
							}
							
							if(trovato == 1)
								break;
						}
						//Ok o ricalcolo?
						int lenFrame = MGMT_FRAME_FIXED_LEN_ASSOCIATION+MGMT_FRAME_IE_FIXED_LEN+CW_80211_MAX_SUPP_RATES;
						if(trovato == 1)
							if(!CW80211SendFrame(WTPGlobalBSSList[BSSIndex], 0, CW_FALSE, msgPtr.msg, lenFrame, &(cookie_out), 1,1))
									CWLog("NL80211: Errore CW80211SendFrame");
					}
#else
					struct ieee80211_hdr *hdr;
                    u16 fc;
                    hdr = (struct ieee80211_hdr *) msgPtr.msg;
                    fc = le_to_host16(hdr->frame_control);
       
                   if( WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_DATA ){
						CWLog("Got 802.11 Data Packet (stype=%d) from AC(hostapd) len:%d",WLAN_FC_GET_STYPE(fc),msgPtr.offset);
						//CWWTPSendFrame(msgPtr.msg, msgPtr.offset);
                         
                   }
                   else{
                        CWLog("Control/Unknow Type type=%d",WLAN_FC_GET_TYPE(fc));
                    }
#endif
				}else{
					CWLog("Unknow Data Msg Type");
				}
				CW_FREE_PROTOCOL_MESSAGE(msgPtr);
		}
	}

CLEAR_DATA_RUN_STATE:
	
#ifdef CW_DTLS_DATA_CHANNEL
	gWTPSessionData = NULL;
#endif
	
	CWThreadMutexLock(&gInterfaceMutex);
	gWTPDataChannelDeadFlag=CW_TRUE;
	gWTPThreadDataPacketState = 2;
	CWThreadMutexUnlock(&gInterfaceMutex);
	
	CWLog("THREAD Data Management exit");
	
	return NULL;
}

/* 
 * Manage Run State.
 */

extern int gRawSock;
int wtpInRunState=0;

CWStateTransition CWWTPEnterRun() {

	int k, msg_len;
	int gWTPThreadDataPacketStateLocal=0;

	CWLog("\n");
	CWLog("######### WTP enters in RUN State #########");
	
	
	gWTPEchoRetransmissionCount=0;
	
	CWThread thread_manageDataPacket;
	if(!CWErr(CWCreateThread(&thread_manageDataPacket, 
				 CWWTPManageDataPacket,
				 (void*)gWTPDataSocket))) {
		
		CWLog("Error starting Thread that receive DTLS DATA packet");
		CWNetworkCloseSocket(gWTPDataSocket);
		//Elena Agostini - 07/2014
		goto CLEAR_RUN_STATE;
	}
	
	for (k = 0; k < MAX_PENDING_REQUEST_MSGS; k++)
		CWResetPendingMsgBox(gPendingRequestMsgs + k);

	if (!CWErr(CWStartEchoRequestTimer())) {
		goto CLEAR_RUN_STATE; //return CW_ENTER_RESET;
	}
	
	wtpInRunState=1;

	CW_REPEAT_FOREVER
	{
		CWBool bReceivePacket = CW_FALSE;
		CWBool bReveiveBinding = CW_FALSE;
		CWBool gWTPDataChannelLocalFlag = CW_FALSE;
		CWBool gWTPExitRunEchoLocal = CW_FALSE;
		
		/*
		 * Elena Agostini - 03/2014
		 * 
		 * If gWTPExitRunEcho == CW_TRUE, no Echo Response has been received
		 * so we consider peer dead and WTP goes in RESET
		 * 
		 * If gWTPDataChannelDeadFlag == CW_TRUE DataChannel is Dead
		 */
		
		CWThreadMutexLock(&gInterfaceMutex);
		gWTPDataChannelLocalFlag = gWTPDataChannelDeadFlag;
		gWTPExitRunEchoLocal=gWTPExitRunEcho;
		CWThreadMutexUnlock(&gInterfaceMutex);
			
		if(gWTPDataChannelLocalFlag == CW_TRUE)
		{
			CWLog("Data Channel is dead... restart Discovery State\n");
			break;
		}
		
		if(gWTPExitRunEchoLocal == CW_TRUE)
		{
			CWLog("Max Num Retransmit Echo Request reached. We consider peer dead..\n");
			break;
		}
			
		/* Wait packet */
		/*
		timenow.tv_sec = time(0) + CW_NEIGHBORDEAD_RESTART_DISCOVERY_DELTA_DEFAULT;	 // greater than NeighborDeadInterval
		timenow.tv_nsec = 0;
		*/
		/*
		 * if there are no frames from stations
		 * and no packets from AC...
		 */
		 
		CWThreadMutexLock(&gInterfaceMutex);
		/*
		if ((CWGetCountElementFromSafeList(gPacketReceiveList) == 0) && (CWGetCountElementFromSafeList(gFrameList) == 0)) {
			//...wait at most 4 mins for a frame or packet.
			 
			if (!CWErr(CWWaitThreadConditionTimeout(&gInterfaceWait, &gInterfaceMutex, &timenow))) {

				CWThreadMutexUnlock(&gInterfaceMutex);
			
				if (CWErrorGetLastErrorCode() == CW_ERROR_TIME_EXPIRED)	{

					CWLog("No Message from AC for a long time... restart Discovery State");
					break;
				}
				continue;
			}
		}*/
		
		bReceivePacket = ((CWGetCountElementFromSafeList(gPacketReceiveList) != 0) ? CW_TRUE : CW_FALSE);
		bReveiveBinding = ((CWGetCountElementFromSafeList(gFrameList) != 0) ? CW_TRUE : CW_FALSE);

		CWThreadMutexUnlock(&gInterfaceMutex);

		if (bReceivePacket) {

			CWProtocolMessage msg;

			msg_len = msg.offset;
			msg.msg = NULL;
			msg.offset = 0;

			if (!(CWReceiveMessage(&msg))) {

				CW_FREE_PROTOCOL_MESSAGE(msg);
				CWLog("Failure Receiving Response");
				break;
			}
			if (!CWErr(CWWTPManageGenericRunMessage(&msg))) {

				if(CWErrorGetLastErrorCode() == CW_ERROR_INVALID_FORMAT) {

					/* Log and ignore message */
					CWErrorHandleLast();
					CWLog("--> Received something different from a valid Run Message");
				} 
				else {
					CW_FREE_PROTOCOL_MESSAGE(msg);
					CWLog("--> Critical Error Managing Generic Run Message... we enter RESET State");
					//wtpInRunState=0;
					break;
					//return CW_ENTER_RESET;
				}
			}
		}
		if (bReveiveBinding)
			CWWTPCheckForBindingFrame();
	}

	/* Elena Agostini - 07/2014 */
	CLEAR_RUN_STATE:
	
	wtpInRunState=0;
	
	CWStopEchoRequestsTimer();
	CWStopKeepAliveTimer();
	CWStopDataChannelDeadTimer();

	/*
	 * Elena Agostini - 07/2014: waiting thread_manageDataPacket 
	 */
	CWThreadMutexLock(&gInterfaceMutex);

	if(gWTPThreadDataPacketState != 2)
		gWTPThreadDataPacketState=2;
	CWThreadMutexUnlock(&gInterfaceMutex);
	
	pthread_join(thread_manageDataPacket, NULL);
	
	CWLog("THREAD Manager Data Channel is dead");


#ifndef CW_NO_DTLS
	CWSecurityDestroyContext(gWTPSecurityContext);
	gWTPSecurityContext = NULL;
	gWTPSession = NULL;
#endif
		
	CWThreadMutexLock(&gInterfaceMutex);
	gWTPDataChannelDeadFlag = CW_FALSE;
	gWTPExitRunEcho = CW_FALSE;
	gWTPThreadDataPacketState=0;
	CWThreadMutexUnlock(&gInterfaceMutex);
		
	return CW_ENTER_RESET;
}

CWBool CWWTPManageGenericRunMessage(CWProtocolMessage *msgPtr) {

	CWControlHeaderValues controlVal;
	
	if(msgPtr == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	msgPtr->offset = 0;
	
	/* will be handled by the caller */
	if(!(CWParseControlHeader(msgPtr, &controlVal))) 
		return CW_FALSE;	

	int len = controlVal.msgElemsLen - CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;

	int pendingMsgIndex = 0;
	pendingMsgIndex = CWFindPendingRequestMsgsBox(gPendingRequestMsgs,
						      MAX_PENDING_REQUEST_MSGS,
						      controlVal.messageTypeValue,
						      controlVal.seqNum);

	/* we have received a new Request or an Echo Response */
	if (pendingMsgIndex < 0) {

		CWProtocolMessage *messages = NULL;
		int fragmentsNum=0;
		CWBool toSend=CW_FALSE;
	
		switch(controlVal.messageTypeValue) {

			case CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_REQUEST:
			{
				CWProtocolResultCode resultCode = CW_PROTOCOL_FAILURE;				
				CWProtocolConfigurationUpdateRequestValues values;
				int updateRequestType;

				/*Update 2009:
					check to see if a time-out on session occur...
					In case it happens it should go back to CW_ENTER_RESET*/
				if (!CWResetEchoRequestRetransmit()) {
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}

				CWLog("Configuration Update Request received");
				
				/************************************************************************************************
				 * Update 2009:																					*
				 *				These two function need an additional parameter (Pointer to updateRequestType)	*
				 *				for distinguish between all types of message elements.							*
				 ************************************************************************************************/

				if(!CWParseConfigurationUpdateRequest((msgPtr->msg)+(msgPtr->offset), len, &values, &updateRequestType))
					return CW_FALSE;

				if(!CWSaveConfigurationUpdateRequest(&values, &resultCode, &updateRequestType))
					return CW_FALSE;

				/*
				if ( updateRequestType == BINDING_MSG_ELEMENT_TYPE_OFDM_CONTROL )
					break; 
				*/
				
				/*Update 2009:
				 Added values (to return stuff with a conf update response)*/
				if(!CWAssembleConfigurationUpdateResponse(&messages,
														  &fragmentsNum,
														  gWTPPathMTU,
														  controlVal.seqNum,
														  resultCode,
														  values)) 
					return CW_FALSE;
				
				toSend=CW_TRUE;				

				 /*
                                 * BUG-ML01- memory leak fix
                                 *
                                 * 16/10/2009 - Donato Capitella
                                 */
				/*
                                CWProtocolVendorSpecificValues* psValues = values.protocolValues;
                                if (psValues->vendorPayloadType == CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI)
					CW_FREE_OBJECT(((CWVendorUciValues *)psValues->payload)->response);
                                CW_FREE_OBJECT(psValues->payload);
                                CW_FREE_OBJECT(values.protocolValues);
				*/
                                break;

				
				break;
			}

			case CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_REQUEST:
			{
				CWProtocolResultCode resultCode = CW_PROTOCOL_FAILURE;
				/*Update 2009:
					check to see if a time-out on session occur...
					In case it happens it should go back to CW_ENTER_RESET*/
				if (!CWResetEchoRequestRetransmit()) {
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}
				CWLog("Clear Configuration Request received");
				/*WTP RESET ITS CONFIGURAION TO MANUFACTURING DEFAULT}*/
				if(!CWSaveClearConfigurationRequest(&resultCode))
					return CW_FALSE;
				if(!CWAssembleClearConfigurationResponse(&messages, &fragmentsNum, gWTPPathMTU, controlVal.seqNum, resultCode)) 
					return CW_FALSE;

				toSend=CW_TRUE;
				break;
			}

			/*  
			 * Elena Agostini 10/2014: Configuration Request Parse
			 */
			case CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_REQUEST:
			{
				int BSSIndex, STAIndex;
				char * addressSta;
				CW_CREATE_ARRAY_CALLOC_ERR(addressSta, ETH_ALEN+1, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				
				CWProtocolResultCode resultCode = CW_PROTOCOL_SUCCESS;
				//CWProtocolStationConfigurationRequestValues values;  --> da implementare
				/*Update 2009:
					check to see if a time-out on session occur...
					In case it happens it should go back to CW_ENTER_RESET*/
				if (!CWResetEchoRequestRetransmit()) {
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}
				CWLog("# _______ Station Configuration Request received _______ #");
				int typeOp=-1;
				if(CWParseStationConfigurationRequest((msgPtr->msg)+(msgPtr->offset), len, &BSSIndex, &STAIndex, &typeOp))
				{
					if(typeOp == CW_MSG_ELEMENT_ADD_STATION_CW_TYPE)
					{
						CWLog("[CW80211] REQUEST Add Station");
						if(!CWWTPAddNewStation(BSSIndex, STAIndex))
							resultCode=CW_PROTOCOL_FAILURE;
					}
					
					if(typeOp == CW_MSG_ELEMENT_DELETE_STATION_CW_TYPE)
					{
						CWLog("[CW80211] REQUEST Delete Station");
						if(!CWWTPDelStation(WTPGlobalBSSList[BSSIndex], &(WTPGlobalBSSList[BSSIndex]->staList[STAIndex])))
							resultCode=CW_PROTOCOL_FAILURE;
					}
				}
				else
					resultCode=CW_PROTOCOL_FAILURE;
				
				if(!CWAssembleStationConfigurationResponse(&messages, &fragmentsNum, gWTPPathMTU, controlVal.seqNum, resultCode)) 
					return CW_FALSE;

				toSend=CW_TRUE;
				break;
			}
			/*
			 * Elena Agostini: 09/2014. IEEE WLAN Configuration Request
			 */
			case CW_MSG_TYPE_VALUE_WLAN_CONFIGURATION_REQUEST:
			{
				CWProtocolResultCode resultCode = CW_PROTOCOL_FAILURE;
				ACInterfaceRequestInfo interfaceACInfo;
				int radioIDsend, wlanIDsend;
				int radioIDindex, wlanIDindex;
				char * bssidAssigned=NULL;
				
				if (!CWResetEchoRequestRetransmit()) {
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}
				
				CWLog("");
				CWLog("# _______ WLAN Configuration Request received _______ #");
				
				if(!(CWParseIEEEConfigurationRequestMessage(msgPtr->msg, len+(msgPtr->offset), controlVal.seqNum, &(interfaceACInfo)))) 
				{
					if(CWErrorGetLastErrorCode() != CW_ERROR_INVALID_FORMAT) {
						CWLog("Failure Parsing Response");
						resultCode = CW_PROTOCOL_FAILURE_UNRECOGNIZED_MSG_ELEM;
						
						return CW_FALSE;
					}
					else {
						CWErrorHandleLast();
					}
					return CW_FALSE;
				}
				
				radioIDsend = interfaceACInfo.radioID;
				wlanIDsend = interfaceACInfo.wlanID;
				
				radioIDindex = CWIEEEBindingGetIndexFromDevID(interfaceACInfo.radioID);
				wlanIDindex = CWIEEEBindingGetIndexFromDevID(interfaceACInfo.wlanID);
				
				if((CWSaveIEEEConfigurationRequestMessage(&(interfaceACInfo)))) {
					resultCode = CW_PROTOCOL_SUCCESS;
					
					if(interfaceACInfo.operation == CW_OP_ADD_WLAN)
					{
						if(
							(wlanIDindex < WTP_MAX_INTERFACES) &&
							(radioIDindex < WTP_RADIO_MAX)
						)
						{
							CW_CREATE_ARRAY_CALLOC_ERR(bssidAssigned, ETH_ALEN+1, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
							CW_COPY_MEMORY(bssidAssigned, gRadiosInfo.radiosInfo[radioIDindex].gWTPPhyInfo.interfaces[wlanIDindex].BSSID, ETH_ALEN);
						}
					}
				}
				
				if(!(CWAssembleIEEEConfigurationResponse(&messages, &fragmentsNum, gWTPPathMTU, controlVal.seqNum,
														resultCode, radioIDsend, wlanIDsend, bssidAssigned)
					)) {
					return CW_FALSE;
				}
				
				toSend=CW_TRUE;
				break;
			}

			case CW_MSG_TYPE_VALUE_ECHO_RESPONSE:
			{
				/*Update 2009:
					check to see if a time-out on session occur...
					In case it happens it should go back to CW_ENTER_RESET*/
				if (!CWResetEchoRequestRetransmit()) {
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}
				CWLog("Echo Response received");
				break;
			}

			default:
				/* 
				 * We can't recognize the received Request so
				 * we have to send a corresponding response
				 * containing a failure result code
				 */
				CWLog("--> Not valid Request in Run State... we send a failure Response");
				/*Update 2009:
					check to see if a time-out on session occur...
					In case it happens it should go back to CW_ENTER_RESET*/
				if (!CWResetEchoRequestRetransmit()) {
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}
				if(!(CWAssembleUnrecognizedMessageResponse(&messages,
									   &fragmentsNum,
									   gWTPPathMTU,
									   controlVal.seqNum,
									   controlVal.messageTypeValue+1))) 
					return CW_FALSE;

				toSend = CW_TRUE;
				/* return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
				 * 		       "Received Message not valid in Run State");
				 */
		}
		if(toSend) {

			int i;
			for(i = 0; i < fragmentsNum; i++) {
#ifdef CW_NO_DTLS
				if(!CWNetworkSendUnsafeConnected(gWTPSocket,
								 messages[i].msg,
								 messages[i].offset)) 
#else
				if(!CWSecuritySend(gWTPSession,
						   messages[i].msg,
						   messages[i].offset))
#endif
				{
					CWLog("Error sending message");
					CWFreeMessageFragments(messages, fragmentsNum);
					CW_FREE_OBJECT(messages);
					return CW_FALSE;
				}
			}

			CWLog("Message Sent\n");
			CWFreeMessageFragments(messages, fragmentsNum);
			CW_FREE_OBJECT(messages);

			/*
			 * Check if we have to exit due to an update commit request.
			 */
			if (WTPExitOnUpdateCommit) {
			     exit(EXIT_SUCCESS);
			}
		}	
	} 
	else {/* we have received a Response */

		/*Update 2009:
		  		check to see if a time-out on session occur...
		 		 In case it happens it should go back to CW_ENTER_RESET*/
		if (!CWResetEchoRequestRetransmit())
			return CW_FALSE;

		switch(controlVal.messageTypeValue) 
		{
			case CW_MSG_TYPE_VALUE_CHANGE_STATE_EVENT_RESPONSE:
				CWLog("Change State Event Response received");
				break;
		
			case CW_MSG_TYPE_VALUE_WTP_EVENT_RESPONSE:
				CWLog("WTP Event Response received");	
				break;
	
			case CW_MSG_TYPE_VALUE_DATA_TRANSFER_RESPONSE:
				CWLog("Data Transfer Response received");
				break;

			default:
				/* 
				 * We can't recognize the received Response: we
				 * ignore the message and log the event.
				 */
				return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
						    "Received Message not valid in Run State");
		}
		CWResetPendingMsgBox(&(gPendingRequestMsgs[pendingMsgIndex]));
	}
	CW_FREE_PROTOCOL_MESSAGE(*msgPtr);
	return CW_TRUE;
}


/*______________________________________________________________*/
/*  *******************___TIMER HANDLERS___*******************  */
void CWWTPHeartBeatTimerExpiredHandler(void *arg) {

	CWList msgElemList = NULL;
	CWProtocolMessage *messages = NULL;
	int fragmentsNum = 0;
	int seqNum;

	if(!gNeighborDeadTimerSet) {
		if (!CWStartNeighborDeadTimer()) {
			CWStopHeartbeatTimer();
			CWStopNeighborDeadTimer();
			return;
		}
	}

	CWLog("WTP HeartBeat Timer Expired... we send an ECHO Request");

	CWLog("\n");
	CWLog("#________ Echo Request Message (Run) ________#");

	/* Send WTP Event Request */
	seqNum = CWGetSeqNum();

	if(!CWAssembleEchoRequest(&messages,
	&fragmentsNum,
	gWTPPathMTU,
	seqNum,
	msgElemList)){
		int i;

		CWDebugLog("Failure Assembling Echo Request");
		if(messages)
		for(i = 0; i < fragmentsNum; i++) {
			CW_FREE_PROTOCOL_MESSAGE(messages[i]);
		}	
		CW_FREE_OBJECT(messages);
		return;
	}

		int i;
		for(i = 0; i < fragmentsNum; i++) {
			#ifdef CW_NO_DTLS
			if(!CWNetworkSendUnsafeConnected(gWTPSocket, messages[i].msg, messages[i].offset)) {
			#else
			if(!CWSecuritySend(gWTPSession, messages[i].msg, messages[i].offset)){
				#endif
				CWLog("Failure sending Request");
				int k;
				for(k = 0; k < fragmentsNum; k++) {
					CW_FREE_PROTOCOL_MESSAGE(messages[k]);
				}	
				CW_FREE_OBJECT(messages);
				break;
			}
		}

		int k;
		for(k = 0; messages && k < fragmentsNum; k++) {
		CW_FREE_PROTOCOL_MESSAGE(messages[k]);
	}	
	CW_FREE_OBJECT(messages);

	if(!CWStartHeartbeatTimer()) {
		return;
	}
}

void CWWTPNeighborDeadTimerExpired(void *arg) {

CWLog("WTP NeighborDead Timer Expired... we consider Peer Dead.");

#ifdef DMALLOC
dmalloc_shutdown();
#endif

return;
}

/*
 * Elena Agostini 03/2014
 * 
 * Only Echo Retransmit Timer
 */
void CWWTPEchoRequestTimerExpiredHandler(void *arg) {

	CWList msgElemList = NULL;
	CWProtocolMessage *messages = NULL;
	int fragmentsNum = 0;
	int seqNum;
	CWBool gWTPDataChannelDeadFlagLocal = CW_FALSE;
	
	//Elena Agostini - 07/2014
	if(gEchoTimerSet == CW_FALSE)
		return;
		
	/*
	 * Check retransmission ECHO condition
	 */
	if(gWTPEchoRetransmissionCount >= gWTPMaxRetransmitEcho)
	{
		CWThreadMutexLock(&gInterfaceMutex);
		gWTPExitRunEcho=CW_TRUE;
		CWThreadMutexUnlock(&gInterfaceMutex);
		CWLog("Massimo numero di Echo Raggiunto");
		return;
	}
	
	/*
	 * Check Data Channel condition
	 */
	CWThreadMutexLock(&gInterfaceMutex);
	gWTPDataChannelDeadFlagLocal=gWTPDataChannelDeadFlag;
	CWThreadMutexUnlock(&gInterfaceMutex);
	if(gWTPDataChannelDeadFlagLocal == CW_TRUE) return;
	
	CWLog("WTP HeartBeat Timer Expired... we send an ECHO Request");
	CWLog("\n");
	CWLog("#________ Echo Request Message [%d] (Run) ________#", gWTPEchoRetransmissionCount);
	
	/* Send WTP Event Request */
	seqNum = CWGetSeqNum();

	if(!CWAssembleEchoRequest(&messages,
				  &fragmentsNum,
				  gWTPPathMTU,
				  seqNum,
				  msgElemList)){
		int i;

		CWDebugLog("Failure Assembling Echo Request");
		if(messages)
			for(i = 0; i < fragmentsNum; i++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[i]);
			}	
		CW_FREE_OBJECT(messages);
		return;
	}

	int i;
	for(i = 0; i < fragmentsNum; i++) {
#ifdef CW_NO_DTLS
		if(!CWNetworkSendUnsafeConnected(gWTPSocket, messages[i].msg, messages[i].offset)) {
#else
		if(!CWSecuritySend(gWTPSession, messages[i].msg, messages[i].offset)){
#endif
			CWLog("Failure sending Request");
			int k;
			for(k = 0; k < fragmentsNum; k++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[k]);
			}	
			CW_FREE_OBJECT(messages);
			break;
		}
	}

	gWTPEchoRetransmissionCount++;

	int k;
	for(k = 0; messages && k < fragmentsNum; k++) {
		CW_FREE_PROTOCOL_MESSAGE(messages[k]);
	}	
	CW_FREE_OBJECT(messages);
	
	if(!CWStartEchoRequestTimer()) {
		return;
	}
}

/*
 * Elena Agostini - 03/2014
 * 
 * DataChannel KeepAlive Timer
 */	 
void CWWTPKeepAliveDataTimerExpiredHandler(void *arg) {

	CWProtocolMessage *messages = NULL;
	CWProtocolMessage sessionIDmsgElem;
	int fragmentsNum = 0;
	CWBool gWTPDataChannelDeadFlagLocal=CW_FALSE;
	CWBool gWTPExitRunEchoLocal=CW_FALSE;
	
	/*
	 * Check Data Channel Condition && Control Channel Condition
	 */
	CWThreadMutexLock(&gInterfaceMutex);
	gWTPDataChannelDeadFlagLocal=gWTPDataChannelDeadFlag;
	gWTPExitRunEchoLocal=gWTPExitRunEcho;
	CWThreadMutexUnlock(&gInterfaceMutex);
	if(gWTPDataChannelDeadFlagLocal == CW_TRUE) return;
	if(gWTPExitRunEchoLocal == CW_TRUE) return;
	
	/*
	 * If not, set Dead Timer 
	 */
	if(!gDataChannelDeadTimerSet) {

		if (!CWStartDataChannelDeadTimer()) {
			CWStopDataChannelDeadTimer();
			return;
		}
	}
	
	CWAssembleMsgElemSessionID(&sessionIDmsgElem, &gWTPSessionID[0]);
	sessionIDmsgElem.data_msgType = CW_DATA_MSG_KEEP_ALIVE_TYPE;
	
	//Send WTP Event Request
	if (!CWAssembleDataMessage(&messages, 
			    &fragmentsNum, 
			    gWTPPathMTU, 
			    &sessionIDmsgElem, 
			    NULL,
			    CW_PACKET_PLAIN,
			    1
			    ))
	{
		int i;

		CWDebugLog("Failure Assembling KeepAlive Request");
		if(messages)
			for(i = 0; i < fragmentsNum; i++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[i]);
			}	
		CW_FREE_OBJECT(messages);
		return;
	}
	
	
	int i;
	for(i = 0; i < fragmentsNum; i++) {
		
	   /*
		* Elena Agostini - 03/2014
		* 
		* DTLS Data Session AC
		*/
		
#ifdef CW_DTLS_DATA_CHANNEL
				
				if(!(CWSecuritySend(gWTPSessionData, messages[i].msg, messages[i].offset))) {
#else
				if(!CWNetworkSendUnsafeConnected(gWTPDataSocket, messages[i].msg, messages[i].offset)) {
#endif
 		
			CWLog("Failure sending  KeepAlive Request");
			int k;
			for(k = 0; k < fragmentsNum; k++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[k]);
			}	
			CW_FREE_OBJECT(messages);
			break;
		}
	}

	int k;
	for(k = 0; messages && k < fragmentsNum; k++) {
		CW_FREE_PROTOCOL_MESSAGE(messages[k]);
	}	
	CW_FREE_OBJECT(messages);
	
	if(!CWStartKeepAliveTimer()) {
		return;
	}
	
}

/*
 * Elena Agostini - 03/2014
 *
 * DataChannel Dead Timer
 */
void CWWTPDataChannelDeadTimerExpired(void *arg) {

	CWLog("WTP DataChannel Timer Expired... we consider Peer Dead.");

	//Flag DataChannel Dead TRUE
	CWThreadMutexLock(&gInterfaceMutex);
	gWTPDataChannelDeadFlag=CW_TRUE;
	CWThreadMutexUnlock(&gInterfaceMutex);
				
#ifdef DMALLOC
	dmalloc_shutdown(); 
#endif

	return;
}



CWBool CWStartHeartbeatTimer() {
	
	gCWHeartBeatTimerID = timer_add(gEchoInterval,
					0,
					&CWWTPHeartBeatTimerExpiredHandler,
					NULL);
	
	if (gCWHeartBeatTimerID == -1)	return CW_FALSE;

	CWDebugLog("Echo Heartbeat Timer Started");

	return CW_TRUE;
}

CWBool CWStartNeighborDeadTimer() {

gCWNeighborDeadTimerID = timer_add(gCWNeighborDeadInterval,
0,
&CWWTPNeighborDeadTimerExpired,
NULL);

if (gCWNeighborDeadTimerID == -1)	return CW_FALSE;

CWDebugLog("NeighborDead Timer Started");
gNeighborDeadTimerSet = CW_TRUE;
return CW_TRUE;

}


CWBool CWStopNeighborDeadTimer() {

timer_rem(gCWNeighborDeadTimerID, NULL);
CWDebugLog("NeighborDead Timer Stopped");
gNeighborDeadTimerSet = CW_FALSE;
return CW_TRUE;
}


CWBool CWResetTimers() {

	if(gNeighborDeadTimerSet) {
		if (!CWStopNeighborDeadTimer()) return CW_FALSE;
	}

	if(!CWStopHeartbeatTimer())
	return CW_FALSE;

	if(!CWStartHeartbeatTimer())
	return CW_FALSE;

	return CW_TRUE;
}

CWBool CWStopHeartbeatTimer(){
	
 	timer_rem(gCWHeartBeatTimerID, NULL);
	CWDebugLog("Echo Heartbeat Timer Stopped");
	timer_rem(gCWKeepAliveTimerID, NULL);
	CWDebugLog("KeepAlive Heartbeat Timer Stopped");
	return CW_TRUE;
}

/*
 * Elena Agostini - 03/2014
 * 
 * Add Echo Request Retransmission
 */
CWBool CWStartEchoRequestTimer() {
	
	gCWEchoRequestTimerID = timer_add(gEchoInterval,
					0,
					&CWWTPEchoRequestTimerExpiredHandler,
					NULL);
	
	if (gCWEchoRequestTimerID == -1)	return CW_FALSE;

//	CWDebugLog("Echo Request Timer Started");
	gEchoTimerSet=CW_TRUE;

	return CW_TRUE;
}


CWBool CWStopEchoRequestsTimer(){
	
 	timer_rem(gCWEchoRequestTimerID, NULL);
 	gEchoTimerSet=CW_FALSE;
 	
//	CWDebugLog("Echo Heartbeat Timer Stopped");
	return CW_TRUE;
}

CWBool CWResetEchoRequestRetransmit() {
	/*
	 * If Echo Response received, Echo Retransmission Count = 0
	 */
	if(!CWStopEchoRequestsTimer()) return CW_FALSE;
	gWTPEchoRetransmissionCount=0;
	if(!CWStartEchoRequestTimer()) return CW_FALSE;

	return CW_TRUE;
}

/*
 * Elena Agostini - 03/2014
 * 
 * KeepAlive & DataChannel Dead Timer
 */

CWBool CWStartKeepAliveTimer() {
	gCWKeepAliveTimerID = timer_add(gDataChannelKeepAlive,
					0,
					&CWWTPKeepAliveDataTimerExpiredHandler,
					NULL);
	
	if (gCWKeepAliveTimerID == -1)	return CW_FALSE;

//	CWDebugLog("Keepalive Heartbeat Timer Started");
	
	return CW_TRUE;
}

CWBool CWStopKeepAliveTimer() {
	
	timer_rem(gCWKeepAliveTimerID, NULL);
//	CWDebugLog("KeepAlive Timer Stopped");
	return CW_TRUE;
}

CWBool CWStartDataChannelDeadTimer() {
	
	gCWDataChannelDeadTimerID = timer_add(gDataChannelDeadInterval,
					0,
					&CWWTPDataChannelDeadTimerExpired,
					NULL);
	
	if (gCWDataChannelDeadTimerID == -1)	return CW_FALSE;

	gDataChannelDeadTimerSet = CW_TRUE;
//	CWDebugLog("DataChannel Dead Timer Started");

	return CW_TRUE;
}

CWBool CWStopDataChannelDeadTimer() {
	
	timer_rem(gCWDataChannelDeadTimerID, NULL);
//	CWDebugLog("DataChannel Dead Timer Stopped");
	gDataChannelDeadTimerSet = CW_FALSE;
	return CW_TRUE;
}

CWBool CWResetDataChannelDeadTimer() {
	
	if(gDataChannelDeadTimerSet) {
		if (!CWStopDataChannelDeadTimer()) return CW_FALSE;
		if (!CWStartDataChannelDeadTimer()) return CW_FALSE;
	}
	return CW_TRUE;
}

/*__________________________________________________________________*/
/*  *******************___ASSEMBLE FUNCTIONS___*******************  */
CWBool CWAssembleEchoRequest (CWProtocolMessage **messagesPtr,
			      int *fragmentsNumPtr,
			      int PMTU,
			      int seqNum,
			      CWList msgElemList) {

	CWProtocolMessage *msgElems= NULL;
	const int msgElemCount = 0;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	
	if(messagesPtr == NULL || fragmentsNumPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
			
	if(!(CWAssembleMessage(messagesPtr,
			       fragmentsNumPtr,
			       PMTU,
			       seqNum,
			       CW_MSG_TYPE_VALUE_ECHO_REQUEST,
			       msgElems,
			       msgElemCount,
			       msgElemsBinding,
			       msgElemBindingCount,
#ifdef CW_NO_DTLSCWParseConfigurationUpdateRequest
			       CW_PACKET_PLAIN
#else			       
			       CW_PACKET_CRYPT
#endif
			       ))) 
		return CW_FALSE;
		
	return CW_TRUE;
}

CWBool CWAssembleWTPDataTransferRequest(CWProtocolMessage **messagesPtr, int *fragmentsNumPtr, int PMTU, int seqNum, CWList msgElemList)
{
	CWProtocolMessage *msgElems= NULL;
	int msgElemCount = 0;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	int i;
	CWListElement *current;
	int k = -1;

	if(messagesPtr == NULL || fragmentsNumPtr == NULL || msgElemList == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	msgElemCount = CWCountElementInList(msgElemList);

	if (msgElemCount > 0) {
		CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, msgElemCount, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	} 
	else msgElems = NULL;
		
	CWLog("Assembling WTP Data Transfer Request...");

	current=msgElemList;
	for (i=0; i<msgElemCount; i++)
	{
		switch (((CWMsgElemData *) current->data)->type)
		{
			case CW_MSG_ELEMENT_DATA_TRANSFER_DATA_CW_TYPE:
				if (!(CWAssembleMsgElemDataTransferData(&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
					goto cw_assemble_error;	
				break;
			/*case CW_MSG_ELEMENT_DATA_TRANSFER_MODE_CW_TYPE:
				if (!(CWAssembleMsgElemDataTansferMode(&(msgElems[++k]))))
					goto cw_assemble_error;
				break;*/
		
			default:
				goto cw_assemble_error;
				break;	
		}

		current = current->next;	
	}

	if (!(CWAssembleMessage(messagesPtr,
				fragmentsNumPtr,
				PMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_DATA_TRANSFER_REQUEST,
				msgElems,
				msgElemCount,
				msgElemsBinding,
				msgElemBindingCount,
#ifdef CW_NO_DTLS
				CW_PACKET_PLAIN
#else
				CW_PACKET_CRYPT
#endif
				)))
	 	return CW_FALSE;

	CWLog("WTP Data Transfer Request Assembled");
	
	return CW_TRUE;

cw_assemble_error:
	{
		int i;
		for(i = 0; i <= k; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE; // error will be handled by the caller
	}
}

//Elena Agostini - 11/2014: Delete Station Msg Elem
CWBool CWAssembleWTPEventRequest(CWProtocolMessage **messagesPtr,
				 int *fragmentsNumPtr,
				 int PMTU,
				 int seqNum,
				 CWList msgElemList,
				 CWMsgElemDataDeleteStation * infoDeleteStation) {

	CWProtocolMessage *msgElems= NULL;
	int msgElemCount = 0;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	int i;
	CWListElement *current;
	int k = -1;

	if(messagesPtr == NULL || fragmentsNumPtr == NULL || msgElemList == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
		
	msgElemCount = CWCountElementInList(msgElemList);

	if (msgElemCount > 0) {

		CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, 
						 msgElemCount,
						 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	} 
	else 
		msgElems = NULL;
		
	CWLog("Assembling WTP Event Request...");

	current=msgElemList;
	for (i=0; i<msgElemCount; i++) {

		switch (((CWMsgElemData *) current->data)->type) {

			case CW_MSG_ELEMENT_CW_DECRYPT_ER_REPORT_CW_TYPE:
				if (!(CWAssembleMsgElemDecryptErrorReport(&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
					goto cw_assemble_error;	
				break;
			case CW_MSG_ELEMENT_DUPLICATE_IPV4_ADDRESS_CW_TYPE:
				if (!(CWAssembleMsgElemDuplicateIPv4Address(&(msgElems[++k]))))
					goto cw_assemble_error;
				break;
			case CW_MSG_ELEMENT_DUPLICATE_IPV6_ADDRESS_CW_TYPE:
				if (!(CWAssembleMsgElemDuplicateIPv6Address(&(msgElems[++k]))))
					goto cw_assemble_error;
				break;
			case CW_MSG_ELEMENT_WTP_OPERAT_STATISTICS_CW_TYPE:
				if (!(CWAssembleMsgElemWTPOperationalStatistics(&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
					goto cw_assemble_error;
				break;
			case CW_MSG_ELEMENT_WTP_RADIO_STATISTICS_CW_TYPE:
				if (!(CWAssembleMsgElemWTPRadioStatistics(&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
					goto cw_assemble_error;
				break;
			case CW_MSG_ELEMENT_WTP_REBOOT_STATISTICS_CW_TYPE:
				if (!(CWAssembleMsgElemWTPRebootStatistics(&(msgElems[++k]))))
					goto cw_assemble_error;	
				break;
			case CW_MSG_ELEMENT_DELETE_STATION_CW_TYPE:
				if(infoDeleteStation == NULL)
					return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
					
				if (!(CWAssembleMsgElemWTPDeleteStation(&(msgElems[++k]), infoDeleteStation)))
					goto cw_assemble_error;	
				break;
			default:
				goto cw_assemble_error;
				break;	
		}
		current = current->next;	
	}

	if (!(CWAssembleMessage(messagesPtr,
				fragmentsNumPtr,
				PMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_WTP_EVENT_REQUEST,
				msgElems,
				msgElemCount,
				msgElemsBinding,
				msgElemBindingCount,
#ifdef CW_NO_DTLS
				CW_PACKET_PLAIN
#else
				CW_PACKET_CRYPT
#endif
				)))
	 	return CW_FALSE;

	CWLog("WTP Event Request Assembled");
	
	return CW_TRUE;

cw_assemble_error:
	{
		int i;
		for(i = 0; i <= k; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE; // error will be handled by the caller
	}
}

/*Update 2009:
	Added values to args... values is used to determine if we have some 
	payload (in this case only vendor and only UCI) to send back with the
	configuration update response*/
CWBool CWAssembleConfigurationUpdateResponse(CWProtocolMessage **messagesPtr,
					     int *fragmentsNumPtr,
					     int PMTU,
					     int seqNum,
					     CWProtocolResultCode resultCode,
						 CWProtocolConfigurationUpdateRequestValues values) {

	CWProtocolMessage *msgElems = NULL;
	const int msgElemCount = 1;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	CWProtocolVendorSpecificValues *protoValues = NULL;

	/*Get protocol data if we have it*/
	if (values.protocolValues) 
		protoValues = (CWProtocolVendorSpecificValues *) values.protocolValues;

	if(messagesPtr == NULL || fragmentsNumPtr == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWLog("Assembling Configuration Update Response...");
	
	CW_CREATE_OBJECT_ERR(msgElems, CWProtocolMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	if (protoValues)  {
		switch (protoValues->vendorPayloadType) {
			case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:
			case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:
					if (!(CWAssembleVendorMsgElemResultCodeWithPayload(msgElems,resultCode, protoValues))) {
						CW_FREE_OBJECT(msgElems);
						return CW_FALSE;
					}

			break;

			default:
				/*Result Code only*/
				if (!(CWAssembleMsgElemResultCode(msgElems,resultCode))) {
					CW_FREE_OBJECT(msgElems);
					return CW_FALSE;
				}
		}
	} else  {
		/*Result Code only*/
		if (!(CWAssembleMsgElemResultCode(msgElems,resultCode))) {
			CW_FREE_OBJECT(msgElems);
			return CW_FALSE;
		}
	}
		
	if(!(CWAssembleMessage(messagesPtr,
			       fragmentsNumPtr,
			       PMTU,
			       seqNum,
			       CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_RESPONSE,
			       msgElems,
			       msgElemCount,
			       msgElemsBinding,
			       msgElemBindingCount,
#ifdef CW_NO_DTLS
			       CW_PACKET_PLAIN
#else
			       CW_PACKET_CRYPT
#endif
			       ))) 
		return CW_FALSE;
	
	CWLog("Configuration Update Response Assembled");
	
	return CW_TRUE;
}

CWBool CWAssembleClearConfigurationResponse(CWProtocolMessage **messagesPtr, int *fragmentsNumPtr, int PMTU, int seqNum, CWProtocolResultCode resultCode) 
{
	CWProtocolMessage *msgElems= NULL;
	const int msgElemCount = 1;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	
	if(messagesPtr == NULL || fragmentsNumPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWLog("Assembling Clear Configuration Response...");
	
	CW_CREATE_OBJECT_ERR(msgElems, CWProtocolMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	if (!(CWAssembleMsgElemResultCode(msgElems,resultCode))) {
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE;
	}

	if(!(CWAssembleMessage(messagesPtr,
			       fragmentsNumPtr,
			       PMTU,
			       seqNum,
			       CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_RESPONSE,
			       msgElems,
			       msgElemCount,
			       msgElemsBinding,
			       msgElemBindingCount,
#ifdef CW_NO_DTLS
			       CW_PACKET_PLAIN
#else
			       CW_PACKET_CRYPT
#endif
			       ))) 
		return CW_FALSE;
	
	CWLog("Clear Configuration Response Assembled");
	
	return CW_TRUE;
}

CWBool CWAssembleStationConfigurationResponse(CWProtocolMessage **messagesPtr, int *fragmentsNumPtr, int PMTU, int seqNum, CWProtocolResultCode resultCode) 
{
	
	CWProtocolMessage *msgElems= NULL;
	const int msgElemCount = 1;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	
	if(messagesPtr == NULL || fragmentsNumPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWLog("Assembling Sattion Configuration Response...");
	
	CW_CREATE_OBJECT_ERR(msgElems, CWProtocolMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	if (!(CWAssembleMsgElemResultCode(msgElems,resultCode))) {
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE;
	}

	if(!(CWAssembleMessage(messagesPtr,
			       fragmentsNumPtr,
			       PMTU,
			       seqNum,
			       CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_RESPONSE,
			       msgElems,
			       msgElemCount,
			       msgElemsBinding,
			       msgElemBindingCount,
#ifdef CW_NO_DTLS
			       CW_PACKET_PLAIN
#else
			       CW_PACKET_CRYPT
#endif
			       ))) 
		return CW_FALSE;
	
	CWLog("Station Configuration Response Assembled");
	
	return CW_TRUE;
}


/*_______________________________________________________________*/
/*  *******************___PARSE FUNCTIONS___*******************  */
/*Update 2009:
	Function that parses vendor payload,
	filling in valuesPtr*/
CWBool CWParseVendorMessage(char *msg, int len, void **valuesPtr) {
	int i;
	CWProtocolMessage completeMsg;
	unsigned short int GlobalElemType=0;// = CWProtocolRetrieve32(&completeMsg);

	if(msg == NULL || valuesPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWLog("Parsing Vendor Specific Message...");
	
	completeMsg.msg = msg;
	completeMsg.offset = 0;

	CWProtocolVendorSpecificValues *vendPtr;
  

	// parse message elements
	while(completeMsg.offset < len) {
	  unsigned short int elemType=0;// = CWProtocolRetrieve32(&completeMsg);
	  unsigned short int elemLen=0;// = CWProtocolRetrieve16(&completeMsg);
		
		CWParseFormatMsgElem(&completeMsg,&elemType,&elemLen);		

		GlobalElemType = elemType;

		//CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);
		
		switch(elemType) {
			case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:
			  completeMsg.offset += elemLen;
			  break;
		default:
				if(elemType == CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE) 
				{
					CW_FREE_OBJECT(valuesPtr);
					return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
				}
				else 
				{
					completeMsg.offset += elemLen;
					break;
				}
		}
	}

	if(completeMsg.offset != len) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");


	switch(GlobalElemType) {
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:
			CW_CREATE_OBJECT_ERR(vendPtr, CWProtocolVendorSpecificValues, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
			/*Allocate various other vendor specific fields*/
		break;
	}

	i=0;
	completeMsg.offset = 0;
	while(completeMsg.offset < len) {
		unsigned short int type=0;
		unsigned short int elemLen=0;
		
		CWParseFormatMsgElem(&completeMsg,&type,&elemLen);		

		switch(type) {
			/*Once we know it is a vendor specific payload...*/
			case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:
				{
					if (!(CWParseVendorPayload(&completeMsg, elemLen, (CWProtocolVendorSpecificValues *) vendPtr)))
					{
						CW_FREE_OBJECT(vendPtr);
						return CW_FALSE; // will be handled by the caller
					}
				}
				break;
			default:
				completeMsg.offset += elemLen;
			break;
		}
	}
	
	*valuesPtr = (void *) vendPtr;
	CWLog("Vendor Message Parsed");
	
	return CW_TRUE;
}


CWBool CWParseConfigurationUpdateRequest (char *msg,
					  int len,
					  CWProtocolConfigurationUpdateRequestValues *valuesPtr, 
					  int *updateRequestType) {

	CWBool bindingMsgElemFound=CW_FALSE;
	CWBool vendorMsgElemFound=CW_FALSE;
	CWProtocolMessage completeMsg;
	unsigned short int GlobalElementType = 0;
	
	if(msg == NULL || valuesPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWLog("Parsing Configuration Update Request...");
	
	completeMsg.msg = msg;
	completeMsg.offset = 0;

	valuesPtr->bindingValues = NULL;
	/*Update 2009:
		added protocolValues (non-binding)*/
	valuesPtr->protocolValues = NULL;

	/* parse message elements */
	while(completeMsg.offset < len) {

		unsigned short int elemType=0;	/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int elemLen=0;	/* = CWProtocolRetrieve16(&completeMsg); */
		
		CWParseFormatMsgElem(&completeMsg,&elemType,&elemLen);		

		GlobalElementType = elemType;

//		CWLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);

		if(CWBindingCheckType(elemType)) {

			bindingMsgElemFound=CW_TRUE;
			completeMsg.offset += elemLen;
			continue;	
		}						
		switch(elemType) {
			/*Update 2009:
				Added case for vendor specific payload
				(Used mainly to parse UCI messages)...*/
			case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:
				vendorMsgElemFound=CW_TRUE;
				completeMsg.offset += elemLen;
				break;
			default:
				return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
		}
	}

	if (completeMsg.offset != len) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");

	/*Update 2009:
		deal with vendor specific messages*/
	if (vendorMsgElemFound) {
		/* For the knownledge of SaveConfiguration */
	  	*updateRequestType = GlobalElementType;

		if (!(CWParseVendorMessage(msg, len, &(valuesPtr->protocolValues))))
			return CW_FALSE;
	}
	
	if (bindingMsgElemFound) {
	  /* For the knownledge of SaveConfiguration */
	  *updateRequestType = GlobalElementType;

		if (!(CWBindingParseConfigurationUpdateRequest(msg, len, &(valuesPtr->bindingValues))))
			return CW_FALSE;
	}

	CWLog("Configure Update Request Parsed");
	
	return CW_TRUE;
}



CWBool CWParseStationConfigurationRequest(char *msg, int len, int * BSSIndex, int * STAIndex, int * typeOp) 
{
	int radioID, wlanID, supportedRatesLen;
	unsigned char * address;
	short int assID, capability;
	char flags;
	unsigned char * supportedRates;
	
	//CWBool bindingMsgElemFound=CW_FALSE;
	CWProtocolMessage completeMsg;
	
	if(msg == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWLog("Parsing Station Configuration Request...");
	
	completeMsg.msg = msg;
	completeMsg.offset = 0;

	//valuesPtr->bindingValues = NULL;

	// parse message elements
	while(completeMsg.offset < len) {
		unsigned short int elemType = 0;
		unsigned short int elemLen = 0;
		
		CWParseFormatMsgElem(&completeMsg,&elemType,&elemLen);		

		//CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);

		/*if(CWBindingCheckType(elemType))
		{
			bindingMsgElemFound=CW_TRUE;
			completeMsg.offset += elemLen;
			continue;	
		}*/
							
		switch(elemType) {
			case CW_MSG_ELEMENT_ADD_STATION_CW_TYPE:
				*(typeOp) = CW_MSG_ELEMENT_ADD_STATION_CW_TYPE;
				if (!(CWParseAddStation(&completeMsg,  elemLen, &(radioID), &(address))))
					return CW_FALSE;
				break;
			case CW_MSG_ELEMENT_IEEE80211_STATION:
				if (!(CWParse80211Station(&completeMsg,  elemLen, &(radioID), &(assID), &(flags), &(address), &(capability), &(wlanID),  &(supportedRatesLen), &(supportedRates))))
					return CW_FALSE;
				break;
				
			case CW_MSG_ELEMENT_DELETE_STATION_CW_TYPE:
				*(typeOp) = CW_MSG_ELEMENT_DELETE_STATION_CW_TYPE;
				if (!(CWParseDeleteStation(&completeMsg,  elemLen, &(radioID), &(address))))
					return CW_FALSE;
				break;
			default:
				return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
		}
	}
	
	if(completeMsg.offset != len) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");
	/*
	if(bindingMsgElemFound)
		if(!(CWBindingParseConfigurationUpdateRequest (msg, len, &(valuesPtr->bindingValues))))
			return CW_FALSE;
	*/
	
	//Add function for delete station
	
	//Ricavo indici di BSS e STA
	int radioIndex = radioID; //CWIEEEBindingGetIndexFromDevID(radioID);
	if(radioIndex < 0)
		return CW_FALSE;
		
	int wlanIndex = wlanID; //CWIEEEBindingGetIndexFromDevID(wlanID);
	if(wlanIndex < 0)
		return CW_FALSE;
	
	int trovato=0;
	(*BSSIndex) = getBSSIndex(radioIndex, wlanIndex);
	
	CWPrintEthernetAddress(address, "Searching for STA");
	
	for((*STAIndex)=0; (*STAIndex) < WTP_MAX_STA; (*STAIndex)++)
	{
		if(
			(WTPGlobalBSSList[(*BSSIndex)] != NULL) &&
			(WTPGlobalBSSList[(*BSSIndex)]->staList[(*STAIndex)].address != NULL) && 
			CWCompareEthernetAddress(WTPGlobalBSSList[(*BSSIndex)]->staList[(*STAIndex)].address, address) == 0
		)
		{
			trovato=1;
			break;
		}
	}
	
	if(trovato == 0)
		return CW_FALSE;

#ifdef SPLIT_MAC
	/*
	 * In caso di split mac riassegno alla STA i valori che l'AC mi invia.
	 * In caso di Local MAC per ora  non faccio nulla, i valori li ha gia decisi in precedenza il WTP
	 */
	if(*(typeOp) == CW_MSG_ELEMENT_ADD_STATION_CW_TYPE)
	{
		WTPGlobalBSSList[(*BSSIndex)]->staList[(*STAIndex)].staAID=assID;
		WTPGlobalBSSList[(*BSSIndex)]->staList[(*STAIndex)].flags=flags;
		WTPGlobalBSSList[(*BSSIndex)]->staList[(*STAIndex)].capabilityBit=capability;
		WTPGlobalBSSList[(*BSSIndex)]->staList[(*STAIndex)].lenSupportedRates=supportedRatesLen;
		 
		CW_CREATE_ARRAY_CALLOC_ERR(WTPGlobalBSSList[(*BSSIndex)]->staList[(*STAIndex)].supportedRates, supportedRatesLen+1, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return CW_FALSE;});
		CW_COPY_MEMORY(WTPGlobalBSSList[(*BSSIndex)]->staList[(*STAIndex)].supportedRates, supportedRates, supportedRatesLen);
		
		CW_CREATE_ARRAY_CALLOC_ERR(WTPGlobalBSSList[(*BSSIndex)]->staList[(*STAIndex)].phyMbpsSet, supportedRatesLen+1, float, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return CW_FALSE;});
		//not working? mbps is always 0
		int indexRates=0;
		for(indexRates=0; indexRates <= supportedRatesLen; indexRates++)
		{
			WTPGlobalBSSList[(*BSSIndex)]->staList[(*STAIndex)].phyMbpsSet[indexRates] = mapSupportedRatesValues(WTPGlobalBSSList[(*BSSIndex)]->staList[(*STAIndex)].supportedRates[indexRates], CW_80211_SUPP_RATES_CONVERT_FRAME_TO_VALUE);
		}
	}
#endif
	
	CWLog("Station Configuration Request Parsed");
	
	return CW_TRUE;
}

CWBool CWParseWTPEventResponseMessage (char *msg, int len, int seqNum, void *values) {

	CWControlHeaderValues controlVal;
	CWProtocolMessage completeMsg;
	
	if(msg == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWLog("Parsing WTP Event Response...");
	
	completeMsg.msg = msg;
	completeMsg.offset = 0;
	
	/* error will be handled by the caller */
	if(!(CWParseControlHeader(&completeMsg, &controlVal))) return CW_FALSE;
	
	/* different type */
	if(controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_WTP_EVENT_RESPONSE)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, 
				    "Message is not WTP Event Response as Expected");
	
	if(controlVal.seqNum != seqNum) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, 
				    "Different Sequence Number");
	
	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;
	
	if(controlVal.msgElemsLen != 0 ) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, 
				    "WTP Event Response must carry no message element");

	CWLog("WTP Event Response Parsed...");

	return CW_TRUE;
}


/*______________________________________________________________*/
/*  *******************___SAVE FUNCTIONS___*******************  */
CWBool CWSaveWTPEventResponseMessage (void *WTPEventResp) {

	CWDebugLog("Saving WTP Event Response...");
	CWDebugLog("WTP Response Saved");
	return CW_TRUE;
}

/*Update 2009:
	Save a vendor message (mainly UCI configuration messages)*/
CWBool CWSaveVendorMessage(void* protocolValuesPtr, CWProtocolResultCode* resultCode) {
	if(protocolValuesPtr==NULL) {return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);}
	*resultCode = CW_PROTOCOL_SUCCESS;

	CWProtocolVendorSpecificValues* vendorPtr=(CWProtocolVendorSpecificValues *)protocolValuesPtr; 

	/*Find out which custom vendor paylod really is...*/
	switch(vendorPtr->vendorPayloadType) {
		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI:
			if(!CWWTPSaveUCIValues((CWVendorUciValues *)(vendorPtr->payload), resultCode))
			{
				CW_FREE_OBJECT(((CWVendorUciValues *)vendorPtr->payload)->commandArgs);
				CW_FREE_OBJECT(vendorPtr->payload);
				CW_FREE_OBJECT(vendorPtr);
				return CW_FALSE;
			}
		break;

		case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM:
			if(!CWWTPSaveWUMValues((CWVendorWumValues *)(vendorPtr->payload), resultCode))
			{
				CW_FREE_OBJECT(vendorPtr->payload);
				CW_FREE_OBJECT(vendorPtr);
				return CW_FALSE;
			}
		break;
	}

	return CW_TRUE;
}

CWBool CWSaveConfigurationUpdateRequest(CWProtocolConfigurationUpdateRequestValues *valuesPtr,
										CWProtocolResultCode* resultCode,
										int *updateRequestType) {

	*resultCode=CW_TRUE;

	if(valuesPtr==NULL) {return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);}

	if (valuesPtr->bindingValues!=NULL) {

	  if(!CWBindingSaveConfigurationUpdateRequest(valuesPtr->bindingValues, resultCode, updateRequestType)) 
			return CW_FALSE;
	} 
	if (valuesPtr->protocolValues!=NULL) {
		/*Update 2009:
			We have a msg which is not a 
			binding specific message... */
	  if(!CWSaveVendorMessage(valuesPtr->protocolValues, resultCode)) 
			return CW_FALSE;
	}
	return CW_TRUE;
}

CWBool CWSaveClearConfigurationRequest(CWProtocolResultCode* resultCode)
{
	*resultCode=CW_TRUE;
	
	/*Back to manufacturing default configuration*/

	if ( !CWErr(CWWTPLoadConfiguration()) || !CWErr(CWWTPInitConfiguration()) ) 
	{
			CWLog("Can't restore default configuration...");
			return CW_FALSE;
	}

	*resultCode=CW_TRUE;
	return CW_TRUE;
}

/*
CWBool CWWTPManageACRunRequest(char *msg, int len)
{
	CWControlHeaderValues controlVal;
	CWProtocolMessage completeMsg;
	
	if(msg == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	completeMsg.msg = msg;
	completeMsg.offset = 0;
	
	if(!(CWParseControlHeader(&completeMsg, &controlVal))) return CW_FALSE; // error will be handled by the caller
	
	switch(controlVal.messageTypeValue) {
		case CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_REQUEST:
			break;
		case CW_MSG_TYPE_VALUE_ECHO_REQUEST:
			break;
		case CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_REQUEST:
			break;
		case CW_MSG_TYPE_VALUE_STATION_CONFIGURATION_REQUEST:
			break;
		default:
			return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Change State Event Response as Expected");
	}

	
	
	//if(controlVal.seqNum != seqNum) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Different Sequence Number");
	
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS; // skip timestamp
	
	if(controlVal.msgElemsLen != 0 ) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Change State Event Response must carry no message elements");

	CWDebugLog("Change State Event Response Parsed");




	CWDebugLog("#########################");
	CWDebugLog("###### STO DENTRO #######");
	CWDebugLog("#########################");

	return CW_TRUE;
}
*/

void CWConfirmRunStateToACWithEchoRequest() {

	CWList msgElemList = NULL;
	CWProtocolMessage *messages = NULL;
	int fragmentsNum = 0;
	int seqNum;

	CWLog("\n");
	CWLog("#________ Echo Request Message (Confirm Run) ________#");
	
	/* Send WTP Event Request */
	seqNum = CWGetSeqNum();

	if(!CWAssembleEchoRequest(&messages,
				  &fragmentsNum,
				  gWTPPathMTU,
				  seqNum,
				  msgElemList)){
		int i;

		CWDebugLog("Failure Assembling Echo Request");
		if(messages)
			for(i = 0; i < fragmentsNum; i++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[i]);
			}	
		CW_FREE_OBJECT(messages);
		return;
	}
	
	int i;
	for(i = 0; i < fragmentsNum; i++) {
#ifdef CW_NO_DTLS
		if(!CWNetworkSendUnsafeConnected(gWTPSocket, messages[i].msg, messages[i].offset)) {
#else
		if(!CWSecuritySend(gWTPSession, messages[i].msg, messages[i].offset)){
#endif
			CWLog("Failure sending Request");
			int k;
			for(k = 0; k < fragmentsNum; k++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[k]);
			}	
			CW_FREE_OBJECT(messages);
			break;
		}
	}

	int k;
	for(k = 0; messages && k < fragmentsNum; k++) {
		CW_FREE_PROTOCOL_MESSAGE(messages[k]);
	}	
	CW_FREE_OBJECT(messages);

}
