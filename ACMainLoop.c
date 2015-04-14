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
 * MA  02111-1307, USA.					
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
 **																								*
 * -------------------------------------------------------------------------------------------- *
 * Project:  Capwap																				*
 *																								*
 * Authors : Ludovico Rossi (ludo@bluepixysw.com)												*  
 *           Del Moro Andrea (andrea_delmoro@libero.it)											*
 *           Giovannini Federica (giovannini.federica@gmail.com)								*
 *           Massimo Vellucci (m.vellucci@unicampus.it)											*
 *           Mauro Bisson (mauro.bis@gmail.com)													*
 *           Daniele De Sanctis (danieledesanctis@gmail.com)									* 
 *	         Antonio Davoli (antonio.davoli@gmail.com)											*
 ************************************************************************************************/

#include "CWAC.h"
#include "CWStevens.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

/* index of the current thread in the global array */
CWThreadSpecific gIndexSpecific;

int gCWWaitJoin = CW_WAIT_JOIN_DEFAULT;

CW_THREAD_RETURN_TYPE CWManageWTP(void *arg);
CW_THREAD_RETURN_TYPE CWManageTimers(void *arg);
void CWCriticalTimerExpiredHandler(int arg);
void CWSoftTimerExpiredHandler(int arg);

void CWACManageIncomingPacket(CWSocket sock,
			      char *buf,
			      int len,
			      int incomingInterfaceIndex,
			      CWNetworkLev4Address *addrPtr,
			      CWBool dataFlag );
void _CWCloseThread(int i);
void CWResetWTPProtocolManager(CWWTPProtocolManager *WTPProtocolManager);
__inline__ CWWTPManager *CWWTPByName(const char *addr);
__inline__ CWWTPManager *CWWTPByAddress(CWNetworkLev4Address *addressPtr,
					CWSocket sock, CWBool dataFlag, char * sessionID);
__inline__ genericHandshakeThreadPtr CWWTPThreadGenericByAddress(CWNetworkLev4Address *addressPtr);
void CWACSetNewGenericHandshakeDataThread(genericHandshakeThreadPtr * genericThreadStruct, CWNetworkLev4Address * addrPtr, CWSocket sock, char * pData, int readBytes);

void CWACSetNewGenericHandshakeDataThread(genericHandshakeThreadPtr * genericThreadStruct, CWNetworkLev4Address * addrPtr, CWSocket sock, char * pData, int readBytes) {
	/* Se nessuno sta gestendo l'handshake creo un nuovo thread generico */
	
	CW_CREATE_OBJECT_ERR((*genericThreadStruct), genericHandshakeThread, return NULL; );
	
	if(addrPtr == NULL) return;

	struct sockaddr_in *tmpAdd = (struct sockaddr_in *) addrPtr;
	CWLog("[DTLS] New generic thread for WTP %s:%d", inet_ntoa(tmpAdd->sin_addr), ntohs(tmpAdd->sin_port));
	
	CW_COPY_NET_ADDR_PTR(&((*genericThreadStruct)->addressWTPPtr), addrPtr);
					
	if (!CWErr(CWCreateSafeList(&((*genericThreadStruct)->packetDataList)))) {
		exit(-1);
	}
	
	CWCreateThreadMutex(&((*genericThreadStruct)->interfaceMutex));
	CWCreateThreadCondition(&((*genericThreadStruct)->interfaceWait));
	CWSetMutexSafeList((*genericThreadStruct)->packetDataList, &((*genericThreadStruct)->interfaceMutex));
	CWSetConditionSafeList((*genericThreadStruct)->packetDataList, &((*genericThreadStruct)->interfaceWait));
	
	//Aggiunta ClientHello				
	CWLockSafeList((*genericThreadStruct)->packetDataList);
	CWAddElementToSafeListTailwitDataFlag((*genericThreadStruct)->packetDataList, pData, readBytes, 1);
	CWUnlockSafeList((*genericThreadStruct)->packetDataList);
	(*genericThreadStruct)->dataSock = sock;
	(*genericThreadStruct)->next = NULL;
	
	//return genericThreadStruct;
}

void CWACEnterMainLoop() {

	struct sigaction act;
	
	CWLog("AC enters in the MAIN_LOOP");
	
	/* set signals
	 * all the thread we spawn will inherit these settings
	 */

        /*
         * BUG UMR03
         *
         * 20/10/2009 - Donato Capitella 
         */
        sigemptyset(&act.sa_mask);

	act.sa_flags = 0;
	/* called when a timer requested by the thread has expired */
	act.sa_handler = CWCriticalTimerExpiredHandler;
	sigaction(CW_CRITICAL_TIMER_EXPIRED_SIGNAL, &act, NULL);
	
	act.sa_flags = 0;
	/* called when a timer requested by the thread has expired */
	act.sa_handler = CWSoftTimerExpiredHandler;
	sigaction(CW_SOFT_TIMER_EXPIRED_SIGNAL, &act, NULL);
	
	/* signals will be unblocked by the threads that needs timers */
	CWThreadSetSignals(SIG_BLOCK, 2, CW_CRITICAL_TIMER_EXPIRED_SIGNAL,
 					 CW_SOFT_TIMER_EXPIRED_SIGNAL);

	if(!(CWThreadCreateSpecific(&gIndexSpecific, NULL))) {
		CWLog("Critical Error With Thread Data");
		exit(1);
	}
	
	CWThread thread_interface;
	if(!CWErr(CWCreateThread(&thread_interface, CWInterface, NULL))) {
		CWLog("Error starting Interface Thread");
		exit(1);
	}

	CW_REPEAT_FOREVER {
		/* CWACManageIncomingPacket will be called 
		 * when a new packet is ready to be read 
		 */
		if(!CWErr(CWNetworkUnsafeMultiHomed(&gACSocket, 
						    CWACManageIncomingPacket,
						    CW_FALSE)))
			exit(1);
	}
}

/* argument passed to the thread func */
typedef struct {
	int index;
	CWSocket sock;
	int interfaceIndex;
} CWACThreadArg;

/*
 * This callback function is called when there is something to read in a 
 * CWMultiHomedSocket (see ACMultiHomed.c).
 * 
 * Params: sock,	is the socket that can receive the packet and it can be
 * 			used to reply.
 * 	   buf,		(array of len chars) contains the packet which is ready
 * 	   		on the socket's queue (obtained with MSG_PEEK).
 *	   incomingInterfaceIndex,  is the index (different from the system 
 *	   			    index, see ACMultiHomed.c) of the interface
 *	   			    the packet was sent to, in the array returned
 *	   			    by CWNetworkGetInterfaceAddresses. If the
 *	   			    packet was sent to a broadcast/multicast address,
 *	   			    incomingInterfaceIndex is -1.
 */
void CWACManageIncomingPacket(CWSocket sock,
			      char *buf,
			      int readBytes,
			      int incomingInterfaceIndex,
			      CWNetworkLev4Address *addrPtr,CWBool dataFlag) {
 
	CWWTPManager *wtpPtr = NULL;
	genericHandshakeThreadPtr tmpGenericThreadList, wtpGenericPtr;
	char* pData;
	CWBool dataFlagTmp;
	CWProtocolMessage msgDataChannel;
	char *valSessionIDPtr=NULL;
	int KeepAliveLenght=0, elemType, elemLen;
	CWSecuritySession sessionDataGeneric;
	int pathMTU, indexTmpThread=0;
/*
 * Elena Agostini - 04/2014: generic handshake datachannel WTP
 */
#ifdef CW_DTLS_DATA_CHANNEL
		if( ((buf[0] & 0x0f) == CW_PACKET_CRYPT) && (dataFlag == CW_TRUE) )
		{
			CW_CREATE_OBJECT_SIZE_ERR(pData, readBytes, { CWLog("Out Of Memory"); return; });
			memcpy(pData, buf, readBytes);
					
			/* Controllo se qualche thread WTP sta gia gestendo questo canale dati */
			//CWLog("+++ Check WTP thread dedicato");
			wtpPtr = CWWTPByAddress(addrPtr, sock, dataFlag, NULL);
			if(wtpPtr == NULL)
			{
				//CWLog("+++ Check WTP thread generico");
				/* Controllo se qualche thread generico sta gia gestendo questo canale dati */
				wtpGenericPtr = CWWTPThreadGenericByAddress(addrPtr);
				if(wtpGenericPtr == NULL)
				{
					CWThreadMutexLock(&gWTPsMutex);
					for(indexTmpThread=0; indexTmpThread < WTP_MAX_TMP_THREAD_DTLS_DATA; indexTmpThread++)
					{
						if(listGenericThreadDTLSData[indexTmpThread] == NULL)
						{
							CW_CREATE_OBJECT_ERR(listGenericThreadDTLSData[indexTmpThread], genericHandshakeThread, return NULL; );

							struct sockaddr_in *tmpAdd = (struct sockaddr_in *) addrPtr;
							CWLog("[DTLS] New generic thread for WTP %s:%d", inet_ntoa(tmpAdd->sin_addr), ntohs(tmpAdd->sin_port));
							
							CW_COPY_NET_ADDR_PTR(&(listGenericThreadDTLSData[indexTmpThread]->addressWTPPtr), addrPtr);
											
							if (!CWErr(CWCreateSafeList(&(listGenericThreadDTLSData[indexTmpThread]->packetDataList)))) {
								exit(-1);
							}
							
							CWCreateThreadMutex(&(listGenericThreadDTLSData[indexTmpThread]->interfaceMutex));
							CWCreateThreadCondition(&(listGenericThreadDTLSData[indexTmpThread]->interfaceWait));
							CWSetMutexSafeList(listGenericThreadDTLSData[indexTmpThread]->packetDataList, &(listGenericThreadDTLSData[indexTmpThread]->interfaceMutex));
							CWSetConditionSafeList(listGenericThreadDTLSData[indexTmpThread]->packetDataList, &(listGenericThreadDTLSData[indexTmpThread]->interfaceWait));
							
							//Aggiunta ClientHello				
							CWLockSafeList(listGenericThreadDTLSData[indexTmpThread]->packetDataList);
							CWAddElementToSafeListTailwitDataFlag(listGenericThreadDTLSData[indexTmpThread]->packetDataList, pData, readBytes, 1);
							CWUnlockSafeList(listGenericThreadDTLSData[indexTmpThread]->packetDataList);
							
							listGenericThreadDTLSData[indexTmpThread]->dataSock = sock;
							listGenericThreadDTLSData[indexTmpThread]->next = NULL;
							
							if(!CWErr(CWCreateThread(&(listGenericThreadDTLSData[indexTmpThread]->thread_GenericDataChannelHandshake), CWGenericWTPDataHandshake, listGenericThreadDTLSData[indexTmpThread]))) {
								CWLog("Error starting Thread that manage generich handshake with WTP");
								exit(1);
							}
							
							//CWACSetNewGenericHandshakeDataThread(&(startGenericThreadList), addrPtr, sock, pData, readBytes);
							break;
						}
					}
					CWThreadMutexUnlock(&gWTPsMutex);
					return;
				}
				else
				{
					CWLockSafeList(wtpGenericPtr->packetDataList);
					CWAddElementToSafeListTailwitDataFlag(wtpGenericPtr->packetDataList, pData, readBytes, 1);
					CWUnlockSafeList(wtpGenericPtr->packetDataList);
					return;
				}
			}
			else
			{
				/* check if sender address is known */
				if ((wtpPtr != NULL) && dataFlag && (wtpPtr->dataaddress.ss_family == AF_UNSPEC)) {
					CW_COPY_NET_ADDR_PTR(&(wtpPtr->dataaddress), addrPtr);
				}
			}
		}
		else
		{
			/* Elena Agostini - 04/2014: more WTPs with same IPs, different PORTs */
			if(dataFlag == CW_TRUE)
			{	
					CWProtocolMessage msg;
					CWProtocolTransportHeaderValues values;
					
					msgDataChannel.msg = buf;
					msgDataChannel.offset = 0;
					
					if(!CWParseTransportHeader(&msgDataChannel, &values, &dataFlag, NULL)){
						CWDebugLog("CWParseTransportHeader failed");
						return CW_FALSE;
					}
					
					if(msgDataChannel.data_msgType == CW_DATA_MSG_KEEP_ALIVE_TYPE) {
						CWParseFormatMsgElem(&msgDataChannel, &elemType, &elemLen);
						valSessionIDPtr = CWParseSessionID(&msgDataChannel, 16);
						wtpPtr = CWWTPByAddress(addrPtr, sock, dataFlag, valSessionIDPtr);
					}
					else {
						wtpPtr = CWWTPByAddress(addrPtr, sock, dataFlag, NULL);
					}
			}
			else
				wtpPtr = CWWTPByAddress(addrPtr, sock, dataFlag, NULL);
		}
		
#else		
	/* Elena Agostini - 04/2014: more WTPs with same IPs, different PORTs */
	if(dataFlag == CW_TRUE)
	{	
			CWProtocolMessage msg;
			CWProtocolTransportHeaderValues values;
			
			msgDataChannel.msg = buf;
			msgDataChannel.offset = 0;
			
			if(!CWParseTransportHeader(&msgDataChannel, &values, &dataFlag, NULL)){
				CWDebugLog("CWParseTransportHeader failed");
				return CW_FALSE;
			}
			
			if(msgDataChannel.data_msgType == CW_DATA_MSG_KEEP_ALIVE_TYPE) {
				CWParseFormatMsgElem(&msgDataChannel, &elemType, &elemLen);
				valSessionIDPtr = CWParseSessionID(&msgDataChannel, 16);
				wtpPtr = CWWTPByAddress(addrPtr, sock, dataFlag, valSessionIDPtr);
			}
			else {
				wtpPtr = CWWTPByAddress(addrPtr, sock, dataFlag, NULL);
			}	
	}
	else
		wtpPtr = CWWTPByAddress(addrPtr, sock, dataFlag, NULL);
	
	/* check if sender address is known */
	if ((wtpPtr != NULL) && dataFlag && (wtpPtr->dataaddress.ss_family == AF_UNSPEC)) {
		CW_COPY_NET_ADDR_PTR(&(wtpPtr->dataaddress), addrPtr);
	}
#endif

	if(wtpPtr != NULL) {
		/* known WTP */
		/* Clone data packet */
		CW_CREATE_OBJECT_SIZE_ERR(pData, readBytes, { CWLog("Out Of Memory"); return; });
		memcpy(pData, buf, readBytes);
		
		/*
		 * Elena Agostini - 03/2014
		 * DTLS Data Packet List
		 */
#ifdef CW_DTLS_DATA_CHANNEL
		if(dataFlag)
		{
			CWLockSafeList(wtpPtr->packetReceiveDataList);
			CWAddElementToSafeListTailwitDataFlag(wtpPtr->packetReceiveDataList, pData, readBytes,dataFlag);
			CWUnlockSafeList(wtpPtr->packetReceiveDataList);
		}
		else
		{
			CWLockSafeList(wtpPtr->packetReceiveList);
			CWAddElementToSafeListTailwitDataFlag(wtpPtr->packetReceiveList, pData, readBytes,dataFlag);
			CWUnlockSafeList(wtpPtr->packetReceiveList);
		}
#else
		CWLockSafeList(wtpPtr->packetReceiveList);
		CWAddElementToSafeListTailwitDataFlag(wtpPtr->packetReceiveList, pData, readBytes,dataFlag);
		CWUnlockSafeList(wtpPtr->packetReceiveList);	
#endif
		
	} else { 
		/* unknown WTP */
		int seqNum, tmp;
			
		CWDiscoveryRequestValues values;
		
		if(!CWErr(CWThreadMutexLock(&gActiveWTPsMutex))) 
			exit(1);
			
		tmp = gActiveWTPs;
		CWThreadMutexUnlock(&gActiveWTPsMutex);

		if(gActiveWTPs >= gMaxWTPs) {

			CWLog("Too many WTPs");
			return;
		}
		CWLog("\n");	
		
		if(CWErr(CWParseDiscoveryRequestMessage(buf, readBytes, &seqNum, &values))) {
		
			CWProtocolMessage *msgPtr;
		
			CWLog("\n");
			CWLog("######### Discovery State #########");

			CWUseSockNtop(addrPtr, CWLog("CAPWAP Discovery Request from %s", str););
	
			/* don't add this WTP to our list to minimize DoS 
			 * attacks (will be added after join) 
			 */

			/* send response to WTP 
			 * note: we can consider reassembling only changed part
			 * AND/OR do this in a new thread.
			 */
			if(!CWErr(CWAssembleDiscoveryResponse(&msgPtr, seqNum, &(values.tmpPhyInfo)))) {
				/* 
				 * note: maybe an out-of-memory memory error 
				 * can be resolved without exit()-ing by 
				 * killing some thread or doing other funky 
				 * things.
				 */
				CWLog("Critical Error Assembling Discovery Response");
				exit(1);
			}

			if(!CWErr(CWNetworkSendUnsafeUnconnected(sock,
								 addrPtr,
								 (*msgPtr).msg,
								 (*msgPtr).offset))) {

				CWLog("Critical Error Sending Discovery Response");
				exit(1);
			}
			
			/* destroy useless values */
			CWDestroyDiscoveryRequestValues(&values);
			
			CW_FREE_PROTOCOL_MESSAGE(*msgPtr);
			CW_FREE_OBJECT(msgPtr);
		} else { 
			/* this isn't a Discovery Request */
			int i;
			CWACThreadArg *argPtr;
			
			CWUseSockNtop(addrPtr, CWDebugLog("Possible Client Hello from %s", str););
			
			if(!CWErr(CWThreadMutexLock(&gWTPsMutex))) exit(1);
			/* look for the first free slot */
			for(i = 0; i < gMaxWTPs && gWTPs[i].isNotFree; i++);
	
			CW_COPY_NET_ADDR_PTR(&(gWTPs[i].address), addrPtr);
			gWTPs[i].dataaddress.ss_family = AF_UNSPEC;
			gWTPs[i].isNotFree = CW_TRUE;
			gWTPs[i].isRequestClose = CW_FALSE;
			/* Elena Agostini - 03/2014: DTLS Data Packet List */
			gWTPs[i].sessionDataActive = CW_FALSE;
			CWThreadMutexUnlock(&gWTPsMutex);

			/* Capwap receive packets list */
			if (!CWErr(CWCreateSafeList(&gWTPs[i].packetReceiveList))) {

				if(!CWErr(CWThreadMutexLock(&gWTPsMutex))) 
					exit(1);
				gWTPs[i].isNotFree = CW_FALSE;
				CWThreadMutexUnlock(&gWTPsMutex);
				return;
			}
			
			CWSetMutexSafeList(gWTPs[i].packetReceiveList, 
					   &gWTPs[i].interfaceMutex);
			CWSetConditionSafeList(gWTPs[i].packetReceiveList,
					       &gWTPs[i].interfaceWait);

			/*
			 * Elena Agostini - 03/2014
			 * DTLS Data Packet List
			 */
			#ifdef CW_DTLS_DATA_CHANNEL
				if (!CWErr(CWCreateSafeList(&gWTPs[i].packetReceiveDataList))) {
					if(!CWErr(CWThreadMutexLock(&gWTPsMutex))) exit(1);
					gWTPs[i].isNotFree = CW_FALSE;
					CWThreadMutexUnlock(&gWTPsMutex);
					return;
				}
			
				CWSetMutexSafeList(gWTPs[i].packetReceiveDataList, &gWTPs[i].interfaceMutex);
				CWSetConditionSafeList(gWTPs[i].packetReceiveDataList, &gWTPs[i].interfaceWait);
			#endif
			
			CW_CREATE_OBJECT_ERR(argPtr, CWACThreadArg, { CWLog("Out Of Memory"); return; });

			argPtr->index = i;
			argPtr->sock = sock;
			argPtr->interfaceIndex = incomingInterfaceIndex;
						
			/* 
			 * If the packet was addressed to a broadcast address,
			 * just choose an interface we like (note: we can consider
			 * a bit load balancing instead of hard-coding 0-indexed 
			 * interface). Btw, Join Request should not really be 
			 * accepted if addressed to a broadcast address, so we 
			 * could simply discard the packet and go on.
			 * If you leave this code, the WTP Count will increase 
			 * for the interface we hard-code here, even if it is not
			 * necessary the interface we use to send packets to that
			 * WTP. If we really want to accept Join Request from 
			 * broadcast address, we can consider asking to the kernel
			 * which interface will be used to send the packet to a 
			 * specific address (if it remains the same) and than 
			 * increment WTPCount for that interface instead of 0-indexed one.
			 */
			if (argPtr->interfaceIndex < 0) argPtr->interfaceIndex = 0; 
	
			/* create the thread that will manage this WTP */
			if(!CWErr(CWCreateThread(&(gWTPs[i].thread), CWManageWTP, argPtr))) {

				CW_FREE_OBJECT(argPtr);
				if(!CWErr(CWThreadMutexLock(&gWTPsMutex))) 
					exit(1);
				
				CWDestroySafeList(&gWTPs[i].packetReceiveList);
				gWTPs[i].isNotFree = CW_FALSE;
				CWThreadMutexUnlock(&gWTPsMutex);
				
				return;
			}
	
	//ELENA - DA LEVARE CON DTLS DATI?
			/* Clone data packet */
			CW_CREATE_OBJECT_SIZE_ERR(pData, readBytes, { CWLog("Out Of Memory"); return; });
			memcpy(pData, buf, readBytes);

			CWLockSafeList(gWTPs[i].packetReceiveList);
			CWAddElementToSafeListTailwitDataFlag(gWTPs[i].packetReceiveList,
 						   pData,
						   readBytes,
						  dataFlag);
			CWUnlockSafeList(gWTPs[i].packetReceiveList);
		}
	}
}

/*
 * Simple job: see if we have a thread that is serving address *addressPtr
 * 
 * Elena Agostini - 04/2014: more WTPs with same IPs, different PORTs
 */
__inline__ CWWTPManager *CWWTPByAddress(CWNetworkLev4Address *addressPtr, CWSocket sock, CWBool dataFlag, char * sessionID) {

	int i;
	
	if(addressPtr == NULL) return NULL;
	CWThreadMutexLock(&gWTPsMutex);
	for(i = 0; i < gMaxWTPs; i++) {
		
		/*
		if(gWTPs[i].isNotFree)
		{
			struct sockaddr_in *tmpAdd1 = (struct sockaddr_in *) addressPtr;
			struct sockaddr_in *tmpAdd2 = (struct sockaddr_in *) &(gWTPs[i].dataaddress);
			CWLog("++++ CWWTPByAddress: NUOVO WTP %s:%d, corrente WTP: %s:%d", inet_ntoa(tmpAdd1->sin_addr), ntohs(tmpAdd1->sin_port), inet_ntoa(tmpAdd2->sin_addr), ntohs(tmpAdd2->sin_port));
		}
		*/
		if(gWTPs[i].isNotFree && 
		   &(gWTPs[i].address) != NULL 
		   && 
		  (
				(
					(dataFlag == CW_FALSE) && 
					(!sock_cmp_addr((struct sockaddr*)addressPtr, (struct sockaddr*)&(gWTPs[i].address),sizeof(CWNetworkLev4Address))) &&
					(!sock_cmp_port((struct sockaddr*)addressPtr, (struct sockaddr*)&(gWTPs[i].address), sizeof(CWNetworkLev4Address)))
				)
				||
				(
					(dataFlag == CW_TRUE) &&
					( 
						(sessionID != NULL) && (memcmp(gWTPs[i].WTPProtocolManager.sessionID, sessionID, WTP_SESSIONID_LENGTH) == 0) ||
						(
							(!sock_cmp_addr((struct sockaddr*)addressPtr, (struct sockaddr*)&(gWTPs[i].dataaddress),sizeof(CWNetworkLev4Address))) &&
							(!sock_cmp_port((struct sockaddr*)addressPtr, (struct sockaddr*)&(gWTPs[i].dataaddress), sizeof(CWNetworkLev4Address)))
						)
					)
						
				)			
		  )
		)
		{ 
		
			/* we treat a WTP that sends packet to a different 
			 * AC's interface as a new WTP
			 */

			CWThreadMutexUnlock(&gWTPsMutex);
			//CWLog("-- WTP gestito dal thread %d ", i);
			return &(gWTPs[i]);
		}
	}
	
	CWThreadMutexUnlock(&gWTPsMutex);
	
	//CWLog("-- WTP mai gestito");
	
	return NULL;
}

/* Elena Agostini - 04/2014: check if there is a generic thread for this handshake on datachannel */
__inline__ genericHandshakeThreadPtr CWWTPThreadGenericByAddress(CWNetworkLev4Address *addressPtr) {
	
	int indexTmpThread=0;
	
	if(addressPtr == NULL) return NULL;
	
	CWThreadMutexLock(&gWTPsMutex);
	
	for(indexTmpThread=0; indexTmpThread < WTP_MAX_TMP_THREAD_DTLS_DATA; indexTmpThread++)
	{
		//CWLog("+++ cerco nella struttura numero %d", indexTmpThread);
		if(listGenericThreadDTLSData[indexTmpThread] != NULL)
		{
			struct sockaddr_in *tmpAdd1 = (struct sockaddr_in *) addressPtr;
			struct sockaddr_in *tmpAdd2 = (struct sockaddr_in *) &(listGenericThreadDTLSData[indexTmpThread]->addressWTPPtr);
			CWLog("++++ CWWTPThreadGenericByAddress, NUOVO WTP %s:%d, CORRENTE WTP: %s:%d, Num Generic Thread: %d", inet_ntoa(tmpAdd1->sin_addr), ntohs(tmpAdd1->sin_port), inet_ntoa(tmpAdd2->sin_addr), ntohs(tmpAdd2->sin_port), indexTmpThread);

			if(
				(!sock_cmp_addr((struct sockaddr*)addressPtr, (struct sockaddr*)&(listGenericThreadDTLSData[indexTmpThread]->addressWTPPtr),sizeof(CWNetworkLev4Address))) &&
				(!sock_cmp_port((struct sockaddr*)addressPtr, (struct sockaddr*)&(listGenericThreadDTLSData[indexTmpThread]->addressWTPPtr), sizeof(CWNetworkLev4Address)))
			)
			{
				CWThreadMutexUnlock(&gWTPsMutex);
				//CWLog("+++++ Trovato");
				return listGenericThreadDTLSData[indexTmpThread];
			}
		}
	}
	
	CWThreadMutexUnlock(&gWTPsMutex);
	CWLog("+++++ NON Trovato");
	
	return NULL;		
}

/* 
 * Session's thread function: each thread will manage a single session 
 * with one WTP.
 */
CW_THREAD_RETURN_TYPE CWManageWTP(void *arg) {

	int 		i = ((CWACThreadArg*)arg)->index;
	CWSocket 	sock = ((CWACThreadArg*)arg)->sock;
	int 		interfaceIndex = ((CWACThreadArg*)arg)->interfaceIndex;
	
	CW_FREE_OBJECT(arg);
	
	if(!(CWThreadSetSpecific(&gIndexSpecific, &i))) {

		CWLog("Critical Error with Thread Data");
		_CWCloseThread(i);
	}

	if(!CWErr(CWThreadMutexLock(&gActiveWTPsMutex))) 
		exit(1);

	gActiveWTPs++;

	gInterfaces[interfaceIndex].WTPCount++;
	CWUseSockNtop(((struct sockaddr*) &(gInterfaces[interfaceIndex].addr)),
				  CWDebugLog("One more WTP on %s (%d)", str, interfaceIndex);
				  );
	
	CWThreadMutexUnlock(&gActiveWTPsMutex);

	CWACInitBinding(i);
	
	gWTPs[i].interfaceIndex = interfaceIndex;
	gWTPs[i].socket = sock;
	
	gWTPs[i].fragmentsList = NULL;
	/* we're in the join state for this session */
	gWTPs[i].currentState = CW_ENTER_JOIN;
	gWTPs[i].subState = CW_DTLS_HANDSHAKE_IN_PROGRESS;
	
	/**** ACInterface ****/
	gWTPs[i].interfaceCommandProgress = CW_FALSE;
	gWTPs[i].interfaceCommand = NO_CMD;
	CWDestroyThreadMutex(&gWTPs[i].interfaceMutex);	
	CWCreateThreadMutex(&gWTPs[i].interfaceMutex);
	CWDestroyThreadMutex(&gWTPs[i].interfaceSingleton);	
	CWCreateThreadMutex(&gWTPs[i].interfaceSingleton);
	CWDestroyThreadCondition(&gWTPs[i].interfaceWait);	
	CWCreateThreadCondition(&gWTPs[i].interfaceWait);
	CWDestroyThreadCondition(&gWTPs[i].interfaceComplete);	
	CWCreateThreadCondition(&gWTPs[i].interfaceComplete);
	gWTPs[i].qosValues = NULL;
	/**** ACInterface ****/

	gWTPs[i].messages = NULL;
 	gWTPs[i].messagesCount = 0;
 	gWTPs[i].isRetransmitting = CW_FALSE;
	gWTPs[i].retransmissionCount = 0;
		
	CWResetWTPProtocolManager(&(gWTPs[i].WTPProtocolManager));

	CWLog("New Session");

	/* start WaitJoin timer */
	if(!CWErr(CWTimerRequest(gCWWaitJoin,
				 &(gWTPs[i].thread),
				 &(gWTPs[i].currentTimer),
				 CW_CRITICAL_TIMER_EXPIRED_SIGNAL))) {

		CWCloseThread();
	}

#ifndef CW_NO_DTLS
	CWDebugLog("Init DTLS Session");

 	if(!CWErr(CWSecurityInitSessionServer(&gWTPs[i],
					      sock,
					      gACSecurityContext,
					      &((gWTPs[i]).session),
					      &(gWTPs[i].pathMTU)))) {

		CWTimerCancel(&(gWTPs[i].currentTimer));
		CWCloseThread();
	}
#endif
	(gWTPs[i]).subState = CW_WAITING_REQUEST;

	if(gCWForceMTU > 0) gWTPs[i].pathMTU = gCWForceMTU;

	CWDebugLog("Path MTU for this Session: %d",  gWTPs[i].pathMTU);
	
	
	CW_REPEAT_FOREVER {
		int readBytes;
		CWProtocolMessage msg;
		CWBool dataFlag = CW_FALSE;

		msg.msg = NULL;
		msg.offset = 0;

		/* Wait WTP action */

		CWThreadMutexLock(&gWTPs[i].interfaceMutex);

		while ((gWTPs[i].isRequestClose == CW_FALSE) &&
		       (CWGetCountElementFromSafeList(gWTPs[i].packetReceiveList) == 0) &&
		       (gWTPs[i].interfaceCommand == NO_CMD)) {

			 /*TODO: Check system */
			CWWaitThreadCondition(&gWTPs[i].interfaceWait, 
					      &gWTPs[i].interfaceMutex);
		}

		CWThreadMutexUnlock(&gWTPs[i].interfaceMutex);

		if (gWTPs[i].isRequestClose) {

			CWLog("Request close thread");
			_CWCloseThread(i);
		}

		CWThreadSetSignals(SIG_BLOCK, 
				   2,
				   CW_SOFT_TIMER_EXPIRED_SIGNAL,
				   CW_CRITICAL_TIMER_EXPIRED_SIGNAL);

		if (CWGetCountElementFromSafeList(gWTPs[i].packetReceiveList) > 0) {

			CWBool 	bCrypt = CW_FALSE;
			char	*pBuffer;

			CWThreadMutexLock(&gWTPs[i].interfaceMutex);
			pBuffer = (char *)CWGetHeadElementFromSafeList(gWTPs[i].packetReceiveList, NULL);
			
			/*
			 * Elena Agostini - 03/2014
			 * 
			 * If && bCrypt will be 0 even if packet is DTLS
			 */
			//if (((pBuffer[0] & 0x0f) == CW_PACKET_CRYPT) || ((gWTPs[i].buf[0] & 0x0f) == CW_PACKET_CRYPT))
			if((pBuffer[0] & 0x0f) == CW_PACKET_CRYPT)  
				bCrypt = CW_TRUE;

			
			CWThreadMutexUnlock(&gWTPs[i].interfaceMutex);

			if (bCrypt) {
			  if(!CWErr(CWSecurityReceive(gWTPs[i].session,
										  gWTPs[i].buf,
										  CW_BUFFER_SIZE - 1,
										  &readBytes))) {
					/* error */
				
				CWDebugLog("Error during security receive");
				CWThreadSetSignals(SIG_UNBLOCK, 1, CW_SOFT_TIMER_EXPIRED_SIGNAL);

				continue;
			  }
			  
			} else {
			  CWThreadMutexLock(&gWTPs[i].interfaceMutex);
			  pBuffer = (char*)CWRemoveHeadElementFromSafeListwithDataFlag(gWTPs[i].packetReceiveList, &readBytes,&dataFlag);
			  CWThreadMutexUnlock(&gWTPs[i].interfaceMutex);
			  
			  memcpy(gWTPs[i].buf, pBuffer, readBytes);
			  CW_FREE_OBJECT(pBuffer);
			}
			
			if(!CWProtocolParseFragment(gWTPs[i].buf,
						    readBytes,
						    &(gWTPs[i].fragmentsList),
						    &msg,
						    &dataFlag,
						    gWTPs[i].RadioMAC)) {

				if(CWErrorGetLastErrorCode() == CW_ERROR_NEED_RESOURCE) {

					CWDebugLog("Need At Least One More Fragment");
				} 
				else {
					CWErrorHandleLast();
				}
				CWThreadSetSignals(SIG_UNBLOCK, 1, CW_SOFT_TIMER_EXPIRED_SIGNAL);
				
				continue;
			}

			switch(gWTPs[i].currentState) 
			{
				case CW_ENTER_JOIN:
				{
					/* we're inside the join state */
					if(!ACEnterJoin(i, &msg)) 
					{
						if(CWErrorGetLastErrorCode() == CW_ERROR_INVALID_FORMAT) 
						{
							/* Log and ignore other messages */
							CWErrorHandleLast();
							CWLog("Received something different from a Join Request");
						} 
						else 
						{
							/* critical error, close session */
							CWErrorHandleLast();
							CWThreadSetSignals(SIG_UNBLOCK, 1, CW_SOFT_TIMER_EXPIRED_SIGNAL);
							CWCloseThread();
						}
					}
					
					break;
				}
				case CW_ENTER_CONFIGURE:
				{
					if(!ACEnterConfigure(i, &msg)) 
					{
						if(CWErrorGetLastErrorCode() == CW_ERROR_INVALID_FORMAT) 
						{
							/* Log and ignore other messages */
							CWErrorHandleLast();
							CWLog("Received something different from a Configure Request");
						} 
						else 
						{
							/* critical error, close session */
							CWErrorHandleLast();
							CWThreadSetSignals(SIG_UNBLOCK, 1, CW_SOFT_TIMER_EXPIRED_SIGNAL);
							CWCloseThread();
						}
					}
					break;
				}
				case CW_ENTER_DATA_CHECK:
				{
					if(!ACEnterDataCheck(i, &msg)) 
					{
						if(CWErrorGetLastErrorCode() == CW_ERROR_INVALID_FORMAT) 
						{
							/* Log and ignore other messages */
							CWErrorHandleLast();
							CWLog("Received something different from a Change State Event Request");
						} 
						else 
						{
							/* critical error, close session */
							CWErrorHandleLast();
							CWThreadSetSignals(SIG_UNBLOCK, 1, CW_SOFT_TIMER_EXPIRED_SIGNAL);
							CWCloseThread();
						}
					}
					
					
					break;
				}	
				case CW_ENTER_RUN:
				{
					/*
					 * Elena Agostini - 03/2014: DTLS Data Session AC. DataPacket Receiver Thread
					 */
					#ifdef CW_DTLS_DATA_CHANNEL
					
					if(gWTPs[i].sessionDataActive == CW_FALSE)
					{
						CWACThreadArg *argPtrDataThread;
						CW_CREATE_OBJECT_ERR(argPtrDataThread, CWACThreadArg, { CWLog("Out Of Memory"); return; });
						argPtrDataThread->index = i;
						argPtrDataThread->sock = sock;
						argPtrDataThread->interfaceIndex = 0;
						
						CWThreadMutexLock(&gWTPs[i].interfaceMutex);
						gWTPs[i].sessionDataActive=CW_TRUE;
						CWThreadMutexUnlock(&gWTPs[i].interfaceMutex);
						
						CWThread thread_receiveDataChannel;
						if(!CWErr(CWCreateThread(&thread_receiveDataChannel, CWACReceiveDataChannel, argPtrDataThread))) {
							CWLog("Error starting Thread that receive data channel");
							exit(1);
						}
						gWTPs[i].sessionDataActive = CW_TRUE;
					}
					#endif
					
					if(!ACEnterRun(i, &msg, dataFlag)) 
					{
						if(CWErrorGetLastErrorCode() == CW_ERROR_INVALID_FORMAT) 
						{
							/* Log and ignore other messages */
							CWErrorHandleLast();
							CWLog("--> Received something different from a valid Run Message");
						} 
						else 
						{
							/* critical error, close session */
							CWLog("--> Critical Error... closing thread");
							CWErrorHandleLast();
							CWThreadSetSignals(SIG_UNBLOCK, 1, CW_SOFT_TIMER_EXPIRED_SIGNAL);
							/*
							 * Elena Agostini - 03/2014
							 * 
							 * DTLS Data Session AC
							 */
							//TODO
							
							CWCloseThread();
						}
					}
					break;
				}
				default:
				{
					CWLog("Not Handled Packet");
					break;
				}
			}
			CW_FREE_PROTOCOL_MESSAGE(msg);
		}
		else {

		  CWThreadMutexLock(&gWTPs[i].interfaceMutex);
		  
		  if (gWTPs[i].interfaceCommand != NO_CMD) {
			
			CWBool bResult = CW_FALSE;
			
			switch (gWTPs[i].interfaceCommand) {
			case QOS_CMD:
			  {
				int seqNum = CWGetSeqNum();
				
				/* CWDebugLog("~~~~~~seq num in Check: %d~~~~~~", seqNum); */
				if (CWAssembleConfigurationUpdateRequest(&(gWTPs[i].messages), 
														 &(gWTPs[i].messagesCount),
														 gWTPs[i].pathMTU,
														 seqNum, CONFIG_UPDATE_REQ_QOS_ELEMENT_TYPE)) {
				  
				  if(CWACSendAcknowledgedPacket(i, CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_RESPONSE, seqNum)) 
					bResult = CW_TRUE;
				  else
					CWACStopRetransmission(i);
				}
				break;
			  }
			  /*
			   * Elena Agostini: 09/2014. IEEE WLAN Configuration Request
			   */
			 case IEEE_WLAN_CONFIGURATION_CMD:
			 {
				int seqNum = CWGetSeqNum();
				
				int radioIndex = CWIEEEBindingGetIndexFromDevID(gWTPs[i].cmdWLAN->radioID);					
				int wlanIndex = CWIEEEBindingGetIndexFromDevID(gWTPs[i].cmdWLAN->wlanID);
				
				CWLog("Assembling WLAN Configuration Request (op. %d)", gWTPs[i].cmdWLAN->typeCmd);
				
				if(gWTPs[i].cmdWLAN->typeCmd == CW_OP_ADD_WLAN)
				{
					//Controlli su numero radio e numero interfaccia
					if(!ACUpdateInfoWlanInterface(
					&(gWTPs[i].WTPProtocolManager.radiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex]), 
					gWTPs[i].cmdWLAN->wlanID, 
					gWTPs[i].cmdWLAN->ssid, 
					gWTPs[i].WTPProtocolManager.radiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex].frameTunnelMode))
						break;//return CW_FALSE;
				}
				
				//Create Configuration Request. Add or Del
				if((CWAssembleIEEEConfigurationRequest(&(gWTPs[i].messages), 
									 &(gWTPs[i].messagesCount), 
									 gWTPs[i].pathMTU, 
									 seqNum,
									 gWTPs[i].cmdWLAN->typeCmd,
									 gWTPs[i].cmdWLAN->radioID,
									 gWTPs[i].cmdWLAN->wlanID,
									 i
									 )))  {
						
					/*	if(!CWACSendFragments(i)) 
							CWLog("CWACSendFragments NO");
						else
							bResult = CW_TRUE;
						*/
						
						if(CWACSendAcknowledgedPacket(i, CW_MSG_TYPE_VALUE_WLAN_CONFIGURATION_REQUEST, seqNum))
							bResult = CW_TRUE;
						 else
							CWACStopRetransmission(i);
					}	
				
				break;
			
			 }
			case CLEAR_CONFIG_MSG_CMD:
			  {
				int seqNum = CWGetSeqNum();
				
						/* Clear Configuration Request */
				if (CWAssembleClearConfigurationRequest(&(gWTPs[i].messages),
														&(gWTPs[i].messagesCount),
														gWTPs[i].pathMTU, seqNum)) {
				  
				  if(CWACSendAcknowledgedPacket(i, CW_MSG_TYPE_VALUE_CLEAR_CONFIGURATION_RESPONSE, seqNum)) 
								bResult = CW_TRUE;
				  else
					CWACStopRetransmission(i);
				}
				break;
			  }
			/********************************************************
			 * 2009 Update:											*
			 *				New switch case for OFDM_CONTROL_CMD	*
			 ********************************************************/
			  
			case OFDM_CONTROL_CMD: 
				  {
					int seqNum = CWGetSeqNum();
					
					  if (CWAssembleConfigurationUpdateRequest(&(gWTPs[i].messages), 
														 &(gWTPs[i].messagesCount),
														 gWTPs[i].pathMTU,
														 seqNum, CONFIG_UPDATE_REQ_OFDM_ELEMENT_TYPE)) {
				  
					  if(CWACSendAcknowledgedPacket(i, CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_RESPONSE, seqNum)) 
						bResult = CW_TRUE;
					  else
						CWACStopRetransmission(i);
					}
				  break;
				  }
			/*Update 2009
				Added case to manage UCI configuration command*/
			case UCI_CONTROL_CMD: 
				  {
					int seqNum = CWGetSeqNum();
					
					  if (CWAssembleConfigurationUpdateRequest(&(gWTPs[i].messages), 
														 &(gWTPs[i].messagesCount),
														 gWTPs[i].pathMTU,
														 seqNum, CONFIG_UPDATE_REQ_VENDOR_UCI_ELEMENT_TYPE)) {
				  
					  if(CWACSendAcknowledgedPacket(i, CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_RESPONSE, seqNum)) 
						bResult = CW_TRUE;
					  else
						CWACStopRetransmission(i);
					}
				  break;
				  }
			case WTP_UPDATE_CMD:
				{
					 int seqNum = CWGetSeqNum();

                                         if (CWAssembleConfigurationUpdateRequest(&(gWTPs[i].messages),
                                                                                                                 &(gWTPs[i].messagesCount),
                                                                                                                 gWTPs[i].pathMTU,
                                                                                                                 seqNum, CONFIG_UPDATE_REQ_VENDOR_WUM_ELEMENT_TYPE)) {

                                          if(CWACSendAcknowledgedPacket(i, CW_MSG_TYPE_VALUE_CONFIGURE_UPDATE_RESPONSE, seqNum))
                                                bResult = CW_TRUE;
                                          else
                                                CWACStopRetransmission(i);
                                        }
                                  break;
			

	
				}
			}

				gWTPs[i].interfaceCommand = NO_CMD;

				if (bResult)
					gWTPs[i].interfaceCommandProgress = CW_TRUE;
				else {
					gWTPs[i].interfaceResult = 0;
					CWSignalThreadCondition(&gWTPs[i].interfaceComplete);
					CWDebugLog("Error sending command");
				}
			}
			CWThreadMutexUnlock(&gWTPs[i].interfaceMutex);
		}
		CWThreadSetSignals(SIG_UNBLOCK, 2, 
				   CW_SOFT_TIMER_EXPIRED_SIGNAL, 
				   CW_CRITICAL_TIMER_EXPIRED_SIGNAL);
	}
}

void _CWCloseThread(int i) {

 	CWThreadSetSignals(SIG_BLOCK, 2, 
			   CW_SOFT_TIMER_EXPIRED_SIGNAL, 
			   CW_CRITICAL_TIMER_EXPIRED_SIGNAL);

	/**** ACInterface ****/
	gWTPs[i].qosValues=NULL;
	CWThreadMutexUnlock(&(gWTPs[i].interfaceMutex));
	/**** ACInterface ****/

	if(!CWErr(CWThreadMutexLock(&gActiveWTPsMutex))) 
		exit(1);
	
	gInterfaces[gWTPs[i].interfaceIndex].WTPCount--;
	gActiveWTPs--;
	
	CWUseSockNtop( ((struct sockaddr*)&(gInterfaces[gWTPs[i].interfaceIndex].addr)),
			CWLog("Remove WTP on Interface %s (%d)", str, gWTPs[i].interfaceIndex););

	CWThreadMutexUnlock(&gActiveWTPsMutex);
	
	CWDebugLog("Close Thread: %08x", (unsigned int)CWThreadSelf());
	
	if(gWTPs[i].subState != CW_DTLS_HANDSHAKE_IN_PROGRESS) {
	
		CWSecurityDestroySession(gWTPs[i].session);
	}
	
	/* this will do nothing if the timer isn't active */
	CWTimerCancel(&(gWTPs[i].currentTimer));
	CWACStopRetransmission(i);

	if (gWTPs[i].interfaceCommandProgress == CW_TRUE) {

		CWThreadMutexLock(&gWTPs[i].interfaceMutex);
		
		gWTPs[i].interfaceResult = 1;
		gWTPs[i].interfaceCommandProgress = CW_FALSE;
		CWSignalThreadCondition(&gWTPs[i].interfaceComplete);

		CWThreadMutexUnlock(&gWTPs[i].interfaceMutex);
	}
	
	gWTPs[i].session = NULL;
	gWTPs[i].subState = CW_DTLS_HANDSHAKE_IN_PROGRESS;
	CWDeleteList(&(gWTPs[i].fragmentsList), CWProtocolDestroyFragment);
	
	/* CW_FREE_OBJECT(gWTPs[i].configureReqValuesPtr); */
	
	CWCleanSafeList(gWTPs[i].packetReceiveList, free);
	CWDestroySafeList(gWTPs[i].packetReceiveList);

	CWThreadMutexLock(&gWTPsMutex);
	gWTPs[i].isNotFree = CW_FALSE;
	CWThreadMutexUnlock(&gWTPsMutex);
	
//-- Elena Agostini: fake method to delete all node about that WTP
	nodeAVL * tmp;
	
	CWLog("AVL AC: \n");
	AVLdisplay_avl(avlTree);
	CWLog("Now delete all STA of WTP %d", i);
	CWThreadMutexLock(&(mutexAvlTree));
	tmp=NULL;
	do {
		tmp = AVLfindWTPNode(avlTree, i);
		if(tmp != NULL)
		{
			CWPrintEthernetAddress(tmp->staAddr, "There is a STA belonging to WTP");
			avlTree = AVLdeleteNodeWithoutRadioID(avlTree, tmp);
		}
	}while(tmp != NULL && avlTree != NULL);
	
	CWThreadMutexUnlock(&(mutexAvlTree));
//--
	
	CWExitThread();
}

void CWCloseThread() {

	int *iPtr;
	
	if((iPtr = ((int*)CWThreadGetSpecific(&gIndexSpecific))) == NULL) {

		CWLog("Error Closing Thread");
		return;
	}
	
	_CWCloseThread(*iPtr);
}

void CWCriticalTimerExpiredHandler(int arg) {

	int *iPtr;

	CWThreadSetSignals(SIG_BLOCK, 2,
			   CW_SOFT_TIMER_EXPIRED_SIGNAL,
			   CW_CRITICAL_TIMER_EXPIRED_SIGNAL);
 	
	CWDebugLog("Critical Timer Expired for Thread: %08x", (unsigned int)CWThreadSelf());
	CWDebugLog("Abort Session");
	/* CWCloseThread(); */

	if((iPtr = ((int*)CWThreadGetSpecific(&gIndexSpecific))) == NULL) {

		CWLog("Error Handling Critical timer");
		CWThreadSetSignals(SIG_UNBLOCK, 2, 
				   CW_SOFT_TIMER_EXPIRED_SIGNAL,
				   CW_CRITICAL_TIMER_EXPIRED_SIGNAL);
		return;
	}

	/* Request close thread */
	gWTPs[*iPtr].isRequestClose = CW_TRUE;
	CWSignalThreadCondition(&gWTPs[*iPtr].interfaceWait);
}

void CWSoftTimerExpiredHandler(int arg) {

	int *iPtr;

	CWThreadSetSignals(SIG_BLOCK, 2, 
			   CW_SOFT_TIMER_EXPIRED_SIGNAL,
			   CW_CRITICAL_TIMER_EXPIRED_SIGNAL);

	CWDebugLog("Soft Timer Expired for Thread: %08x", 
		   (unsigned int)CWThreadSelf());
	
	if((iPtr = ((int*)CWThreadGetSpecific(&gIndexSpecific))) == NULL) {

		CWLog("Error Handling Soft timer");
		CWThreadSetSignals(SIG_UNBLOCK, 2, 
				   CW_SOFT_TIMER_EXPIRED_SIGNAL,
				   CW_CRITICAL_TIMER_EXPIRED_SIGNAL);
		return;
	}
	
	if((!gWTPs[*iPtr].isRetransmitting) || (gWTPs[*iPtr].messages == NULL)) {

		CWDebugLog("Soft timer expired but we are not retransmitting");
		CWThreadSetSignals(SIG_UNBLOCK, 2, 
				   CW_SOFT_TIMER_EXPIRED_SIGNAL,
				   CW_CRITICAL_TIMER_EXPIRED_SIGNAL);
		return;
	}

	(gWTPs[*iPtr].retransmissionCount)++;
	
	CWDebugLog("Retransmission Count increases to %d", gWTPs[*iPtr].retransmissionCount);
	
	if(gWTPs[*iPtr].retransmissionCount >= gCWMaxRetransmit) 
	{
		CWDebugLog("Peer is Dead");
		/* ?? _CWCloseThread(*iPtr);
		 * Request close thread
		 */
		gWTPs[*iPtr].isRequestClose = CW_TRUE;
		CWSignalThreadCondition(&gWTPs[*iPtr].interfaceWait);
		return;
	}

	if(!CWErr(CWACResendAcknowledgedPacket(*iPtr))) {
		_CWCloseThread(*iPtr);
	}
	
	/* CWDebugLog("~~~~~~fine ritrasmissione ~~~~~"); */
	CWThreadSetSignals(SIG_UNBLOCK, 2, 
			   CW_SOFT_TIMER_EXPIRED_SIGNAL,
			   CW_CRITICAL_TIMER_EXPIRED_SIGNAL);
}

void CWResetWTPProtocolManager(CWWTPProtocolManager *WTPProtocolManager) {

	CW_FREE_OBJECT(WTPProtocolManager->locationData);
	CW_FREE_OBJECT(WTPProtocolManager->name);
	WTPProtocolManager->sessionID = 0;
	WTPProtocolManager->descriptor.maxRadios= 0;
	WTPProtocolManager->descriptor.radiosInUse= 0;
	WTPProtocolManager->descriptor.encCapabilities= 0;
	WTPProtocolManager->descriptor.vendorInfos.vendorInfosCount= 0;
	CW_FREE_OBJECT(WTPProtocolManager->descriptor.vendorInfos.vendorInfos);
	
	WTPProtocolManager->radiosInfo.radioCount= 0;
	CW_FREE_OBJECT(WTPProtocolManager->radiosInfo.radiosInfo);
	CW_FREE_OBJECT(WTPProtocolManager->ACName);
	(WTPProtocolManager->ACNameIndex).count = 0;
	CW_FREE_OBJECT((WTPProtocolManager->ACNameIndex).ACNameIndex);
	(WTPProtocolManager->radioAdminInfo).radiosCount = 0;
	CW_FREE_OBJECT((WTPProtocolManager->radioAdminInfo).radios);
	WTPProtocolManager->StatisticsTimer = 0;
	(WTPProtocolManager->WTPBoardData).vendorInfosCount = 0;
	CW_FREE_OBJECT((WTPProtocolManager->WTPBoardData).vendorInfos);
	CW_FREE_OBJECT(WTPProtocolManager->WTPRebootStatistics);

	//CWWTPResetRebootStatistics(&(WTPProtocolManager->WTPRebootStatistics));

	/*
		**mancano questi campi:**
		CWNetworkLev4Address address;
		int pathMTU;
		struct sockaddr_in ipv4Address;
		CWProtocolConfigureRequestValues *configureReqValuesPtr;
		CWTimerID currentPacketTimer;
	*/
}

/*
 * Elena Agostini - 04/2014: Generic thread handler generich DTLS Data Channel handshake WTP 
 */
CW_THREAD_RETURN_TYPE CWGenericWTPDataHandshake(void *arg) {
	
	genericHandshakeThreadPtr argInputThread = (genericHandshakeThreadPtr) arg;
	CWWTPManager *wtpPtr = NULL;
	struct sockaddr_in *tmpAdd;
	CWSecuritySession sessionDataGeneric;
	int pathMTU, readBytes, countPacketDataList, dataFlag=1, elemLen, elemType, fragments, i;
	char buf[CW_BUFFER_SIZE];
	char * pData, * valSessionIDPtr;
	CWProtocolMessage msg, msgDataChannel;
	CWProtocolTransportHeaderValues values;
	CWSocket dataSocket;
	int indexTmpThread;
	
	dataSocket = argInputThread->dataSock;
	if (dataSocket == 0){
		CWLog("data socket of WTP isn't ready.");
		CWErrorHandleLast();
		CWCloseThread();
	}

	/* Sessione DTLS Dati Genrica con WTP in DataCheck per primo Handshake dati */
	if(!CWErr(CWSecurityInitGenericSessionServerDataChannel(argInputThread->packetDataList,	
									&(argInputThread->addressWTPPtr),
									dataSocket,
									gACSecurityContext,
									&sessionDataGeneric,
									&pathMTU)))
	{
		CWErrorHandleLast();
		CWCloseThread();
	}
	
	/* Leggo i dati dalla packetList e li riscrivo decifrati */	
	CW_REPEAT_FOREVER {
		countPacketDataList=0;
	
		//Se ci sono pacchetti sulla lista dati ... 
		CWLockSafeList(argInputThread->packetDataList);
		countPacketDataList = CWGetCountElementFromSafeList(argInputThread->packetDataList);
		CWUnlockSafeList(argInputThread->packetDataList);
		if(countPacketDataList > 0) {
			// ... li legge cifrati ... 
			if(!CWErr(CWSecurityReceive(sessionDataGeneric,
										buf,
										CW_BUFFER_SIZE - 1,
										&readBytes)))
			{		
				CWDebugLog("Error during security receive");
				CWThreadSetSignals(SIG_UNBLOCK, 1, CW_SOFT_TIMER_EXPIRED_SIGNAL);
				continue;
			}
			
			/* Se e un keepalive associo il canale dati a quello di controllo */
			
			msgDataChannel.msg = buf;
			msgDataChannel.offset = 0;
			
			if(!CWParseTransportHeader(&msgDataChannel, &values, &dataFlag, NULL)){
				CWDebugLog("CWParseTransportHeader failed");
				return CW_FALSE;
			}
		
			if(msgDataChannel.data_msgType == CW_DATA_MSG_KEEP_ALIVE_TYPE) {
				CWParseFormatMsgElem(&msgDataChannel, &elemType, &elemLen);
				valSessionIDPtr = CWParseSessionID(&msgDataChannel, 16);
				wtpPtr = CWWTPByAddress(&(argInputThread->addressWTPPtr), 0, CW_TRUE, valSessionIDPtr);
				if ((wtpPtr != NULL) && (wtpPtr->dataaddress.ss_family == AF_UNSPEC)) {
					CW_COPY_NET_ADDR_PTR(&(wtpPtr->dataaddress), &(argInputThread->addressWTPPtr));
					
					/* ++++++++++++++++++++ Replay with KeepAlive ++++++++++++++++++++ */
					CWProtocolMessage *messages = NULL;
					CWProtocolMessage sessionIDmsgElem;
					int fragmentsNum = 0;
					
					CWAssembleMsgElemSessionID(&sessionIDmsgElem, valSessionIDPtr);
					sessionIDmsgElem.data_msgType = CW_DATA_MSG_KEEP_ALIVE_TYPE;
					if (!CWAssembleDataMessage(&messages, 
						  &fragmentsNum, 
						  pathMTU, 
						  &sessionIDmsgElem, 
						  NULL,
						  CW_PACKET_CRYPT,
						  1
						  ))
					{
						CWLog("Failure Assembling KeepAlive Request");
						if(messages)
							for(i = 0; i < fragmentsNum; i++) {
								CW_FREE_PROTOCOL_MESSAGE(messages[i]);
							}	
						CW_FREE_OBJECT(messages);
						return CW_FALSE;
					}

					for(i = 0; i < fragmentsNum; i++) {
						if(!(CWSecuritySend(sessionDataGeneric, messages[i].msg, messages[i].offset))) {
							CWLog("Failure sending  KeepAlive Request");
							int k;
							for(k = 0; k < fragmentsNum; k++) {
								CW_FREE_PROTOCOL_MESSAGE(messages[k]);
							}	
							CW_FREE_OBJECT(messages);
							break;
						}
					}

					CWLog("Inviato KeepAlive");

					int k;
					for(k = 0; messages && k < fragmentsNum; k++) {
						CW_FREE_PROTOCOL_MESSAGE(messages[k]);
					}	
					CW_FREE_OBJECT(messages);
					/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
			
			
					//Termina handshake e termina thread
				}
				break;
			}
		}	
	}
	
	CWThreadMutexLock(&gWTPsMutex);
	for(indexTmpThread=0; indexTmpThread < WTP_MAX_TMP_THREAD_DTLS_DATA; indexTmpThread++)
	{
		if(listGenericThreadDTLSData[indexTmpThread] != NULL)
		{
			struct sockaddr_in *tmpAdd1 = (struct sockaddr_in *) &(argInputThread->addressWTPPtr);
			struct sockaddr_in *tmpAdd2 = (struct sockaddr_in *) &(listGenericThreadDTLSData[indexTmpThread]->addressWTPPtr);
				
			//CWLog("++++ Free prima di terminare il thread, NUOVO WTP %s:%d, CORRENTE WTP: %s:%d", inet_ntoa(tmpAdd1->sin_addr), ntohs(tmpAdd1->sin_port), inet_ntoa(tmpAdd2->sin_addr), ntohs(tmpAdd2->sin_port));

			if(
				(!sock_cmp_addr((struct sockaddr*)&(argInputThread->addressWTPPtr), (struct sockaddr*)&(listGenericThreadDTLSData[indexTmpThread]->addressWTPPtr),sizeof(CWNetworkLev4Address))) &&
				(!sock_cmp_port((struct sockaddr*)&(argInputThread->addressWTPPtr), (struct sockaddr*)&(listGenericThreadDTLSData[indexTmpThread]->addressWTPPtr), sizeof(CWNetworkLev4Address)))
			)
			{
			//	CWLog("++++ Trovato e faccio FREE della struttura numero %d", indexTmpThread);
				free(listGenericThreadDTLSData[indexTmpThread]);
				listGenericThreadDTLSData[indexTmpThread]=NULL;
				
				//CW_FREE_OBJECT(tmpGenericThreadList);
			//	CWLog("++++ Free Thread Generico");
				break;
			}
		}
	}
	CWThreadMutexUnlock(&gWTPsMutex);
	
	struct sockaddr_in *tmpAdd1 = (struct sockaddr_in *) &(argInputThread->addressWTPPtr);
	CWLog("[DTLS] New DTLS Data session created with WTP %s:%d.. generic thread exit", inet_ntoa(tmpAdd1->sin_addr), ntohs(tmpAdd1->sin_port));
	
	return NULL;
}
