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

 
#include "CWWTP.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

static CWBool gSuccessfulHandshake = CW_TRUE;
int gCWWaitJoin = CW_JOIN_INTERVAL_DEFAULT;

/*__________________________________________________________*/
/*  *******************___PROTOTYPES___*******************  */
void CWWTPWaitJoinExpired(CWTimerArg arg);
CWBool CWAssembleJoinRequest(CWProtocolMessage **messagesPtr,
			     int *fragmentsNumPtr,
			     int PMTU,
			     int seqNum,
			     CWList msgElemList);

CWBool CWParseJoinResponseMessage(char *msg,
				  int len,
				  int seqNum,
				  CWProtocolJoinResponseValues *valuesPtr);

CWBool CWSaveJoinResponseMessage (CWProtocolJoinResponseValues *joinResponse);

/*_____________________________________________________*/
/*  *******************___FUNCTIONS___*******************  */

/*
 * Manage Join State.
 */
CWStateTransition CWWTPEnterJoin() {

	CWTimerID waitJoinTimer;
	int seqNum;
	CWProtocolJoinResponseValues values;
	
	CWLog("\n");
	CWLog("######### Join State #########");
	
	/* reset Join state */
	CWNetworkCloseSocket(gWTPSocket);
	CWSecurityDestroySession(gWTPSession);
	CWSecurityDestroyContext(gWTPSecurityContext);
	gWTPSecurityContext = NULL;
	gWTPSession = NULL;

	/*
	 * Elena Agostini - 02/2014
	 *
	 * If gWTPForceACAddress is NOT NULL and WTP jump Discovery state, 
	 * object gACInfoPtr is not allocated. Set ACIPv4ListInfo without create object
	 * generate Segmentation Fault.
	 */
	if(gWTPForceACAddress != NULL) {
		CW_CREATE_OBJECT_ERR(gACInfoPtr, 
				     CWACInfoValues,
				     return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););	
	}

	/* Initialize gACInfoPtr */
	gACInfoPtr->ACIPv4ListInfo.ACIPv4ListCount=0;
	gACInfoPtr->ACIPv4ListInfo.ACIPv4List=NULL;	
	gACInfoPtr->ACIPv6ListInfo.ACIPv6ListCount=0;
	gACInfoPtr->ACIPv6ListInfo.ACIPv6List=NULL;

	if ((waitJoinTimer = timer_add(gCWWaitJoin, 0, CWWTPWaitJoinExpired, NULL)) == -1) {
		return CW_ENTER_DISCOVERY;
	}

	if(gWTPForceACAddress != NULL) {
		CWNetworkGetAddressForHost(gWTPForceACAddress, 
					   &(gACInfoPtr->preferredAddress));
/*
		struct sockaddr_in *sin = (struct sockaddr_in *)&(gACInfoPtr->preferredAddress);
		unsigned char *ip = (unsigned char *)&sin->sin_addr.s_addr;
		CWLog("Preferred: %d %d %d %d\n", ip[0], ip[1], ip[2], ip[3]);
*/	
		gACInfoPtr->security = gWTPForceSecurity;
	}
	
	/*
	 * Open control channel
	 */
	if(gWTPSocket)
		CWNetworkCloseSocket(gWTPSocket);
	/* Elena Agostini - 04/2014: make control port always the same inside each WTP */
	if(!CWErr(CWNetworkInitSocketClientWithPort(&gWTPSocket, &(gACInfoPtr->preferredAddress), WTP_PORT_CONTROL))) {
		timer_rem(waitJoinTimer, NULL);
		return CW_ENTER_DISCOVERY;
	}

	/*
	 * Open data channel
	 */	
	if(gWTPDataSocket)
		CWNetworkCloseSocket(gWTPDataSocket);
	/* Elena Agostini - 04/2014: make data port always the same inside each WTP */
	if(!CWErr(CWNetworkInitSocketClientDataChannelWithPort(&gWTPDataSocket, &(gACInfoPtr->preferredAddress), WTP_PORT_DATA)) ) {
		return CW_ENTER_DISCOVERY;
	}
	
	CWLog("Initiate Data Channel");

	/* Init DTLS session */

/* Elena Agostini - 04/2014 */	
#if !defined(CW_NO_DTLS) || defined(CW_DTLS_DATA_CHANNEL)
	if(gACInfoPtr->security == CW_X509_CERTIFICATE) {
		/*
		 * Elena Agostini - 02/2014
		 * Dynamic OpenSSL params
		 */
		if(!CWErr(CWSecurityInitContext(&gWTPSecurityContext,
						gWTPCertificate,
						gWTPKeyfile,
						gWTPPassword,
						CW_TRUE,
						NULL))) {
			
			timer_rem(waitJoinTimer, NULL);
			CWNetworkCloseSocket(gWTPSocket);
			gWTPSecurityContext = NULL;
			return CW_ENTER_DISCOVERY;
		}
	} else { 
		/* pre-shared keys */
		if(!CWErr(CWSecurityInitContext(&gWTPSecurityContext,
						NULL,
						NULL,
						NULL,
						CW_TRUE,
						NULL))) {
			
			timer_rem(waitJoinTimer, NULL);
			CWNetworkCloseSocket(gWTPSocket);
			gWTPSecurityContext = NULL;
			return CW_ENTER_DISCOVERY;
		}
	}
#endif

	CWThread thread_receiveFrame;
	if(!CWErr(CWCreateThread(&thread_receiveFrame, 
				 CWWTPReceiveDtlsPacket,
				 (void*)gWTPSocket))) {
		
		CWLog("Error starting Thread that receive DTLS packet");
		timer_rem(waitJoinTimer, NULL);
		CWNetworkCloseSocket(gWTPSocket);
#ifndef CW_NO_DTLS
		CWSecurityDestroyContext(gWTPSecurityContext);
		gWTPSecurityContext = NULL;
		gWTPSession = NULL;
#endif
		return CW_ENTER_DISCOVERY;
	}

	CWThread thread_receiveDataFrame;
	if(!CWErr(CWCreateThread(&thread_receiveDataFrame, 
				 CWWTPReceiveDataPacket,
				 (void*)gWTPDataSocket))) {
		
		CWLog("Error starting Thread that receive data packet");
		return CW_ENTER_DISCOVERY;
	}
		
#ifndef CW_NO_DTLS

	if(!CWErr(CWSecurityInitSessionClient(gWTPSocket,
					      &(gACInfoPtr->preferredAddress),
					      gPacketReceiveList,
					      gWTPSecurityContext,
					      &gWTPSession,
					      &gWTPPathMTU))) { 
		
		/* error setting up DTLS session */
		timer_rem(waitJoinTimer, NULL);		
		CWNetworkCloseSocket(gWTPSocket);
		CWSecurityDestroyContext(gWTPSecurityContext);
		gWTPSecurityContext = NULL;
		gWTPSession = NULL;
		return CW_ENTER_DISCOVERY;
	}
#endif
	if(gCWForceMTU > 0) {
		gWTPPathMTU = gCWForceMTU;
	}
	
	CWDebugLog("Path MTU for this Session: %d", gWTPPathMTU);
	
	/* send Join Request */
	seqNum = CWGetSeqNum();

	if(!CWErr(CWWTPSendAcknowledgedPacket(seqNum,
					      NULL,
					      CWAssembleJoinRequest,
					      (void*)CWParseJoinResponseMessage,
					      (void*)CWSaveJoinResponseMessage,
					      &values))) {
cw_join_err:
		timer_rem(waitJoinTimer, NULL);
		CWNetworkCloseSocket(gWTPSocket);
#ifndef CW_NO_DTLS
		CWSecurityDestroySession(gWTPSession);
		CWSecurityDestroyContext(gWTPSecurityContext);
		gWTPSecurityContext = NULL;
		gWTPSession = NULL;
#endif
		return CW_ENTER_DISCOVERY;
	}
	
	timer_rem(waitJoinTimer, NULL);
	
	if(!gSuccessfulHandshake) { 
		/* timer expired */
		goto cw_join_err;
	}

	CWLog("Join Completed");
	
	return CW_ENTER_CONFIGURE;
}

void CWWTPWaitJoinExpired(CWTimerArg arg) {
	
	CWLog("WTP Wait Join Expired");
	gSuccessfulHandshake = CW_FALSE;
	CWNetworkCloseSocket(gWTPSocket);
}

CWBool CWAssembleJoinRequest(CWProtocolMessage **messagesPtr, 
			     int *fragmentsNumPtr,
			     int PMTU,
			     int seqNum,
			     CWList msgElemList) {

	CWProtocolMessage	*msgElems= NULL;
	const int 		msgElemCount = 10;
	CWProtocolMessage 	*msgElemsBinding= NULL;
	const int 		msgElemBindingCount=0;
	int 			k = -1;
	
	if(messagesPtr == NULL || fragmentsNumPtr == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems,
					 msgElemCount,
					 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););	
		
		/* Assemble Message Elements */
	if ( 
	     (!(CWAssembleMsgElemLocationData(&(msgElems[++k])))) ||
	     (!(CWAssembleMsgElemWTPBoardData(&(msgElems[++k])))) ||
	     (!(CWAssembleMsgElemWTPDescriptor(&(msgElems[++k])))) ||
	     (!(CWAssembleMsgElemWTPIPv4Address(&(msgElems[++k])))) ||
	     (!(CWAssembleMsgElemWTPName(&(msgElems[++k])))) ||
	     (!(CWAssembleMsgElemSessionID(&(msgElems[++k]), &gWTPSessionID[0]))) ||
	     (!(CWAssembleMsgElemWTPFrameTunnelMode(&(msgElems[++k])))) ||
	     (!(CWAssembleMsgElemWTPMACType(&(msgElems[++k])))) ||
		/*
		 * Elena Agostini - 02/2014: ECN Support Msg Elem MUST be included in Join Request/Response Messages
	 	 */
	     (!(CWAssembleMsgElemECNSupport(&(msgElems[++k]))))
	) {
		int i;
		for(i = 0; i <= k; i++) { 
			CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);
		}
		CW_FREE_OBJECT(msgElems);
		/* error will be handled by the caller */
		return CW_FALSE;
	}
	
	//Elena Agostini - 07/2014: nl80211 support. 
	int indexWTPRadioInfo=0;
	for(indexWTPRadioInfo=0; indexWTPRadioInfo<gRadiosInfo.radioCount; indexWTPRadioInfo++)
	{
		if(!(CWAssembleMsgElemWTPRadioInformation( &(msgElems[++k]), gRadiosInfo.radiosInfo[indexWTPRadioInfo].gWTPPhyInfo.radioID, gRadiosInfo.radiosInfo[indexWTPRadioInfo].gWTPPhyInfo.phyStandardValue)))
		{
			int i;
			for(i = 0; i <= k; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
			CW_FREE_OBJECT(msgElems);
			/* error will be handled by the caller */
			return CW_FALSE;	
		}
	}
	
	return CWAssembleMessage(messagesPtr,
				 fragmentsNumPtr,
				 PMTU,
				 seqNum,
				 CW_MSG_TYPE_VALUE_JOIN_REQUEST,
				 msgElems,
				 msgElemCount,
				 msgElemsBinding,
				 msgElemBindingCount,
#ifdef CW_NO_DTLS
				 CW_PACKET_PLAIN
#else
				 CW_PACKET_CRYPT
#endif
				 );
}


/* 
 * Parse Join Response and return informations in *valuesPtr.
 */
CWBool CWParseJoinResponseMessage(char *msg,
				  int len,
				  int seqNum,
				  CWProtocolJoinResponseValues *valuesPtr) {

	CWControlHeaderValues 	controlVal;
	CWProtocolMessage 	completeMsg;
	int 			offsetTillMessages;
	char tmp_ABGNTypes;
	if (msg == NULL || valuesPtr == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Parsing Join Response...");
	
	completeMsg.msg = msg;
	completeMsg.offset = 0;
	
	/* error will be handled by the caller */
	if(!(CWParseControlHeader(&completeMsg, &controlVal))) return CW_FALSE;

	if(controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_JOIN_RESPONSE)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, 
				    "Message is not Join Response as Expected");
	
	if(controlVal.seqNum != seqNum) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
				    "Different Sequence Number");
	
	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;
	
	offsetTillMessages = completeMsg.offset;

	/* Mauro */
	valuesPtr->ACInfoPtr.IPv4AddressesCount = 0;
	valuesPtr->ACInfoPtr.IPv6AddressesCount = 0;

	/* parse message elements */
	while((completeMsg.offset-offsetTillMessages) < controlVal.msgElemsLen) {
		unsigned short int type=0;
		unsigned short int len=0;
		
		CWParseFormatMsgElem(&completeMsg,&type,&len);		

	//	CWDebugLog("Parsing Message Element: %u, len: %u", type, len);
		/*
		valuesPtr->ACInfoPtr.IPv4AddressesCount = 0;
		valuesPtr->ACInfoPtr.IPv6AddressesCount = 0;
		*/
		valuesPtr->ACIPv4ListInfo.ACIPv4ListCount=0;
		valuesPtr->ACIPv4ListInfo.ACIPv4List=NULL;
		valuesPtr->ACIPv6ListInfo.ACIPv6ListCount=0;
		valuesPtr->ACIPv6ListInfo.ACIPv6List=NULL;
	
		switch(type) {
			case CW_MSG_ELEMENT_AC_DESCRIPTOR_CW_TYPE:
				/* will be handled by the caller */
				if(!(CWParseACDescriptor(&completeMsg, len, &(valuesPtr->ACInfoPtr)))) return CW_FALSE;
				break;
			case CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE:
				/* will be handled by the caller */
				if(!CWParseWTPRadioInformation_FromAC(&completeMsg, len, &tmp_ABGNTypes)) return CW_FALSE;
				break;
			case CW_MSG_ELEMENT_AC_IPV4_LIST_CW_TYPE:
				if(!(CWParseACIPv4List(&completeMsg, len, &(valuesPtr->ACIPv4ListInfo)))) return CW_FALSE;
				break;
			case CW_MSG_ELEMENT_AC_IPV6_LIST_CW_TYPE:
				if(!(CWParseACIPv6List(&completeMsg, len, &(valuesPtr->ACIPv6ListInfo)))) return CW_FALSE;
				break;
			case CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE:
				if(!(CWParseResultCode(&completeMsg, len, &(valuesPtr->code)))) return CW_FALSE;
				break;
			case CW_MSG_ELEMENT_AC_NAME_CW_TYPE:
				/* will be handled by the caller */
				if(!(CWParseACName(&completeMsg, len, &(valuesPtr->ACInfoPtr.name)))) return CW_FALSE;
				break;
			case CW_MSG_ELEMENT_LOCAL_IPV4_ADDRESS_CW_TYPE:
				/*
				 * Elena Agostini - 03/2014: Add AC local IPv4 Address Msg. Elem.
				 */
				//valuesPtr->ACInfoPtr.IPv4AddressesCount++;
				completeMsg.offset += len;
				break;
			case CW_MSG_ELEMENT_CW_CONTROL_IPV4_ADDRESS_CW_TYPE:
				/* 
				 * just count how many interfacess we
				 * have, so we can allocate the array 
				 */
				valuesPtr->ACInfoPtr.IPv4AddressesCount++;
				completeMsg.offset += len;
				break;
			case CW_MSG_ELEMENT_CW_CONTROL_IPV6_ADDRESS_CW_TYPE:
				/* 
				 * just count how many interfacess we
				 * have, so we can allocate the array 
				 */
				valuesPtr->ACInfoPtr.IPv6AddressesCount++;
				completeMsg.offset += len;
				break;
			/*
			 * Elena Agostini - 02/2014
		 	 *
		 	 * ECN Support Msg Elem MUST be included in Join Request/Response Messages
		 	 */
			case CW_MSG_ELEMENT_ECN_SUPPORT_CW_TYPE:
				if(!(CWParseACECNSupport(&completeMsg, len, &(valuesPtr->ECNSupport))))
					/* will be handled by the caller */
					return CW_FALSE;
				break;
 			/*
 			case CW_MSG_ELEMENT_SESSION_ID_CW_TYPE:
 				if(!(CWParseSessionID(&completeMsg, len, valuesPtr))) return CW_FALSE;
 				break;	
 			*/
			default:
				return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
		}

		/* CWDebugLog("bytes: %d/%d", (completeMsg.offset-offsetTillMessages), controlVal.msgElemsLen); */
	}
	
	if(completeMsg.offset != len) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, 
				    "Garbage at the End of the Message");
	
	/* actually read each interface info */
	CW_CREATE_ARRAY_ERR(valuesPtr->ACInfoPtr.IPv4Addresses, 
			    valuesPtr->ACInfoPtr.IPv4AddressesCount,
			    CWProtocolIPv4NetworkInterface,
			    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	if(valuesPtr->ACInfoPtr.IPv6AddressesCount > 0) {

		CW_CREATE_ARRAY_ERR(valuesPtr->ACInfoPtr.IPv6Addresses,
				    valuesPtr->ACInfoPtr.IPv6AddressesCount,
				    CWProtocolIPv6NetworkInterface,
				    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}

	int i = 0;
	int j = 0;
	
	completeMsg.offset = offsetTillMessages;
	while((completeMsg.offset-offsetTillMessages) < controlVal.msgElemsLen) {
		unsigned short int type=0;	/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int len=0;	/* = CWProtocolRetrieve16(&completeMsg); */
		
		CWParseFormatMsgElem(&completeMsg,&type,&len);		
		
		switch(type) {
			case CW_MSG_ELEMENT_CW_CONTROL_IPV4_ADDRESS_CW_TYPE:
				/* will be handled by the caller */
				if(!(CWParseCWControlIPv4Addresses(&completeMsg, 
								   len,
								   &(valuesPtr->ACInfoPtr.IPv4Addresses[i]))))
				       	return CW_FALSE;
				i++;
				break;
			case CW_MSG_ELEMENT_CW_CONTROL_IPV6_ADDRESS_CW_TYPE:
				/* will be handled by the caller */
				if(!(CWParseCWControlIPv6Addresses(&completeMsg,
								   len,
								   &(valuesPtr->ACInfoPtr.IPv6Addresses[j]))))
					return CW_FALSE;
				j++;
				break;
			default:
				completeMsg.offset += len;
				break;
		}
	}

	return CW_TRUE;
}

CWBool CWSaveJoinResponseMessage(CWProtocolJoinResponseValues *joinResponse) {

   if(joinResponse == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

   if((joinResponse->code == CW_PROTOCOL_SUCCESS) ||
      (joinResponse->code == CW_PROTOCOL_SUCCESS_NAT)) {

	if(gACInfoPtr == NULL) 
		return CWErrorRaise(CW_ERROR_NEED_RESOURCE, NULL);
	
	gACInfoPtr->stations = (joinResponse->ACInfoPtr).stations;
	gACInfoPtr->limit = (joinResponse->ACInfoPtr).limit;
	gACInfoPtr->activeWTPs = (joinResponse->ACInfoPtr).activeWTPs;
	gACInfoPtr->maxWTPs = (joinResponse->ACInfoPtr).maxWTPs;
	gACInfoPtr->security = (joinResponse->ACInfoPtr).security;
	gACInfoPtr->RMACField = (joinResponse->ACInfoPtr).RMACField;

	/*
	 * Elena Agostini - 02/2014
	 *
	 * If gWTPForceACAddress is NOT NULL and WTP jump Discovery state, 
	 * object gACInfoPtr hasn't all the information. If gACInfoPtr->name is NULL,
	 * Configure State will get a Segmentation Fault.
	 */
	CW_CREATE_STRING_FROM_STRING_ERR((gACInfoPtr->name), ((joinResponse->ACInfoPtr).name), return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	/*
	 * Elena Agostini - 02/2014
	 *
	 * If gWTPForceACAddress is NOT NULL and WTP jump Discovery state, 
	 * object gACInfoPtr hasn't all the information. gACInfoPtr->vendorInfos
	 * wasn't initialized.
	 */
	if(gWTPForceACAddress == NULL) {
		/* BUG-ML07
		 * Before overwriting the field vendorInfos we'd better
		 * free it (it was allocated during the Discovery State by
		 * the function CWParseACDescriptor()).
		 *
		 * 19/10/2009 - Donato Capitella
		 */
		int i;
		for(i = 0; i < gACInfoPtr->vendorInfos.vendorInfosCount; i++) {
		        CW_FREE_OBJECT(gACInfoPtr->vendorInfos.vendorInfos[i].valuePtr);
		}
		CW_FREE_OBJECT(gACInfoPtr->vendorInfos.vendorInfos);
	}

	gACInfoPtr->vendorInfos = (joinResponse->ACInfoPtr).vendorInfos;
	
	if(joinResponse->ACIPv4ListInfo.ACIPv4ListCount >0) {

		gACInfoPtr->ACIPv4ListInfo.ACIPv4ListCount = joinResponse->ACIPv4ListInfo.ACIPv4ListCount; 
		gACInfoPtr->ACIPv4ListInfo.ACIPv4List = joinResponse->ACIPv4ListInfo.ACIPv4List; 
	}
	
	if(joinResponse->ACIPv6ListInfo.ACIPv6ListCount >0) {

		gACInfoPtr->ACIPv6ListInfo.ACIPv6ListCount = joinResponse->ACIPv6ListInfo.ACIPv6ListCount; 
		gACInfoPtr->ACIPv6ListInfo.ACIPv6List = joinResponse->ACIPv6ListInfo.ACIPv6List; 
	}
	
	/* 
         * This field name was allocated for storing the AC name; however, it
         * doesn't seem to be used and it is certainly lost when we exit
         * CWWTPEnterJoin() as joinResponse is actually a local variable of that
         * function.
         *
         * Thus, it seems good to free it now.   
         * 
         * BUG ML03  
         * 16/10/2009 - Donato Capitella
         */
        CW_FREE_OBJECT(joinResponse->ACInfoPtr.name);
        /* BUG ML08 */
        CW_FREE_OBJECT(joinResponse->ACInfoPtr.IPv4Addresses);

	CWDebugLog("Join Response Saved");	
	return CW_TRUE;
   }
   else {
	   CWDebugLog("Join Response said \"Failure\"");
	   return CW_FALSE;
  }
}
