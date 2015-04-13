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
 *											   *
 * --------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                        *
 *                                                                                         *
 * Author :  Ludovico Rossi (ludo@bluepixysw.com)                                          *  
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                    *
 *           Giovannini Federica (giovannini.federica@gmail.com)                           *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                    *
 *           Mauro Bisson (mauro.bis@gmail.com)                                            *
 *******************************************************************************************/

 
#include "CWAC.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

CWBool CWAssembleJoinResponse(CWProtocolMessage **messagesPtr,
			      int *fragmentsNumPtr,
			      int PMTU,
			      int seqNum,
			      CWList msgElemList,
			      CWWTPProtocolManager *WTPProtocolManager);

CWBool CWParseJoinRequestMessage(char *msg,
				 int len,
				 int *seqNumPtr,
				 CWProtocolJoinRequestValues *valuesPtr);

CWBool CWSaveJoinRequestMessage(CWProtocolJoinRequestValues *joinRequest,
				CWWTPProtocolManager *WTPProtocolManager);


CWBool ACEnterJoin(int WTPIndex, CWProtocolMessage *msgPtr)
{	
	int seqNum;
	CWProtocolJoinRequestValues joinRequest;
	CWList msgElemList = NULL;
	
	CWLog("\n");
	CWLog("######### Join State #########");	

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	if(!(CWParseJoinRequestMessage(msgPtr->msg, msgPtr->offset, &seqNum, &joinRequest))) {
		/* note: we can kill our thread in case of out-of-memory 
		 * error to free some space.
		 * we can see this just calling CWErrorGetLastErrorCode()
		 */
		return CW_FALSE;
	}

	// cancel waitJoin timer
	if(!CWTimerCancel(&(gWTPs[WTPIndex].currentTimer)))
	{
		return CW_FALSE;
	}

	CWBool ACIpv4List = CW_FALSE;
	CWBool ACIpv6List = CW_FALSE;
	CWBool resultCode = CW_TRUE;
	int resultCodeValue = CW_PROTOCOL_SUCCESS;
	/* CWBool sessionID = CW_FALSE; */

	//Elena Agostini - 07/2014: nl80211 support
	if(!(CWSaveJoinRequestMessage(&joinRequest, &(gWTPs[WTPIndex].WTPProtocolManager)))) {

		resultCodeValue = CW_PROTOCOL_FAILURE_RES_DEPLETION;
	}
	
	CWMsgElemData *auxData;
	if(ACIpv4List) {
		CW_CREATE_OBJECT_ERR(auxData, CWMsgElemData, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
                auxData->type = CW_MSG_ELEMENT_AC_IPV4_LIST_CW_TYPE;
		auxData->value = 0;
		CWAddElementToList(&msgElemList,auxData);
	}
	if(ACIpv6List){
		CW_CREATE_OBJECT_ERR(auxData, CWMsgElemData, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
                auxData->type = CW_MSG_ELEMENT_AC_IPV6_LIST_CW_TYPE;
                auxData->value = 0;
                CWAddElementToList(&msgElemList,auxData);
	}
	if(resultCode){
		CW_CREATE_OBJECT_ERR(auxData, CWMsgElemData, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
                auxData->type =  CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE;
                auxData->value = resultCodeValue;
                CWAddElementToList(&msgElemList,auxData);
	}
	
	/*
 	if(sessionID){
 		CW_CREATE_OBJECT_ERR(auxData, CWMsgElemData, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
                 auxData->type =  CW_MSG_ELEMENT_SESSION_ID_CW_TYPE;
                 auxData->value = CWRandomIntInRange(0, INT_MAX);
                 CWAddElementToList(&msgElemList,auxData);
 	}
 	*/

	/* random session ID */
	if(!(CWAssembleJoinResponse(&(gWTPs[WTPIndex].messages),
				    &(gWTPs[WTPIndex].messagesCount),
				    gWTPs[WTPIndex].pathMTU,
				    seqNum,
				    msgElemList,
				    &(gWTPs[WTPIndex].WTPProtocolManager)))){

		CWDeleteList(&msgElemList, CWProtocolDestroyMsgElemData);
		return CW_FALSE;
	}
	
	CWDeleteList(&msgElemList, CWProtocolDestroyMsgElemData);
	
	if(!CWACSendFragments(WTPIndex)) {
		return CW_FALSE;
 	}

	gWTPs[WTPIndex].currentState = CW_ENTER_CONFIGURE;
	
	return CW_TRUE;
}

/*
 * Assemble Join Response.
 */
CWBool CWAssembleJoinResponse(CWProtocolMessage **messagesPtr,
			      int *fragmentsNumPtr,
			      int PMTU,
			      int seqNum,
			      CWList msgElemList,
			      CWWTPProtocolManager *WTPProtocolManager) {

	CWProtocolMessage *msgElems= NULL;
	int msgElemCount = 0;
	/* Result code is not included because it's already
	 * in msgElemList. Control IPv6 to be added.
	 */
	const int mandatoryMsgElemCount=6;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	int i;
	CWListElement *current;
	int k = -1;
	
	if(messagesPtr == NULL || fragmentsNumPtr == NULL || msgElemList == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	msgElemCount = CWCountElementInList(msgElemList);

	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems,
					 msgElemCount + mandatoryMsgElemCount,
					 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	CWDebugLog("Assembling Join Response...");
	
	if(
	   (!(CWAssembleMsgElemACDescriptor(&(msgElems[++k])))) ||
	   (!(CWAssembleMsgElemACName(&(msgElems[++k])))) ||
		/*
		 * Elena Agostini - 02/2014
	 	 *
	 	 * ECN Support Msg Elem MUST be included in Join Request/Response Messages
	 	 */
	     (!(CWAssembleMsgElemECNSupport(&(msgElems[++k])))) ||

		/*
		 * Elena Agostini - 03/2014: Add AC local IPv4 Address Msg. Elem.
		 */
		(!(CWAssembleMsgElemCWLocalIPv4Addresses(&(msgElems[++k])))) ||

	   (!(CWAssembleMsgElemCWControlIPv4Addresses(&(msgElems[++k]))))
	) {
		CWErrorHandleLast();
		int i;
		for(i = 0; i <= k; i++) {CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
		CW_FREE_OBJECT(msgElems);
		/* error will be handled by the caller */
		return CW_FALSE;
	} 
		
	//Elena Agostini - 07/2014: wtp radio info replay
	int indexWTPRadio;
	unsigned char phyStandardValue;
	for(indexWTPRadio=0; indexWTPRadio< WTPProtocolManager->radiosInfo.radioCount; indexWTPRadio++) {
		
		if(!(CWAssembleMsgElemACWTPRadioInformation(&(msgElems[++k]), 
													WTPProtocolManager->radiosInfo.radiosInfo[indexWTPRadio].gWTPPhyInfo.radioID, 
													WTPProtocolManager->radiosInfo.radiosInfo[indexWTPRadio].gWTPPhyInfo.phyStandardValue))
		)
		{
			CWErrorHandleLast();
			int i;
			for(i = 0; i <= k; i++) {CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
			CW_FREE_OBJECT(msgElems);
			return CW_FALSE; // error will be handled by the caller
		}
	}
		
	current=msgElemList;
	for (i=0; i<msgElemCount; i++) {

                switch (((CWMsgElemData *) (current->data))->type) {

			case CW_MSG_ELEMENT_AC_IPV4_LIST_CW_TYPE:
				if (!(CWAssembleMsgElemACIPv4List(&(msgElems[++k]))))
					goto cw_assemble_error;	
				break;			
			case CW_MSG_ELEMENT_AC_IPV6_LIST_CW_TYPE:
				if (!(CWAssembleMsgElemACIPv6List(&(msgElems[++k]))))
					goto cw_assemble_error;
				break;
			case CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE:
				if (!(CWAssembleMsgElemResultCode(&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
					goto cw_assemble_error;
				break;
			/*
			case CW_MSG_ELEMENT_SESSION_ID_CW_TYPE:
				if (!(CWAssembleMsgElemSessionID(&(msgElems[++k]), ((CWMsgElemData *) current->data)->value)))
					goto cw_assemble_error;
				break;
			*/
                        default: {
                                int j;
                                for(j = 0; j <= k; j++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[j]);}
                                CW_FREE_OBJECT(msgElems);
                                return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element for Join Response Message");
				break;
		        }
                }
		current = current->next;
	}

	if (!(CWAssembleMessage(messagesPtr,
				fragmentsNumPtr,
				PMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_JOIN_RESPONSE,
				msgElems,
				msgElemCount + mandatoryMsgElemCount,
				msgElemsBinding,
				msgElemBindingCount,
#ifdef CW_NO_DTLS
				CW_PACKET_PLAIN)))
#else
 				CW_PACKET_CRYPT)))
#endif
		return CW_FALSE;

	CWDebugLog("Join Response Assembled");
	
	return CW_TRUE;

cw_assemble_error:
	{
		int i;
		for(i = 0; i <= k; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
		CW_FREE_OBJECT(msgElems);
		/* error will be handled by the caller */
		return CW_FALSE;
	}
	return CW_TRUE;
}

/* 
 * Parses Join Request.
 */
CWBool CWParseJoinRequestMessage(char *msg,
				 int len,
				 int *seqNumPtr,
				 CWProtocolJoinRequestValues *valuesPtr) {

	CWControlHeaderValues controlVal;
	int offsetTillMessages;
	CWProtocolMessage completeMsg;
	char RadioInfoABGN;
	
	if(msg == NULL || seqNumPtr == NULL || valuesPtr == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Parse Join Request");
	
	completeMsg.msg = msg;
	completeMsg.offset = 0;

	//Elena Agostini: nl80211 support
	valuesPtr->tmpPhyInfo.numPhyActive=0;
	CW_CREATE_ARRAY_CALLOC_ERR(valuesPtr->tmpPhyInfo.singlePhyInfo, WTP_RADIO_MAX, WTPSinglePhyInfo, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	if(!(CWParseControlHeader(&completeMsg, &controlVal)))
		/* will be handled by the caller */
		return CW_FALSE;

	/* different type */
	if(controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_JOIN_REQUEST)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Join Request as Expected");
	
	*seqNumPtr = controlVal.seqNum;
	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;
	offsetTillMessages = completeMsg.offset;
	
	/* parse message elements */
	while((completeMsg.offset-offsetTillMessages) < controlVal.msgElemsLen) {

		unsigned short int elemType = 0;/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int elemLen =0 ;	/* = CWProtocolRetrieve16(&completeMsg); */
		
		CWParseFormatMsgElem(&completeMsg,&elemType,&elemLen);
		
//		CWLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);
									
		switch(elemType) {
			case CW_MSG_ELEMENT_LOCATION_DATA_CW_TYPE:
				if(!(CWParseLocationData(&completeMsg, elemLen, &(valuesPtr->location)))) 
					/* will be handled by the caller */
					return CW_FALSE;
				break;
				
			case CW_MSG_ELEMENT_WTP_BOARD_DATA_CW_TYPE:
				if(!(CWParseWTPBoardData(&completeMsg, elemLen, &(valuesPtr->WTPBoardData)))) 
					/* will be handled by the caller */
					return CW_FALSE;
				break; 
				
			case CW_MSG_ELEMENT_SESSION_ID_CW_TYPE:
				valuesPtr->sessionID  = CWParseSessionID(&completeMsg, elemLen);
				break;
				
			case CW_MSG_ELEMENT_WTP_DESCRIPTOR_CW_TYPE:
				if(!(CWParseWTPDescriptor(&completeMsg, elemLen, &(valuesPtr->WTPDescriptor))))
					/* will be handled by the caller */
					return CW_FALSE;
				break;
				
			case CW_MSG_ELEMENT_LOCAL_IPV4_ADDRESS_CW_TYPE:
				if(!(CWParseWTPIPv4Address(&completeMsg, elemLen, valuesPtr)))
					/* will be handled by the caller */
					return CW_FALSE;
				break;
				
			case CW_MSG_ELEMENT_WTP_NAME_CW_TYPE:
				if(!(CWParseWTPName(&completeMsg, elemLen, &(valuesPtr->name))))
					/* will be handled by the caller */
					return CW_FALSE;
				break;
				
			case CW_MSG_ELEMENT_WTP_FRAME_TUNNEL_MODE_CW_TYPE:
				if(!(CWParseWTPFrameTunnelMode(&completeMsg, elemLen, &(valuesPtr->frameTunnelMode))))
					/* will be handled by the caller */
					return CW_FALSE;
				break;
				
			case CW_MSG_ELEMENT_WTP_MAC_TYPE_CW_TYPE:
				if(!(CWParseWTPMACType(&completeMsg, elemLen, &(valuesPtr->MACType))))
					/* will be handled by the caller */
					return CW_FALSE;
				break;
			
			/*
			 * Elena Agostini - 08/2014: nl80211 support
		 	 */
			case CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE:
				if(valuesPtr->tmpPhyInfo.numPhyActive < WTP_RADIO_MAX)
					if(!(CWParseWTPRadioInformation(&completeMsg, 
													elemLen, 
													&(valuesPtr->tmpPhyInfo.singlePhyInfo[valuesPtr->tmpPhyInfo.numPhyActive].radioID),
													&(valuesPtr->tmpPhyInfo.singlePhyInfo[valuesPtr->tmpPhyInfo.numPhyActive].phyStandardValue)
													)
					))return CW_FALSE;
					valuesPtr->tmpPhyInfo.numPhyActive++;
				break;
			/*
			 * Elena Agostini - 02/2014: ECN Support Msg Elem MUST be included in Join Request/Response Messages
		 	 */
			case CW_MSG_ELEMENT_ECN_SUPPORT_CW_TYPE:
				if(!(CWParseWTPECNSupport(&completeMsg, elemLen, &(valuesPtr->ECNSupport))))
					/* will be handled by the caller */
					return CW_FALSE;
				break;
	
			default:
				completeMsg.offset += elemLen;
				CWLog("Unrecognized Message Element(%d) in Discovery response",elemType);
				break;
		}
		/*CWDebugLog("bytes: %d/%d", (completeMsg.offset-offsetTillMessages), controlVal.msgElemsLen);*/
	}

	if (completeMsg.offset != len) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");
		
	return CW_TRUE;
}

CWBool CWSaveJoinRequestMessage(CWProtocolJoinRequestValues *joinRequest,
				CWWTPProtocolManager *WTPProtocolManager) {

	CWDebugLog("Saving Join Request...");
	
	if(joinRequest == NULL || WTPProtocolManager == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	if ((joinRequest->location)!= NULL) {

		CW_FREE_OBJECT(WTPProtocolManager->locationData);
		WTPProtocolManager->locationData= joinRequest->location;
	}
	else 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	if ((joinRequest->name)!= NULL) {

		CW_FREE_OBJECT(WTPProtocolManager->name);
		WTPProtocolManager->name= joinRequest->name;
	}
	else 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
		
	CW_FREE_OBJECT((WTPProtocolManager->WTPBoardData).vendorInfos);
	WTPProtocolManager->WTPBoardData = joinRequest->WTPBoardData;

	/*
	 * Elena Agostini - 04/2014: SessionID string wasn't saved in right way
	 */
	 CW_CREATE_ARRAY_ERR(WTPProtocolManager->sessionID, WTP_SESSIONID_LENGTH, unsigned char, return;);
	 memcpy(WTPProtocolManager->sessionID, joinRequest->sessionID, WTP_SESSIONID_LENGTH);
	//CW_CREATE_STRING_FROM_STRING_ERR(WTPProtocolManager->sessionID, joinRequest->sessionID, {return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);});

	WTPProtocolManager->ipv4Address= joinRequest->addr;
	
	WTPProtocolManager->descriptor= joinRequest->WTPDescriptor;
	WTPProtocolManager->radiosInfo.radioCount = (joinRequest->WTPDescriptor).radiosInUse;
	CW_FREE_OBJECT(WTPProtocolManager->radiosInfo.radiosInfo);

	CW_CREATE_ARRAY_ERR(WTPProtocolManager->radiosInfo.radiosInfo, 
			    WTPProtocolManager->radiosInfo.radioCount, 
			    CWWTPRadioInfoValues,
			    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	int i, indexWlan;
	for(i=0; i< WTPProtocolManager->radiosInfo.radioCount; i++) {
		//Elena Agostini: per ora vengono salvati solo WTP_RADIO_MAX (ACNL80211.h) message elements dal join request.
		//Si dovranno trovare altre soluzioni quando si lavorerà al management
		if(i >= WTP_RADIO_MAX) continue;
		/*WTPProtocolManager->radiosInfo.radiosInfo[i].stationCount = 0;*/
		/* default value for CAPWAP */
        WTPProtocolManager->radiosInfo.radiosInfo[i].adminState = ENABLED;
        WTPProtocolManager->radiosInfo.radiosInfo[i].adminCause = AD_NORMAL;
        WTPProtocolManager->radiosInfo.radiosInfo[i].operationalState = DISABLED;
        WTPProtocolManager->radiosInfo.radiosInfo[i].operationalCause = OP_NORMAL;
        WTPProtocolManager->radiosInfo.radiosInfo[i].TxQueueLevel = 0;
        WTPProtocolManager->radiosInfo.radiosInfo[i].wirelessLinkFramesPerSec = 0;
        //Duplicate
        WTPProtocolManager->radiosInfo.radiosInfo[i].radioID = CWIEEEBindingGetIndexFromDevID(joinRequest->tmpPhyInfo.singlePhyInfo[i].radioID);
        WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.radioID = joinRequest->tmpPhyInfo.singlePhyInfo[i].radioID;
        
		//802.11a/b/g/n total value
		WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyStandardValue = PHY_NO_STANDARD;
        if( (joinRequest->tmpPhyInfo.singlePhyInfo[i].phyStandardValue & 0x1) == PHY_STANDARD_B)
        {
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyStandardB=CW_TRUE;
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyStandardValue += PHY_STANDARD_B;
		}
		else
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyStandardB=CW_FALSE;
			
		if( (joinRequest->tmpPhyInfo.singlePhyInfo[i].phyStandardValue & 0x2) == PHY_STANDARD_A)
		{
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyStandardA=CW_TRUE;
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyStandardValue += PHY_STANDARD_A;
		}
		else
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyStandardA=CW_FALSE;
		
		if( (joinRequest->tmpPhyInfo.singlePhyInfo[i].phyStandardValue & 0x4) == PHY_STANDARD_G)
		{
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyStandardG=CW_TRUE;
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyStandardValue += PHY_STANDARD_G;
		}
		else
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyStandardG=CW_FALSE;
		
		if( (joinRequest->tmpPhyInfo.singlePhyInfo[i].phyStandardValue & 0x8) == PHY_STANDARD_N)
		{
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyStandardN=CW_TRUE;
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyStandardValue += PHY_STANDARD_N;
		}
		else
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyStandardN=CW_FALSE;
		
		WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.numInterfaces=0;
		
		//Set all interface WTP_MAX_INTERFACES in STA mode
		for(indexWlan=0; indexWlan < WTP_MAX_INTERFACES; indexWlan++)
		{
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.interfaces[indexWlan].typeInterface = CW_STA_MODE;
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.interfaces[indexWlan].BSSID = NULL;
			WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.interfaces[indexWlan].wlanID = CWIEEEBindingGetDevFromIndexID(indexWlan);
			if ((joinRequest->frameTunnelMode)!= NULL)
				WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.interfaces[indexWlan].frameTunnelMode=joinRequest->frameTunnelMode;
			else 
				WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.interfaces[indexWlan].frameTunnelMode=0;
		}
	}
	CWDebugLog("Join Request Saved");
	return CW_TRUE;
}
