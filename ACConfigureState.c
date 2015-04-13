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
 *                                                                                         *
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

int gCWChangeStatePendingTimer = CW_CHANGE_STATE_INTERVAL_DEFAULT;

CWBool CWAssembleConfigureResponse(CWProtocolMessage **messagesPtr,
				   int *fragmentsNumPtr,
				   int PMTU,
				   int seqNum);

CWBool CWParseConfigureRequestMessage(char *msg,
				      int len,
				      int *seqNumPtr,
				      CWProtocolConfigureRequestValues *valuesPtr, char*, char*);

CWBool CWSaveConfigureRequestMessage(CWProtocolConfigureRequestValues *configureRequest,
				     CWWTPProtocolManager *WTPProtocolManager);


CWBool ACEnterConfigure(int WTPIndex, CWProtocolMessage *msgPtr) {

	/*** tmp Radio Info ***/
	char tmp_RadioInformationABGN;
	char tmp_SuppRates[8];
	char tmp_MultiDomCapa[6];
	

	int seqNum;
	CWProtocolConfigureRequestValues configureRequest;
	
	CWLog("\n");
	CWLog("######### Configure State #########");	
	 	
	if(!(CWParseConfigureRequestMessage(msgPtr->msg, 
										msgPtr->offset, 
										&seqNum, 
										&configureRequest,
										&tmp_RadioInformationABGN,
										tmp_MultiDomCapa))) {
		/* note: we can kill our thread in case of out-of-memory 
		 * error to free some space.
		 * we can see this just calling CWErrorGetLastErrorCode()
		 */
		return CW_FALSE;
	}

	CWLog("Configure Request Received");
	
	if(!(CWSaveConfigureRequestMessage(&configureRequest, &(gWTPs[WTPIndex].WTPProtocolManager)))){
		return CW_FALSE;
	}
	
	
	//Elena Agostini note: useless?
	/* Store Radio Info in gWTPs */
	gWTPs[WTPIndex].RadioInformationABGN = tmp_RadioInformationABGN;
	memcpy( gWTPs[WTPIndex].SuppRates, tmp_SuppRates, 8 );
	memcpy( gWTPs[WTPIndex].MultiDomCapa, tmp_MultiDomCapa, 6);
	
	/* Store Radio Info in gWTPs */
	
	
	if(!(CWAssembleConfigureResponse(&(gWTPs[WTPIndex].messages), 
					 &(gWTPs[WTPIndex].messagesCount), 
					 gWTPs[WTPIndex].pathMTU, 
					 seqNum)))  { 
		return CW_FALSE;
	}
	
	if(!CWACSendFragments(WTPIndex)) {
		return CW_FALSE;
	}
	
	CWLog("Configure Response Sent");
	
	/* start Change State Pending timer */
	if(!CWErr(CWTimerRequest(gCWChangeStatePendingTimer,
				 &(gWTPs[WTPIndex].thread),
				 &(gWTPs[WTPIndex].currentTimer),
				 CW_CRITICAL_TIMER_EXPIRED_SIGNAL))) {

		CWCloseThread();
	}
	
	/* Elena Agostini: 09/2014 IEEE 802.11 Binding */
/*	if(!ACEnterIEEEConfiguration(WTPIndex, NULL))
		return CW_FALSE;
		
	gWTPs[WTPIndex].currentState = CW_ENTER_IEEEE_CONFIGURATION;
*/
	gWTPs[WTPIndex].currentState = CW_ENTER_DATA_CHECK;
	return CW_TRUE;
}

CWBool CWParseConfigureRequestMessage(char *msg,
				      int len,
				      int *seqNumPtr,
				      CWProtocolConfigureRequestValues *valuesPtr,
				      char *tmp_RadioInformationABGN,
				      char *tmp_MultiDomCapa) {

	CWControlHeaderValues controlVal;
	int i,j;
	int offsetTillMessages;
	char * tmpSuppRates;
	int radioID, rateLen, indexRadio;
	
	CWProtocolMessage completeMsg;
	
	if(msg == NULL || seqNumPtr == NULL || valuesPtr == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Parsing Configure Request...");
	
	//Elena Agostini: nl80211 support
	valuesPtr->tmpPhyInfo.numPhyActive=0;
	CW_CREATE_ARRAY_CALLOC_ERR(valuesPtr->tmpPhyInfo.singlePhyInfo, WTP_RADIO_MAX, WTPSinglePhyInfo, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	CW_CREATE_ARRAY_CALLOC_ERR(valuesPtr->phyFrequencyInfo, WTP_RADIO_MAX, PhyFrequencyInfoConfigureMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	valuesPtr->numPhyFrequencyInfo=0;
	
	completeMsg.msg = msg;
	completeMsg.offset = 0;
	
	if(!(CWParseControlHeader(&completeMsg, &controlVal))) 
		/* will be handled by the caller */
		return CW_FALSE;

	/* different type */
	if(controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_CONFIGURE_REQUEST)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Configure Request (maybe it is Image Data Request)");
	
	*seqNumPtr = controlVal.seqNum;
	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;
	
	offsetTillMessages = completeMsg.offset;
	
	/* valuesPtr->WTPRadioInfo.radiosCount=0; */
	valuesPtr->ACinWTP.count=0;
	valuesPtr->radioAdminInfoCount=0;
	
	/* parse message elements */
	while((completeMsg.offset-offsetTillMessages) < controlVal.msgElemsLen) {
	
		unsigned short int elemType = 0;/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int elemLen = 0;	/* = CWProtocolRetrieve16(&completeMsg); */
		
		CWParseFormatMsgElem(&completeMsg,&elemType,&elemLen);		

		/*CWDebugLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);*/
									
		switch(elemType) {
			case CW_MSG_ELEMENT_AC_NAME_CW_TYPE:
				if(!(CWParseACName(&completeMsg, elemLen, &(valuesPtr->ACName)))) 
					/* will be handled by the caller */
					return CW_FALSE;
				break;
			case CW_MSG_ELEMENT_AC_NAME_INDEX_CW_TYPE:
				/* just count how many radios we have,
				 * so we can allocate the array
				 */
				valuesPtr->ACinWTP.count++;
				completeMsg.offset += elemLen;
				break;			
			case CW_MSG_ELEMENT_RADIO_ADMIN_STATE_CW_TYPE:
				/* just count how many radios we have,
				 * so we can allocate the array
				 */
				(valuesPtr->radioAdminInfoCount)++;
				completeMsg.offset += elemLen;
				break;
			case CW_MSG_ELEMENT_STATISTICS_TIMER_CW_TYPE:
				if(!(CWParseWTPStatisticsTimer(&completeMsg, elemLen, &(valuesPtr->StatisticsTimer)))) 
					/* will be handled by the caller */
					return CW_FALSE;
				break;
			case CW_MSG_ELEMENT_WTP_REBOOT_STATISTICS_CW_TYPE:
				CW_CREATE_OBJECT_ERR(valuesPtr->WTPRebootStatistics,
						     WTPRebootStatisticsInfo,
						     return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				if(!(CWParseWTPRebootStatistics(&completeMsg,
								elemLen,
								valuesPtr->WTPRebootStatistics))) 
					/* will be handled by the caller */
					return CW_FALSE;
				break;
			
			case CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE:
				/*
				 * Elena Agostini: I'm not going to save again those values
				 * I've already saved in join state those values and in this momento there isn't an AC logic managment
				*/
				if(valuesPtr->tmpPhyInfo.numPhyActive < WTP_RADIO_MAX)
					if(!(CWParseWTPRadioInformation(&completeMsg, 
													elemLen, 
													&(valuesPtr->tmpPhyInfo.singlePhyInfo[valuesPtr->tmpPhyInfo.numPhyActive].radioID),
													&(valuesPtr->tmpPhyInfo.singlePhyInfo[valuesPtr->tmpPhyInfo.numPhyActive].phyStandardValue)
													)
					))return CW_FALSE;
					valuesPtr->tmpPhyInfo.numPhyActive++;
				break;
				
			case CW_MSG_ELEMENT_IEEE80211_MULTI_DOMAIN_CAPABILITY_CW_TYPE:
				
				if(valuesPtr->numPhyFrequencyInfo < WTP_RADIO_MAX)
					if(!(CWParseWTPMultiDomainCapability(&completeMsg, 
													elemLen, 
													&(valuesPtr->phyFrequencyInfo[valuesPtr->numPhyFrequencyInfo])
													)
					))
						return CW_FALSE;
					
					valuesPtr->numPhyFrequencyInfo++;
				
				break;
			//Elena Agostini: TODO. Without AC logic, save these values is useless
			case CW_MSG_ELEMENT_IEEE80211_MAC_OPERATION_CW_TYPE:
				completeMsg.offset += elemLen;
				break;
			
			case CW_MSG_ELEMENT_IEEE80211_SUPPORTED_RATES_CW_TYPE:
				
				CW_CREATE_ARRAY_CALLOC_ERR(tmpSuppRates, CW_80211_MAX_SUPP_RATES, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				if(!(CWParseWTPSupportedRates(&completeMsg, elemLen, &(radioID), &(tmpSuppRates), &(rateLen))))
					break;	
				
				indexRadio = CWIEEEBindingGetIndexFromDevID(radioID);
				valuesPtr->phyFrequencyInfo[indexRadio].lenSupportedRates = rateLen;
				CW_CREATE_ARRAY_CALLOC_ERR(valuesPtr->phyFrequencyInfo[indexRadio].supportedRates, rateLen+1, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				CW_COPY_MEMORY(valuesPtr->phyFrequencyInfo[indexRadio].supportedRates, tmpSuppRates, rateLen);
	
				break;
				
			default:
				return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
		}
	}
	
	if(completeMsg.offset != len) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");
	
	/* actually read each radio info */
	CW_CREATE_ARRAY_ERR((valuesPtr->ACinWTP).ACNameIndex, 
			    (valuesPtr->ACinWTP).count,
			    CWACNameWithIndexValues, 
			    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		
	CW_CREATE_ARRAY_ERR(valuesPtr->radioAdminInfo,
			    valuesPtr->radioAdminInfoCount,
			    CWRadioAdminInfoValues,
			    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	i = 0;
	j = 0;

	completeMsg.offset = offsetTillMessages;
	while(completeMsg.offset-offsetTillMessages < controlVal.msgElemsLen) {
		unsigned short int type=0;
		unsigned short int len=0;
		
		CWParseFormatMsgElem(&completeMsg,&type,&len);		

		switch(type) {
			case CW_MSG_ELEMENT_AC_NAME_INDEX_CW_TYPE:
				if(!(CWParseACNameWithIndex(&completeMsg, len, &(valuesPtr->ACinWTP.ACNameIndex[i])))) 
					/* will be handled by the caller */
					return CW_FALSE;
				i++;
				break;
			case CW_MSG_ELEMENT_RADIO_ADMIN_STATE_CW_TYPE:
				if(!(CWParseWTPRadioAdminState(&completeMsg, len, &(valuesPtr->radioAdminInfo[j]))))
					/* will be handled by the caller */
					return CW_FALSE;
				j++;
				break;
			default:
				completeMsg.offset += len;
				break;
		}
	}
	CWDebugLog("Configure Request Parsed");	
	return CW_TRUE;
}

CWBool CWAssembleConfigureResponse(CWProtocolMessage **messagesPtr,
				   int *fragmentsNumPtr,
				   int PMTU,
				   int seqNum) {

	CWProtocolMessage *msgElems = NULL;
	const int MsgElemCount=6;
	CWProtocolMessage *msgElemsBinding = NULL;
	int msgElemBindingCount=0;
	int k = -1;
	
	if(messagesPtr == NULL || fragmentsNumPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Assembling Configure Response...");
	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	/* Assemble Message Elements */
	if ((!(CWAssembleMsgElemACIPv4List(&(msgElems[++k])))) ||
	    (!(CWAssembleMsgElemACIPv6List(&(msgElems[++k])))) ||
	    (!(CWAssembleMsgElemCWTimer(&(msgElems[++k])))) ||
	    /*(!(CWAssembleMsgElemRadioOperationalState(-1, &(msgElems[++k])))) ||*/
	    (!(CWAssembleMsgElemDecryptErrorReportPeriod(&(msgElems[++k])))) ||
	    (!(CWAssembleMsgElemIdleTimeout(&(msgElems[++k])))) ||
	    (!(CWAssembleMsgElemWTPFallback(&(msgElems[++k]))))
	){
		int i;
		for(i = 0; i <= k; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
		CW_FREE_OBJECT(msgElems);
		/* error will be handled by the caller */
		return CW_FALSE;
	}
	
	if(!CWBindingAssembleConfigureResponse(&msgElemsBinding, &msgElemBindingCount))
	{
		int i;
		for(i = 0; i <= MsgElemCount; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
		CW_FREE_OBJECT(msgElems);
		return CW_FALSE;
	}
	
	/*CWDebugLog("~~~~~ msg count: %d ", msgElemBindingCount);*/
	
	if(!(CWAssembleMessage(messagesPtr,
			       fragmentsNumPtr,
			       PMTU,
			       seqNum,
			       CW_MSG_TYPE_VALUE_CONFIGURE_RESPONSE,
			       msgElems,
			       MsgElemCount,
			       msgElemsBinding,
			       msgElemBindingCount,
#ifdef CW_NO_DTLS
			       CW_PACKET_PLAIN))) {
#else
			       CW_PACKET_CRYPT))) {
#endif
		return CW_FALSE;
	}
	
	CWDebugLog("Configure Response Assembled");
	return CW_TRUE;
}

CWBool CWSaveConfigureRequestMessage (CWProtocolConfigureRequestValues *configureRequest,
				      CWWTPProtocolManager *WTPProtocolManager) {

	CWDebugLog("Saving Configure Request...");
	
	CW_FREE_OBJECT(WTPProtocolManager->ACName);

	if((configureRequest->ACName) != NULL)
		WTPProtocolManager->ACName = configureRequest->ACName;
	
	CW_FREE_OBJECT((WTPProtocolManager->ACNameIndex).ACNameIndex);
	WTPProtocolManager->ACNameIndex = configureRequest->ACinWTP;
	
	CW_FREE_OBJECT((WTPProtocolManager->radioAdminInfo).radios);
	(WTPProtocolManager->radioAdminInfo).radiosCount = configureRequest->radioAdminInfoCount;
	(WTPProtocolManager->radioAdminInfo).radios = configureRequest->radioAdminInfo;
		
	WTPProtocolManager->StatisticsTimer = configureRequest->StatisticsTimer;
	
	/*	
	CW_FREE_OBJECT((WTPProtocolManager->WTPRadioInfo).radios);
	WTPProtocolManager->WTPRadioInfo = configureRequest->WTPRadioInfo;	
	*/

	CW_FREE_OBJECT(WTPProtocolManager->WTPRebootStatistics);
	WTPProtocolManager->WTPRebootStatistics = configureRequest->WTPRebootStatistics;
	
	/*
	 * Elena Agostini-08/2014: WTP Multi Domain Capability save info for each radio saved in Join State
	 */
	int i, j;
	for(i=0; i< configureRequest->numPhyFrequencyInfo; i++) {
		for(j=0; j< WTPProtocolManager->radiosInfo.radioCount; j++) {
			if(WTPProtocolManager->radiosInfo.radiosInfo[j].gWTPPhyInfo.radioID == configureRequest->phyFrequencyInfo[i].radioID)
			{
				WTPProtocolManager->radiosInfo.radiosInfo[j].gWTPPhyInfo.phyFrequencyInfo.totChannels = configureRequest->phyFrequencyInfo[i].totChannels;
				CW_CREATE_ARRAY_CALLOC_ERR(WTPProtocolManager->radiosInfo.radiosInfo[i].gWTPPhyInfo.phyFrequencyInfo.frequencyList, 1, PhyFrequencyInfoList, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				WTPProtocolManager->radiosInfo.radiosInfo[j].gWTPPhyInfo.phyFrequencyInfo.frequencyList[0].frequency = configureRequest->phyFrequencyInfo[i].firstChannel;
				WTPProtocolManager->radiosInfo.radiosInfo[j].gWTPPhyInfo.phyFrequencyInfo.frequencyList[0].maxTxPower = configureRequest->phyFrequencyInfo[i].maxTxPower;
				WTPProtocolManager->radiosInfo.radiosInfo[j].gWTPPhyInfo.lenSupportedRates = configureRequest->phyFrequencyInfo[i].lenSupportedRates;
				
				CW_CREATE_ARRAY_CALLOC_ERR(WTPProtocolManager->radiosInfo.radiosInfo[j].gWTPPhyInfo.supportedRates, configureRequest->phyFrequencyInfo[i].lenSupportedRates+1, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				CW_COPY_MEMORY(WTPProtocolManager->radiosInfo.radiosInfo[j].gWTPPhyInfo.supportedRates, configureRequest->phyFrequencyInfo[i].supportedRates, configureRequest->phyFrequencyInfo[i].lenSupportedRates);
				
				CWLog("Dentro CWSaveConfigureRequestMessage: %d - %d", WTPProtocolManager->radiosInfo.radiosInfo[j].gWTPPhyInfo.supportedRates[0], WTPProtocolManager->radiosInfo.radiosInfo[j].gWTPPhyInfo.supportedRates[7]);
				
				break;
			}
		}
	}

	CWDebugLog("Configure Request Saved");
	return CW_TRUE;
}
