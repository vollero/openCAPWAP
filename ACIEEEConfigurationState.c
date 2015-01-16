/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	IEEE Binding
 * 
 ***************************************/

#include "CWAC.h"
//#include "CWVendorPayloads.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

CWBool CWParseIEEEConfigurationResponseMessage(CWProtocolMessage *msgPtr,
				      int len,
				      int WTPIndex) {

	CWControlHeaderValues controlVal;
	int offsetTillMessages;
	CWProtocolMessage completeMsg;
	
	CWProtocolResultCode resultCode;
	int radioIDtmp, wlanIDtmp;
	char * bssIDTmp;
				
	if(msgPtr == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Parsing Configuration Response...");
	
	completeMsg.msg = msgPtr->msg;
	completeMsg.offset = 0;
	
	if(!(CWParseControlHeader(&completeMsg, &controlVal))) 
		/* will be handled by the caller */
		return CW_FALSE;

	/* different type */
	if(controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_WLAN_CONFIGURATION_RESPONSE)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Message is not Configuration Response (maybe it is Image Data Request)");
	
	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;	
	offsetTillMessages = completeMsg.offset;
	
	/* parse message elements */
	while((completeMsg.offset-offsetTillMessages) < controlVal.msgElemsLen) {
	
		unsigned short int elemType = 0;/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int elemLen = 0;	/* = CWProtocolRetrieve16(&completeMsg); */
		
		CWParseFormatMsgElem(&completeMsg,&elemType,&elemLen);		

//		CWLog("Parsing Message Element: %u, elemLen: %u", elemType, elemLen);
									
		switch(elemType) {
			case CW_MSG_ELEMENT_RESULT_CODE_CW_TYPE:
				if(!(CWParseResultCode(&completeMsg, elemLen, &(resultCode))))
					return CW_FALSE;
				if(resultCode != CW_PROTOCOL_SUCCESS)
						CWLog("ERROR IEEE 802.11 Configuration");
					else
						CWLog("OK IEEE 802.11 Configuration");
				break;
			case CW_MSG_ELEMENT_IEEE80211_ASSIGNED_WTP_BSSID_CW_TYPE:
				CW_CREATE_ARRAY_CALLOC_ERR(bssIDTmp, ETH_ALEN+1, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				if(!(CWParseACAssignedWTPBSSID(WTPIndex, &completeMsg, elemLen, &radioIDtmp, &wlanIDtmp, &(bssIDTmp))))
					return CW_FALSE;

				int radioIndex = CWIEEEBindingGetIndexFromDevID(radioIDtmp);					
				int wlanIndex = CWIEEEBindingGetIndexFromDevID(wlanIDtmp);

				if(radioIndex >= 0 && radioIndex < WTP_RADIO_MAX && wlanIndex >= 0 &&wlanIndex < WTP_MAX_INTERFACES)
				{
					//Settato solo se era un add. Come lo rimetto in modalita STA?
					CW_CREATE_ARRAY_CALLOC_ERR(gWTPs[WTPIndex].WTPProtocolManager.radiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex].BSSID, ETH_ALEN+1, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
					CW_COPY_MEMORY(gWTPs[WTPIndex].WTPProtocolManager.radiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex].BSSID, bssIDTmp, ETH_ALEN);
					gWTPs[WTPIndex].WTPProtocolManager.radiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex].typeInterface = CW_AP_MODE;
				}
				
				CW_FREE_OBJECT(bssIDTmp);
				
				break;
			/*
			case CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE:
				CW_CREATE_OBJECT_ERR(vendPtr, CWProtocolVendorSpecificValues, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				if (!(CWParseVendorPayload(&completeMsg, elemLen, (CWProtocolVendorSpecificValues *) vendPtr)))
				{
					CW_FREE_OBJECT(vendPtr);
					return CW_FALSE; // will be handled by the caller
				}
				break;		
			*/
			default:
				return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
		}
	}
	
	
	if((completeMsg.offset - offsetTillMessages) != len)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");
		
	//if(completeMsg.offset != len) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Garbage at the End of the Message");
	
	CWDebugLog("Configure Response Parsed");	
	return CW_TRUE;
}

CWBool CWAssembleIEEEConfigurationRequest(CWProtocolMessage **messagesPtr,
				   int *fragmentsNumPtr,
				   int PMTU,
				   int seqNum,
				   int operation,
				   int radioID,
				   int wlanID,
				   int WTPIndex) {

	CWProtocolMessage *msgElems = NULL;
	const int MsgElemCount=1;
	CWProtocolMessage *msgElemsBinding = NULL;
	int msgElemBindingCount=0;
	int k = -1;
	
	if(messagesPtr == NULL || fragmentsNumPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	int radioIndex = CWIEEEBindingGetIndexFromDevID(radioID);					
	int wlanIndex = CWIEEEBindingGetIndexFromDevID(wlanID);
	
	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, MsgElemCount, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	//Add WLAN
	if(operation == CW_OP_ADD_WLAN)
	{		
		if(
			(!(CWAssembleMsgElemACAddWlan(radioID, gWTPs[WTPIndex].WTPProtocolManager.radiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex], &(msgElems[++k]))))
		){
			int i;
			for(i = 0; i <= k; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
			CW_FREE_OBJECT(msgElems);
			/* error will be handled by the caller */
			return CW_FALSE;
		}
	}
	//Del WLAN
	else if(operation == CW_OP_DEL_WLAN)
	{
		if(
			(!(CWAssembleMsgElemACDelWlan(radioID, wlanID, &(msgElems[++k]))))
		){
			int i;
			for(i = 0; i <= k; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
			CW_FREE_OBJECT(msgElems);
			/* error will be handled by the caller */
			return CW_FALSE;
		}
	}
	//Update WLAN
	else if(operation == CW_OP_UPDATE_WLAN)
	{
		if(
			(!(CWAssembleMsgElemACUpdateWlan(radioID, gWTPs[WTPIndex].WTPProtocolManager.radiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex], &(msgElems[++k]))))
		){
			int i;
			for(i = 0; i <= k; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
			CW_FREE_OBJECT(msgElems);
			/* error will be handled by the caller */
			return CW_FALSE;
		}
	}
	
	if(!(CWAssembleMessage(messagesPtr,
			       fragmentsNumPtr,
			       PMTU,
			       seqNum,
			       CW_MSG_TYPE_VALUE_WLAN_CONFIGURATION_REQUEST,
			       msgElems,
			       MsgElemCount,
			       msgElemsBinding,
			       msgElemBindingCount,
#ifdef CW_NO_DTLS
			       CW_PACKET_PLAIN)))
#else
			       CW_PACKET_CRYPT))) 
#endif
		return CW_FALSE;
	
	CWDebugLog("Configure Response Assembled");
	return CW_TRUE;
}

CWBool ACUpdateInfoWlanInterface(WTPInterfaceInfo * interfaceInfo, int wlanID, char * SSID, int tunnelMode) {

	int index;
	//WlanID by AC
	interfaceInfo->wlanID=wlanID;
	
	//Useless for AC. WTP will not send the interface name
	interfaceInfo->ifName = NULL;
	
	//Capability
	//ESS: AC MUST set ESS 1
	interfaceInfo->capability[0]=1;
	//IBSS: AC MUST set IBSS 0
	interfaceInfo->capability[1]=0;
	//CF-Pollable
	interfaceInfo->capability[2]=0;
	//CF-Poll
	interfaceInfo->capability[3]=0;
	//Privacy
	interfaceInfo->capability[4]=0;
	//Short Preamble
	interfaceInfo->capability[5]=0;
	//PBCC
	interfaceInfo->capability[6]=0;
	//Channel Agility
	interfaceInfo->capability[7]=0;
	//Spectrum Management
	interfaceInfo->capability[8]=0;
	//QoS
	interfaceInfo->capability[9]=0;
	//Short Slot Time
	interfaceInfo->capability[10]=1;
	//APSD
	interfaceInfo->capability[11]=0;
	//Reserved: MUST be 0
	interfaceInfo->capability[12]=0;
	//DSSS-OFDM
	interfaceInfo->capability[13]=0;
	//Delayed Block ACK
	interfaceInfo->capability[14]=0;
	//Immediate Block ACK
	interfaceInfo->capability[15]=0;
	
	//Bitwise operation for capability 16-bit version
	interfaceInfo->capabilityBit=0;
	for(index=WLAN_CAPABILITY_NUM_FIELDS-1; index>= 0; index--)
		interfaceInfo->capabilityBit |= interfaceInfo->capability[index] << index;

	
	//Key not used
	interfaceInfo->keyIndex=0;
	interfaceInfo->keyStatus=0;
	interfaceInfo->keyLength=0;
	CW_ZERO_MEMORY(interfaceInfo->key, WLAN_KEY_LEN);
	
	//Group TSC: not used
	CW_ZERO_MEMORY(interfaceInfo->groupTSC, WLAN_GROUP_TSC_LEN);
	
	//QoS
	interfaceInfo->qos=0;
	//Auth Type: 0 open system, 1 wep
	interfaceInfo->authType=NL80211_AUTHTYPE_OPEN_SYSTEM;
	//Mac Mode: 0 LocalMAC, 1 Split MAC
	interfaceInfo->MACmode=0;
	//Tunnel Mode: this info is in discovery request from WTP
	interfaceInfo->frameTunnelMode=tunnelMode;
	//Suppress SSID: 0 yes, 1 no
	interfaceInfo->suppressSSID=1;
	//SSID
	CW_CREATE_STRING_FROM_STRING_ERR(interfaceInfo->SSID, SSID, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	return CW_TRUE;
}
