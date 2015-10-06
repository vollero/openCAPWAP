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

/*_________________________________________________________*/
/*  *******************___FUNCTIONS___*******************  */

CWBool CWAssembleIEEEConfigurationResponse(CWProtocolMessage **messagesPtr,
				  int *fragmentsNumPtr,
				  int PMTU,
				  int seqNum,
				  int resultCode,
				  int radioID,
				  int wlanID,
				  char * bssidAssigned);
				  
CWBool CWParseIEEEConfigurationRequestMessage (char *msg,
					int len,
					int seqNum,
					ACInterfaceRequestInfo * interfaceInfo);
					
CWBool CWSaveIEEEConfigurationRequestMessage(ACInterfaceRequestInfo * interfaceInfo);

CWBool CWWTPIEEEConfigurationReceiveSendPacket(int seqNum, CWList msgElemlist);


/* 
 * Send Configure Request on the active session.
 */
CWBool CWAssembleIEEEConfigurationResponse(CWProtocolMessage **messagesPtr,
				  int *fragmentsNumPtr,
				  int PMTU,
				  int seqNum,
				  int resultCode,
				  int radioID,
				  int wlanID,
				  char * bssid) {

	CWProtocolMessage 	*msgElems= NULL;
	CWProtocolMessage 	*msgElemsBinding= NULL;
	const int 		msgElemCount = 2;
	const int 		msgElemBindingCount=0;
	int k = -1;
	
	if(messagesPtr == NULL || fragmentsNumPtr == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, 
					 msgElemCount,
					 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););	
		
	CWDebugLog("Assembling IEEE configuration Response...");
	if(bssid == NULL)
	{
		if((!(CWAssembleMsgElemResultCode(&(msgElems[++k]), resultCode))))
		{
			int i;
			for(i = 0; i <= k; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
			CW_FREE_OBJECT(msgElems);
			/* error will be handled by the caller */
			return CW_FALSE;
		}
	}
	else
	{
		if ((!(CWAssembleMsgElemResultCode(&(msgElems[++k]), resultCode)))	||
			(!(CWAssembleMsgElemAssignedWTPSSID(&(msgElems[++k]), radioID, wlanID, bssid)))
		)
		{
			int i;
			for(i = 0; i <= k; i++) { CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);}
			CW_FREE_OBJECT(msgElems);
			/* error will be handled by the caller */
			return CW_FALSE;
		}
	}
	
	if (!(CWAssembleMessage(messagesPtr, 
				fragmentsNumPtr,
				PMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_WLAN_CONFIGURATION_RESPONSE,
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
	
	CWDebugLog("IEEE Configuration Request Assembled");	 
	return CW_TRUE;
}

CWBool CWParseIEEEConfigurationRequestMessage (char *msg,
					int len,
					int seqNum,
					ACInterfaceRequestInfo * interfaceInfo) {

	CWControlHeaderValues 	controlVal;
	CWProtocolMessage 	completeMsg;
	CWBool 			bindingMsgElemFound = CW_FALSE;
	int 			offsetTillMessages;
	int 			i=0;
	int 			j=0;
	
	if(msg == NULL || interfaceInfo == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Parsing IEEE Configuration Response...");
	
	completeMsg.msg = msg;
	completeMsg.offset = 0;
		
	/* error will be handled by the caller */
	if(!(CWParseControlHeader(&completeMsg, &controlVal))) return CW_FALSE;

	/* different type */
	if (controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_WLAN_CONFIGURATION_REQUEST)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, 
				    "Message is not IEE Wlan Configuration Request as Expected");
	
	if (controlVal.seqNum != seqNum) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, 
				    "Different Sequence Number");
	
	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;
	
	offsetTillMessages = completeMsg.offset;	
	
	/* parse message elements */
	while((completeMsg.offset-offsetTillMessages) < controlVal.msgElemsLen) {
		unsigned short int type=0;	/* = CWProtocolRetrieve32(&completeMsg); */
		unsigned short int len=0;	/* = CWProtocolRetrieve16(&completeMsg); */
		
		CWParseFormatMsgElem(&completeMsg,&type,&len);
		// CWLog("Parsing Message Element: %u, len: %u complete: %d", type, len, completeMsg.offset);

		switch(type) {
			case CW_MSG_ELEMENT_IEEE80211_ADD_WLAN_CW_TYPE:
				if(!(CWParseACAddWlan(&completeMsg, len, interfaceInfo))) return CW_FALSE;
				break;
			case CW_MSG_ELEMENT_IEEE80211_DELETE_WLAN_CW_TYPE:
				if(!(CWParseACDelWlan(&completeMsg, len, interfaceInfo))) return CW_FALSE;
				break;
			case CW_MSG_ELEMENT_IEEE80211_UPDATE_WLAN_CW_TYPE:
				if(!(CWParseACUpdateWlan(&completeMsg, len, interfaceInfo))) return CW_FALSE;
				break;
			default:
				return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Unrecognized Message Element");
		}
	}
	
	if(completeMsg.offset != len) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT,
				    "Garbage at the End of the Message");
	
	completeMsg.offset = offsetTillMessages;

	
	CWDebugLog("IEEE Configuration Request Parsed");
	return CW_TRUE;
}

CWBool CWSaveIEEEConfigurationRequestMessage(ACInterfaceRequestInfo * interfaceACInfo) {
	
	if(interfaceACInfo == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	//RFC radioID > 0 wlanID > 0
	/*if(interfaceACInfo->radioID <= 0 || interfaceACInfo->wlanID <= 0)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
		*/
	int indexRadio = CWIEEEBindingGetIndexFromDevID(interfaceACInfo->radioID);
	int indexWlan = CWIEEEBindingGetIndexFromDevID(interfaceACInfo->wlanID);
	
//	CWLog("WLAN Interface op %d on radioID: %d wlanID: %d", interfaceACInfo->operation, indexRadio, indexWlan);
	//Add Wlan
	if(interfaceACInfo->operation == CW_OP_ADD_WLAN)
	{
		if(
			(indexWlan < WTP_MAX_INTERFACES) &&
			(indexRadio < WTP_RADIO_MAX) &&
			(gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].typeInterface == CW_STA_MODE)
		)
		{
			//gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].wlanID = indexWlan;
			
			CW_COPY_MEMORY(gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].capability, interfaceACInfo->capability, WLAN_CAPABILITY_NUM_FIELDS);
			gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].capabilityBit = interfaceACInfo->capabilityBit;
					
			//---- Key
			gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].keyIndex = interfaceACInfo->keyIndex;
			gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].keyStatus = interfaceACInfo->keyStatus;
			gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].keyLength = interfaceACInfo->keyLength;
			CW_COPY_MEMORY(gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].key, interfaceACInfo->key, WLAN_KEY_LEN);
			//---- Key
			
			CW_COPY_MEMORY(gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].groupTSC, interfaceACInfo->groupTSC, WLAN_GROUP_TSC_LEN);
			gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].qos = interfaceACInfo->qos;
			gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].authType = interfaceACInfo->authType;
			gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].MACmode = interfaceACInfo->MACmode;
			gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].frameTunnelMode = interfaceACInfo->tunnelMode;
			gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].suppressSSID = interfaceACInfo->suppressSSID;
			CW_CREATE_STRING_FROM_STRING_ERR(gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].SSID, interfaceACInfo->SSID, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
			
			if(!CWWTPSetAPInterface(indexRadio, indexWlan, &(gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan])))
				goto failure;
			
			//Add interface to bridge
/*			if(gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].frameTunnelMode == CW_LOCAL_BRIDGING)
//			if(CWWTPGetFrameTunnelMode() == CW_LOCAL_BRIDGING)
			{
				CWLog("Local Bridging tunnel mode. Adding %s to %s", gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].ifName, gBridgeInterfaceName);
				if(!CWAddNewBridgeInterface(globalNLSock.ioctl_sock, gBridgeInterfaceName, gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].realWlanID))
					goto failure;
			}	
	*/
			goto success;
		}
		else
			goto failure;
	}
	//Delete Wlan
	else if(interfaceACInfo->operation == CW_OP_DEL_WLAN)
	{
		if(
			(indexWlan < WTP_MAX_INTERFACES) &&
			(indexRadio < WTP_RADIO_MAX) &&
			(gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].typeInterface == CW_AP_MODE)
		)
		{
			if(!CWWTPDeleteWLANAPInterface(indexRadio, indexWlan))
					goto failure;
			
			//Delete interface from structure
			if(gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].SSID != NULL)
			{
				CW_FREE_OBJECT(gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].SSID);
				gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].SSID=NULL;
			}
			
			gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.interfaces[indexWlan].typeInterface = CW_STA_MODE;
			//TODO: Serve?
			gRadiosInfo.radiosInfo[indexRadio].gWTPPhyInfo.numInterfaces--;	
			
			//Delete BSS
			if(!CWWTPDeleteBSS(indexRadio, indexWlan))
				goto failure;

			goto success;
		}
		else
			goto failure;
	}
	//Update Wlan
	else if(interfaceACInfo->operation == CW_OP_UPDATE_WLAN)
	{
		//TODO
		CWLog("IEEE update WLAN operation");
		goto success;
	}
	else
	{
		CWLog("IEEE Unknwon type of WLAN operation");
		goto failure;
	}

success:	
//	CW_FREE_OBJECT(interfaceACInfo);
	CWLog("IEEE Configuration Request Saved");
	return CW_TRUE;	
	
failure:	
//	CW_FREE_OBJECT(interfaceACInfo);
	CWLog("IEEE Configuration Request NOT Saved");
	return CW_FALSE;
}
