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

 
#include "CWWTP.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

/*____________________________________________________________________________*/
/*  *****************************___ASSEMBLE___*****************************  */
CWBool CWAssembleMsgElemACName(CWProtocolMessage *msgPtr) 
{
	char *name;
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	name = CWWTPGetACName();
//	CWDebugLog("AC Name: %s", name);
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, strlen(name), return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStoreStr(msgPtr, name);
				
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_AC_NAME_CW_TYPE);
}

CWBool CWAssembleMsgElemACNameWithIndex(CWProtocolMessage *msgPtr) 
{
	const int ac_Index_length=1;
	CWACNamesWithIndex ACsinfo;
	CWProtocolMessage *msgs;
	int len = 0;
	int i;
	int j;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	if(!CWWTPGetACNameWithIndex(&ACsinfo)){
		return CW_FALSE;
	}
	
	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgs, ACsinfo.count, return  CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	// create message
	for(i = 0; i < ACsinfo.count; i++) {
		// create message
		CW_CREATE_PROTOCOL_MESSAGE(msgs[i], ac_Index_length+strlen(ACsinfo.ACNameIndex[i].ACName), return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		CWProtocolStore8(&(msgs[i]), ACsinfo.ACNameIndex[i].index); // ID of the AC
		CWProtocolStoreStr(&(msgs[i]), ACsinfo.ACNameIndex[i].ACName); // name of the AC
		if(!(CWAssembleMsgElem(&(msgs[i]), CW_MSG_ELEMENT_AC_NAME_INDEX_CW_TYPE))) {
			for(j = i; j >= 0; j--) { CW_FREE_PROTOCOL_MESSAGE(msgs[j]);}
			CW_FREE_OBJECT(ACsinfo.ACNameIndex);
			CW_FREE_OBJECT(msgs);
			return CW_FALSE;
		}
//		CWDebugLog("AC Name with index: %d - %s", ACsinfo.ACNameIndex[i].index, ACsinfo.ACNameIndex[i].ACName);
		len += msgs[i].offset;
	}
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < ACsinfo.count; i++) {
		CWProtocolStoreMessage(msgPtr, &(msgs[i]));
		CW_FREE_PROTOCOL_MESSAGE(msgs[i]);
	}
	
	CW_FREE_OBJECT(msgs);

 	/*
         * They free ACNameIndex, which is an array of CWACNameWithIndexValues,
         * but nobody cares to free the actual strings that were allocated as fields
         * of the CWACNameWithIndexValues structures in the CWWTPGetACNameWithIndex() 
         * function.. Here we take care of this.
         *
         * BUG ML06
         * 16/10/2009 - Donato Capitella 
         */
        CW_FREE_OBJECT(ACsinfo.ACNameIndex[0].ACName);
        CW_FREE_OBJECT(ACsinfo.ACNameIndex[1].ACName);


	CW_FREE_OBJECT(ACsinfo.ACNameIndex);
	
	return CW_TRUE;
}

CWBool CWAssembleMsgElemDataTransferData(CWProtocolMessage *msgPtr, int data_type) {
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	char* debug_data= " #### DATA DEBUG INFO #### ";   //to be changed...
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 2 + strlen(debug_data) , return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	

	CWProtocolStore8(msgPtr, data_type);
	CWProtocolStore8(msgPtr,strlen(debug_data));
	CWProtocolStoreStr(msgPtr, debug_data);
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_DATA_TRANSFER_DATA_CW_TYPE);
}

CWBool CWAssembleMsgElemDiscoveryType(CWProtocolMessage *msgPtr) {
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 1, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
//	CWDebugLog("Discovery Type: %d", CWWTPGetDiscoveryType());

	CWProtocolStore8(msgPtr, CWWTPGetDiscoveryType());

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_DISCOVERY_TYPE_CW_TYPE);
}

/*
 * Elena Agostini - 02/2014
 *
 * ECN Support Msg Elem MUST be included in Join Request/Response Messages
 */
CWBool CWAssembleMsgElemECNSupport(CWProtocolMessage *msgPtr) {
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 1, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	CWProtocolStore8(msgPtr, CWWTPGetECNSupport());

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_ECN_SUPPORT_CW_TYPE);
}

CWBool CWAssembleMsgElemLocationData(CWProtocolMessage *msgPtr) {
	char *location;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	location = CWWTPGetLocation();
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, strlen(location), return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
//	CWDebugLog("Location Data: %s", location);
	CWProtocolStoreStr(msgPtr, location);
					
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_LOCATION_DATA_CW_TYPE);	
}

CWBool CWAssembleMsgElemStatisticsTimer(CWProtocolMessage *msgPtr)
{	
	const int statistics_timer_length= 2;
	
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, statistics_timer_length, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore16(msgPtr, CWWTPGetStatisticsTimer());
	
//	CWDebugLog("Statistics Timer: %d", CWWTPGetStatisticsTimer());
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_STATISTICS_TIMER_CW_TYPE);	
}

CWBool CWAssembleMsgElemWTPBoardData(CWProtocolMessage *msgPtr) 
{
	const int VENDOR_ID_LENGTH = 4; 	//Vendor Identifier is 4 bytes long
	const int TLV_HEADER_LENGTH = 4; 	//Type and Length of a TLV field is 4 byte long 
	CWWTPVendorInfos infos;
	int i, size = 0;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	 // get infos
	if(!CWWTPGetBoardData(&infos)) {
		return CW_FALSE;
	}
	
	//Calculate msg elem size
	size = VENDOR_ID_LENGTH;
	for(i = 0; i < infos.vendorInfosCount; i++) 
		{size += (TLV_HEADER_LENGTH + ((infos.vendorInfos)[i]).length);}
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, size, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore32(msgPtr, ((infos.vendorInfos)[0].vendorIdentifier));
	for(i = 0; i < infos.vendorInfosCount; i++) 
	{
		CWProtocolStore16(msgPtr, ((infos.vendorInfos)[i].type));
		CWProtocolStore16(msgPtr, ((infos.vendorInfos)[i].length));
		
		if((infos.vendorInfos)[i].length == 4) {
			*((infos.vendorInfos)[i].valuePtr) = htonl(*((infos.vendorInfos)[i].valuePtr));
		}
	
		CWProtocolStoreRawBytes(msgPtr, (char*) ((infos.vendorInfos)[i].valuePtr), (infos.vendorInfos)[i].length);
		
//		CWDebugLog("Board Data: %d - %d - %d - %d", (infos.vendorInfos)[i].vendorIdentifier, (infos.vendorInfos)[i].type, (infos.vendorInfos)[i].length, *((infos.vendorInfos)[i].valuePtr));
	}

	CWWTPDestroyVendorInfos(&infos);

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_BOARD_DATA_CW_TYPE);
}

CWBool CWAssembleMsgElemVendorSpecificPayload(CWProtocolMessage *msgPtr) {
	const int VENDOR_ID_LENGTH = 4; 	//Vendor Identifier is 4 bytes long
	const int  ELEMENT_ID = 2; 	//Type and Length of a TLV field is 4 byte long 
	const int  DATA_LEN = 2;
	CWWTPVendorInfos infos;
	int i, size = 0;
	int element_id_zero = 0;
	int data_zero = 0;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	 // get infos
	if(!CWWTPGetBoardData(&infos)) {
		return CW_FALSE;
	}
	
	//Calculate msg elem size
	size = VENDOR_ID_LENGTH + ELEMENT_ID + DATA_LEN ;
	
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, size, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore32(msgPtr, ((infos.vendorInfos)[0].vendorIdentifier));
	CWProtocolStore16(msgPtr, element_id_zero);
	CWProtocolStore16(msgPtr, data_zero);

	CWWTPDestroyVendorInfos(&infos);

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_BW_CW_TYPE);
}

CWBool CWAssembleMsgElemWTPDescriptor(CWProtocolMessage *msgPtr) {
	const int GENERIC_RADIO_INFO_LENGTH = 4;//First 4 bytes for Max Radios, Radios In Use and Encryption Capability 
	const int VENDOR_ID_LENGTH = 4; 	//Vendor Identifier is 4 bytes long
	const int TLV_HEADER_LENGTH = 4; 	//Type and Length of a TLV field is 4 byte long 
	CWWTPVendorInfos infos;
	int i, size = 0;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	// get infos
	if(!CWWTPGetVendorInfos(&infos)) { 
		return CW_FALSE;
	}
	
	//Calculate msg elem size
	size = GENERIC_RADIO_INFO_LENGTH;
	for(i = 0; i < infos.vendorInfosCount; i++) 
		{size += (VENDOR_ID_LENGTH + TLV_HEADER_LENGTH + ((infos.vendorInfos)[i]).length);}
	/*
	 * Elena Agostini - 02/2014
	 *
	 * BUG Valgrind: Real size of msgPrt is 42, not 40. With 40 bytes there's
	 * an heap overrun.
	 */
	size += 2;

	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, size, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore8(msgPtr, CWWTPGetMaxRadios()); // number of radios supported by the WTP
	CWProtocolStore8(msgPtr, CWWTPGetRadiosInUse()); // number of radios present in the WTP

	// encryption capabilities
	CWProtocolStore8(msgPtr, 1);
	CWProtocolStore8(msgPtr, 1);	// IEEE802.11 binding
	CWProtocolStore16(msgPtr, CWWTPGetEncCapabilities());
 
	for(i = 0; i < infos.vendorInfosCount; i++) {
		CWProtocolStore32(msgPtr, ((infos.vendorInfos)[i].vendorIdentifier));
		CWProtocolStore16(msgPtr, ((infos.vendorInfos)[i].type));
		CWProtocolStore16(msgPtr, ((infos.vendorInfos)[i].length));
		
		if((infos.vendorInfos)[i].length == 4) {
			*((infos.vendorInfos)[i].valuePtr) = htonl(*((infos.vendorInfos)[i].valuePtr));
		}
	
		CWProtocolStoreRawBytes(msgPtr, (char*) ((infos.vendorInfos)[i].valuePtr), (infos.vendorInfos)[i].length);
/*
		CWDebugLog("WTP Descriptor Vendor ID: %d", (infos.vendorInfos)[i].vendorIdentifier);
		CWDebugLog("WTP Descriptor Type: %d", (infos.vendorInfos)[i].type);
		CWDebugLog("WTP Descriptor Length: %d", (infos.vendorInfos)[i].length);
		CWDebugLog("WTP Descriptor Value: %d", *((infos.vendorInfos)[i].valuePtr));
*/
		//CWDebugLog("Vendor Info \"%d\" = %d - %d - %d", i, (infos.vendorInfos)[i].vendorIdentifier, (infos.vendorInfos)[i].type, (infos.vendorInfos)[i].length);
	}
	
	CWWTPDestroyVendorInfos(&infos);
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_DESCRIPTOR_CW_TYPE);
}

CWBool CWAssembleMsgElemWTPFrameTunnelMode(CWProtocolMessage *msgPtr) {
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 1, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
//	CWDebugLog("Frame Tunnel Mode: %d", CWWTPGetFrameTunnelMode());
	CWProtocolStore8(msgPtr, CWWTPGetFrameTunnelMode()); // frame encryption

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_FRAME_TUNNEL_MODE_CW_TYPE);
}

CWBool CWAssembleMsgElemWTPIPv4Address(CWProtocolMessage *msgPtr) {
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 4, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

//	CWDebugLog("WTP IPv4 Address: %d", CWWTPGetIPv4Address());
	CWProtocolStore32(msgPtr, CWWTPGetIPv4Address());

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_LOCAL_IPV4_ADDRESS_CW_TYPE);
}

CWBool CWAssembleMsgElemWTPMACType(CWProtocolMessage *msgPtr) {

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 1, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
//	CWDebugLog("WTP MAC Type: %d", CWWTPGetMACType());
	CWProtocolStore8(msgPtr, CWWTPGetMACType()); // mode of operation of the WTP (local, split, ...)

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_MAC_TYPE_CW_TYPE);
}

/* Elena Agostini - 07/2014: WTP Radio Info: nl80211 support */
CWBool CWAssembleMsgElemWTPRadioInformation(CWProtocolMessage *msgPtr, int radioID, char radioType) {

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 5, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	//RadioID - 1 byte
	CWProtocolStore8(msgPtr, radioID);
	//Reserved - 3 byte
	CWProtocolStore8(msgPtr, 0); 
	CWProtocolStore8(msgPtr, 0);
	CWProtocolStore8(msgPtr, 0);
	//Radio Type	 
	CWProtocolStore8(msgPtr, radioType);

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_IEEE80211_WTP_RADIO_INFORMATION_CW_TYPE);
}

CWBool CWAssembleMsgElemSupportedRates(CWProtocolMessage *msgPtr, int radioID,char * suppRates, int lenSuppRates) {

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 9, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		
	CWProtocolStore8(msgPtr, radioID); 
	int index;
	for(index=0; index<lenSuppRates; index++)
		CWProtocolStore8(msgPtr, suppRates[index]);
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_IEEE80211_SUPPORTED_RATES_CW_TYPE);
}

//Elena Agostini - 08/2014: nl80211 support 
CWBool CWAssembleMsgElemMultiDomainCapability(CWProtocolMessage *msgPtr, int radioID, int firstChannel, int numChannels, int maxTxPower) {

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 8, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore8(msgPtr, radioID); 
	CWProtocolStore8(msgPtr, 0); 
	
	CWProtocolStore16(msgPtr, firstChannel);
	CWProtocolStore16(msgPtr, numChannels); 
	CWProtocolStore16(msgPtr, maxTxPower); 

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_IEEE80211_MULTI_DOMAIN_CAPABILITY_CW_TYPE);
}

//Elena Agostini - 08/2014: nl80211 support 
CWBool CWAssembleMsgElemMACOperation(CWProtocolMessage *msgPtr, int radioID, int fragmentationTreshold, int rtsThreshold, char shortRetry, char longRetry, int txMSDU, int rxMSDU) {

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 16, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore8(msgPtr, radioID); 
	CWProtocolStore8(msgPtr, 0); 
	
	CWProtocolStore16(msgPtr, rtsThreshold);
	CWProtocolStore8(msgPtr, shortRetry);
	CWProtocolStore8(msgPtr, longRetry);
	CWProtocolStore16(msgPtr, fragmentationTreshold);
	
	CWProtocolStore32(msgPtr, txMSDU);
	CWProtocolStore32(msgPtr, rxMSDU);
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_IEEE80211_MAC_OPERATION_CW_TYPE);
}

//Elena Agostini - 09/2014: IEEE Binding
CWBool CWAssembleMsgElemAssignedWTPSSID(CWProtocolMessage *msgPtr, int radioID, int wlanID, char * bssid) {

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 8, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	//1
	CWProtocolStore8(msgPtr, radioID); 
	//1
	CWProtocolStore8(msgPtr, wlanID); 
	//6
	CWProtocolStoreRawBytes(msgPtr, bssid, ETH_ALEN);
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_IEEE80211_ASSIGNED_WTP_BSSID_CW_TYPE);
}


CWBool CWAssembleMsgElemWTPName(CWProtocolMessage *msgPtr) {
	char *name;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	name = CWWTPGetName();
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, strlen(name), return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
//	CWDebugLog("WTPName: %s", name);
	CWProtocolStoreStr(msgPtr, name);
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_NAME_CW_TYPE);	
}

CWBool CWAssembleMsgElemWTPOperationalStatistics(CWProtocolMessage *msgPtr, int radio)
{
	const int operational_statistics_length= 4;

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if(radio<0 || radio>=gRadiosInfo.radioCount) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, operational_statistics_length, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore8(msgPtr, radio);
	CWProtocolStore8(msgPtr, gRadiosInfo.radiosInfo[radio].TxQueueLevel);
	CWProtocolStore16(msgPtr, gRadiosInfo.radiosInfo[radio].wirelessLinkFramesPerSec);

//	CWDebugLog("");	
//	CWDebugLog("WTPOperationalStatistics of radio \"%d\": %d - %d", radio,gRadiosInfo.radiosInfo[radio].TxQueueLevel,  gRadiosInfo.radiosInfo[radio].wirelessLinkFramesPerSec);

	CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_OPERAT_STATISTICS_CW_TYPE);
	
	return CW_TRUE;	
}

CWBool CWAssembleMsgElemWTPRadioStatistics(CWProtocolMessage *msgPtr, int radio)
{
	const int radio_statistics_length= 20;

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if(radio<0 || radio>gRadiosInfo.radioCount) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, radio_statistics_length, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	CWProtocolStore8(msgPtr, radio);
	CWProtocolStore8(msgPtr, gRadiosInfo.radiosInfo[radio].statistics.lastFailureType);
	CWProtocolStore16(msgPtr, gRadiosInfo.radiosInfo[radio].statistics.resetCount);
	CWProtocolStore16(msgPtr, gRadiosInfo.radiosInfo[radio].statistics.SWFailureCount);
	CWProtocolStore16(msgPtr, gRadiosInfo.radiosInfo[radio].statistics.HWFailuireCount);
	CWProtocolStore16(msgPtr, gRadiosInfo.radiosInfo[radio].statistics.otherFailureCount);
	CWProtocolStore16(msgPtr, gRadiosInfo.radiosInfo[radio].statistics.unknownFailureCount);
	CWProtocolStore16(msgPtr, gRadiosInfo.radiosInfo[radio].statistics.configUpdateCount);
	CWProtocolStore16(msgPtr, gRadiosInfo.radiosInfo[radio].statistics.channelChangeCount);
	CWProtocolStore16(msgPtr, gRadiosInfo.radiosInfo[radio].statistics.bandChangeCount);
	CWProtocolStore16(msgPtr, gRadiosInfo.radiosInfo[radio].statistics.currentNoiseFloor);

//	CWDebugLog("");
//	CWDebugLog("WTPRadioStatistics of radio: \"%d\"", radio);
//	CWDebugLog("WTPRadioStatistics(1): %d - %d - %d", gRadiosInfo.radiosInfo[radio].statistics.lastFailureType, gRadiosInfo.radiosInfo[radio].statistics.resetCount, gRadiosInfo.radiosInfo[radio].statistics.SWFailureCount);
//	CWDebugLog("WTPRadioStatistics(2): %d - %d - %d", gRadiosInfo.radiosInfo[radio].statistics.HWFailuireCount, gRadiosInfo.radiosInfo[radio].statistics.otherFailureCount, gRadiosInfo.radiosInfo[radio].statistics.unknownFailureCount);
//	CWDebugLog("WTPRadioStatistics(3): %d - %d - %d - %d", gRadiosInfo.radiosInfo[radio].statistics.configUpdateCount, gRadiosInfo.radiosInfo[radio].statistics.channelChangeCount,gRadiosInfo.radiosInfo[radio].statistics.bandChangeCount,gRadiosInfo.radiosInfo[radio].statistics.currentNoiseFloor);

	//return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_RADIO_STATISTICS_CW_TYPE);

	CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_RADIO_STATISTICS_CW_TYPE);
	
	return CW_TRUE;
}

CWBool CWAssembleMsgElemWTPRebootStatistics(CWProtocolMessage *msgPtr)
{
	const int reboot_statistics_length= 15;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, reboot_statistics_length, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore16(msgPtr, gWTPRebootStatistics.rebootCount);
	CWProtocolStore16(msgPtr, gWTPRebootStatistics.ACInitiatedCount);
	CWProtocolStore16(msgPtr, gWTPRebootStatistics.linkFailurerCount);
	CWProtocolStore16(msgPtr, gWTPRebootStatistics.SWFailureCount);
	CWProtocolStore16(msgPtr, gWTPRebootStatistics.HWFailuireCount);
	CWProtocolStore16(msgPtr, gWTPRebootStatistics.otherFailureCount);
	CWProtocolStore16(msgPtr, gWTPRebootStatistics.unknownFailureCount);
	CWProtocolStore8(msgPtr, gWTPRebootStatistics.lastFailureType);

//	CWDebugLog("");	
//	CWDebugLog("WTPRebootStat(1): %d - %d - %d", gWTPRebootStatistics.rebootCount, gWTPRebootStatistics.ACInitiatedCount, gWTPRebootStatistics.linkFailurerCount);
//	CWDebugLog("WTPRebootStat(2): %d - %d - %d", gWTPRebootStatistics.SWFailureCount, gWTPRebootStatistics.HWFailuireCount, gWTPRebootStatistics.otherFailureCount);
//	CWDebugLog("WTPRebootStat(3): %d - %d", gWTPRebootStatistics.unknownFailureCount, gWTPRebootStatistics.lastFailureType);

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_REBOOT_STATISTICS_CW_TYPE);
}

//Elena Agostini - 11/2014: Delete Station Msg Elem
CWBool CWAssembleMsgElemWTPDeleteStation(CWProtocolMessage *msgPtr, CWMsgElemDataDeleteStation * infoDeleteStation)
{	
	if(msgPtr == NULL || infoDeleteStation == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 2+ETH_ALEN, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore8(msgPtr, infoDeleteStation->radioID);
	CWProtocolStore8(msgPtr, ETH_ALEN);
	CWProtocolStoreRawBytes(msgPtr, infoDeleteStation->staAddr, ETH_ALEN);
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_DELETE_STATION_CW_TYPE);
}

//test version
CWBool CWAssembleMsgElemDuplicateIPv4Address(CWProtocolMessage *msgPtr) {
	const int duplicate_ipv4_length= 11;
	char *macAddress;

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, duplicate_ipv4_length, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

//	CWDebugLog("");	
//	CWDebugLog("Duplicate IPv4 Address: %d", CWWTPGetIPv4Address());
	
	CWProtocolStore32(msgPtr, CWWTPGetIPv4Address());

	CWProtocolStore8(msgPtr, CWWTPGetIPv4StatusDuplicate());

	CWProtocolStore8(msgPtr, 6);

	CW_CREATE_ARRAY_ERR(macAddress, 6, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	macAddress[0] = 103;
	macAddress[1] = 204;
	macAddress[2] = 204;
	macAddress[3] = 190;
	macAddress[4] = 180;
	macAddress[5] = 0;
	
	CWProtocolStoreRawBytes(msgPtr, macAddress, 6);
	CW_FREE_OBJECT(macAddress);

	//CWProtocolStore8(msgPtr, CWWTPGetIPv4StatusDuplicate());

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_DUPLICATE_IPV4_ADDRESS_CW_TYPE);
}

//test version
CWBool CWAssembleMsgElemDuplicateIPv6Address(CWProtocolMessage *msgPtr) {
	const int duplicate_ipv6_length= 23;
	char *macAddress;

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, duplicate_ipv6_length, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

//	CWDebugLog("");	
//	CWDebugLog("Duplicate IPv6 Address");
	
	struct sockaddr_in6 myAddr;
	CWWTPGetIPv6Address(&myAddr);
	CWProtocolStoreRawBytes(msgPtr, (char*)myAddr.sin6_addr.s6_addr, 16);

	CWProtocolStore8(msgPtr, CWWTPGetIPv6StatusDuplicate());
	
	CWProtocolStore8(msgPtr, 6);

	CW_CREATE_ARRAY_ERR(macAddress, 6, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	macAddress[0] = 103;
	macAddress[1] = 204;
	macAddress[2] = 204;
	macAddress[3] = 190;
	macAddress[4] = 180;
	macAddress[5] = 0;
	
	CWProtocolStoreRawBytes(msgPtr, macAddress, 6);
	CW_FREE_OBJECT(macAddress);

	//CWProtocolStore8(msgPtr, CWWTPGetIPv6StatusDuplicate());

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_DUPLICATE_IPV6_ADDRESS_CW_TYPE);
}



CWBool CWAssembleMsgElemRadioAdminState(CWProtocolMessage *msgPtr) 
{
	const int radio_Admin_State_Length=2;
	CWRadiosAdminInfo infos;
	CWProtocolMessage *msgs;
	int len = 0;
	int i;
	int j;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	if(!CWGetWTPRadiosAdminState(&infos)) {
		return CW_FALSE;
	}
	
	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgs, (infos.radiosCount), return  CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		// create message
		CW_CREATE_PROTOCOL_MESSAGE(msgs[i], radio_Admin_State_Length, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		CWProtocolStore8(&(msgs[i]), infos.radios[i].ID); // ID of the radio
		CWProtocolStore8(&(msgs[i]), infos.radios[i].state); // state of the radio
		//CWProtocolStore8(&(msgs[i]), infos.radios[i].cause);
		
		if(!(CWAssembleMsgElem(&(msgs[i]), CW_MSG_ELEMENT_RADIO_ADMIN_STATE_CW_TYPE))) {
			for(j = i; j >= 0; j--) { CW_FREE_PROTOCOL_MESSAGE(msgs[j]);}
			CW_FREE_OBJECT(infos.radios);
			CW_FREE_OBJECT(msgs);
			return CW_FALSE;
		}
		
		len += msgs[i].offset;
//		CWDebugLog("Radio Admin State: %d - %d - %d", infos.radios[i].ID, infos.radios[i].state, infos.radios[i].cause);
	}
	
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		CWProtocolStoreMessage(msgPtr, &(msgs[i]));
		CW_FREE_PROTOCOL_MESSAGE(msgs[i]);
	}
	
	CW_FREE_OBJECT(msgs);
	CW_FREE_OBJECT(infos.radios);

	return CW_TRUE;
}

//if radioID is negative return Radio Operational State for all radios
CWBool CWAssembleMsgElemRadioOperationalState(int radioID, CWProtocolMessage *msgPtr) 
{
	const int radio_Operational_State_Length=3;
	CWRadiosOperationalInfo infos;
	CWProtocolMessage *msgs;
	int len = 0;
	int i;

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if(!(CWGetWTPRadiosOperationalState(radioID,&infos))) {
		return CW_FALSE;
	}

	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgs, (infos.radiosCount), return  CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		// create message
		CW_CREATE_PROTOCOL_MESSAGE(msgs[i], radio_Operational_State_Length, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		CWProtocolStore8(&(msgs[i]), infos.radios[i].ID); // ID of the radio
		CWProtocolStore8(&(msgs[i]), infos.radios[i].state); // state of the radio
		CWProtocolStore8(&(msgs[i]), infos.radios[i].cause);
		
		if(!(CWAssembleMsgElem(&(msgs[i]), CW_MSG_ELEMENT_RADIO_OPERAT_STATE_CW_TYPE))) {
			int j;
			for(j = i; j >= 0; j--) { CW_FREE_PROTOCOL_MESSAGE(msgs[j]);}
			CW_FREE_OBJECT(infos.radios);
			CW_FREE_OBJECT(msgs);
			return CW_FALSE;
		}
		
		len += msgs[i].offset;
		CWLog("Radio Operational State: %d - %d - %d", infos.radios[i].ID, infos.radios[i].state, infos.radios[i].cause);
	}
	
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		CWProtocolStoreMessage(msgPtr, &(msgs[i]));
		CW_FREE_PROTOCOL_MESSAGE(msgs[i]);
	}
	
	CW_FREE_OBJECT(msgs);
	CW_FREE_OBJECT(infos.radios);

	return CW_TRUE;
}

CWBool CWAssembleMsgElemDecryptErrorReport(CWProtocolMessage *msgPtr, int radioID) 
{
	int decrypy_Error_Report_Length=0;
	CWDecryptErrorReportInfo infos;
	CWProtocolMessage *msgs;
	int len = 0;
	int i;

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if(!(CWGetDecryptErrorReport(radioID,&infos))) {
		return CW_FALSE;
	}

	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgs, (infos.radiosCount), return  CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		// create message
		decrypy_Error_Report_Length = 2 + sizeof(CWMACAddress)*(infos.radios[i].numEntries); 
		
		CW_CREATE_PROTOCOL_MESSAGE(msgs[i], decrypy_Error_Report_Length, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		CWProtocolStore8(&(msgs[i]), infos.radios[i].ID); // ID of the radio
		CWProtocolStore8(&(msgs[i]), infos.radios[i].numEntries); // state of the radio

		CWProtocolStore8(&(msgs[i]), (unsigned char)sizeof(CWMACAddress)*(infos.radios[i].numEntries));

		CWProtocolStoreRawBytes(&(msgs[i]), (char*)*(infos.radios[i].decryptErrorMACAddressList), sizeof(CWMACAddress)*(infos.radios[i].numEntries));
		
		/*
		CWDebugLog("###numEntries = %d", infos.radios[i].numEntries);
		CWDebugLog("j = %d", sizeof(CWMACAddress)*(infos.radios[i].numEntries));
		
		int j;
		for (j=(sizeof(CWMACAddress)*(infos.radios[i].numEntries)); j>0; j--)
			CWDebugLog("##(%d/6) = %d", j, msgs[i].msg[(msgs[i].offset)-j]);
		*/
		
		if(!(CWAssembleMsgElem(&(msgs[i]), CW_MSG_ELEMENT_CW_DECRYPT_ER_REPORT_CW_TYPE))) {
			int j;
			for(j = i; j >= 0; j--) { CW_FREE_PROTOCOL_MESSAGE(msgs[j]);}
			for(j=0; j<infos.radiosCount; j++) {CW_FREE_OBJECT(infos.radios[j].decryptErrorMACAddressList);}
			CW_FREE_OBJECT(infos.radios);
			CW_FREE_OBJECT(msgs);
			return CW_FALSE;
		}
		
		len += msgs[i].offset;
//		CWDebugLog("Radio Decrypt Error Report of radio \"%d\" = %d", infos.radios[i].ID, infos.radios[i].numEntries);
	}
	
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		CWProtocolStoreMessage(msgPtr, &(msgs[i]));
		CW_FREE_PROTOCOL_MESSAGE(msgs[i]);
	}
	
	for(i = 0; i < infos.radiosCount; i++) {
		CW_FREE_OBJECT(infos.radios[i].decryptErrorMACAddressList);
	}
	
	CW_FREE_OBJECT(msgs);
	CW_FREE_OBJECT(infos.radios);

	return CW_TRUE;
	
}

/*
CWBool CWAssembleMsgElemWTPRadioInformation(CWProtocolMessage *msgPtr) {
	CWProtocolMessage *msgs;
	CWRadiosInformation infos;
	
	int len = 0;
	int i;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Assemble WTP Radio Info");
	
	if(!CWWTPGetRadiosInformation(&infos)) {
		return CW_FALSE;
	}
	
	// create one message element for each radio
	
	CW_CREATE_ARRAY_ERR(msgs, (infos.radiosCount), CWProtocolMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		// create message
		CW_CREATE_PROTOCOL_MESSAGE(msgs[i], 5, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		CWProtocolStore8(&(msgs[i]), infos.radios[i].ID); // ID of the radio
		CWProtocolStore32(&(msgs[i]), infos.radios[i].type); // type of the radio
		
		CWDebugLog("WTPRadioInformation: %d - %d", infos.radios[i].ID, infos.radios[i].type);
		
		if(!(CWAssembleMsgElem(&(msgs[i]), CW_MSG_ELEMENT_WTP_RADIO_INFO_CW_TYPE))) {
			int j;
			for(j = i; j >= 0; j--) { CW_FREE_PROTOCOL_MESSAGE(msgs[j]);}
			CW_FREE_OBJECT(infos.radios);
			CW_FREE_OBJECT(msgs);
			return CW_FALSE;
		}
		
		len += msgs[i].offset;
	}
	
	// return all the messages as one big message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		CWProtocolStoreMessage(msgPtr, &(msgs[i]));
		CW_FREE_PROTOCOL_MESSAGE(msgs[i]);
	}
	
	CW_FREE_OBJECT(msgs);
	CW_FREE_OBJECT(infos.radios);
	
	return CW_TRUE;
}
*/

/*_________________________________________________________________________*/
/*  *****************************___PARSE___*****************************  */
CWBool CWParseWTPRadioInformation_FromAC(CWProtocolMessage *msgPtr, int len, char *valPtr) {
	//CWParseMessageElementStart();
	
	CWProtocolRetrieve8(msgPtr);
	
	CWProtocolRetrieve8(msgPtr);
	CWProtocolRetrieve8(msgPtr);
	CWProtocolRetrieve8(msgPtr);
	*valPtr = CWProtocolRetrieve8(msgPtr);
	return CW_TRUE;
	//CWParseMessageElementEnd();
}

CWBool CWParseACDescriptor(CWProtocolMessage *msgPtr, int len, CWACInfoValues *valPtr) {
	int i=0, theOffset=0;
		
	CWParseMessageElementStart();
	
	
	valPtr->stations= CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("AC Descriptor Stations: %d", valPtr->stations);
	
	valPtr->limit	= CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("AC Descriptor Limit: %d", valPtr->limit);
	
	valPtr->activeWTPs= CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("AC Descriptor Active WTPs: %d", valPtr->activeWTPs);
	
	valPtr->maxWTPs	= CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("AC Descriptor Max WTPs: %d",	valPtr->maxWTPs);
	
	valPtr->security= CWProtocolRetrieve8(msgPtr);
//	CWDebugLog("AC Descriptor Security: %d",	valPtr->security);
	
	valPtr->RMACField= CWProtocolRetrieve8(msgPtr);
//	CWDebugLog("AC Descriptor Radio MAC Field: %d",	valPtr->security);

//	valPtr->WirelessField= CWProtocolRetrieve8(msgPtr);
//	CWDebugLog("AC Descriptor Wireless Field: %d",	valPtr->security);

	CWProtocolRetrieve8(msgPtr);			//Reserved

	valPtr->DTLSPolicy= CWProtocolRetrieve8(msgPtr); // DTLS Policy
//	CWDebugLog("DTLS Policy: %d",	valPtr->DTLSPolicy);

	valPtr->vendorInfos.vendorInfosCount = 0;
	
	theOffset = msgPtr->offset;
	
	// see how many vendor ID we have in the message
	while((msgPtr->offset-oldOffset) < len) {	// oldOffset stores msgPtr->offset's value at the beginning of this function.
							// See the definition of the CWParseMessageElementStart() macro.
		int tmp, id=0, type=0;		

		//CWDebugLog("differenza:%d, offset:%d, oldOffset:%d", (msgPtr->offset-oldOffset), (msgPtr->offset), oldOffset);

		id=CWProtocolRetrieve32(msgPtr);
//		CWDebugLog("ID: %d", id); // ID
		
		type=CWProtocolRetrieve16(msgPtr);
//		CWDebugLog("TYPE: %d",type); // type
		
		tmp = CWProtocolRetrieve16(msgPtr);
		msgPtr->offset += tmp; // len
//		CWDebugLog("offset %d", msgPtr->offset);
		valPtr->vendorInfos.vendorInfosCount++;
	}
	
	msgPtr->offset = theOffset;
	
	// actually read each vendor ID
	CW_CREATE_ARRAY_ERR(valPtr->vendorInfos.vendorInfos, valPtr->vendorInfos.vendorInfosCount, CWACVendorInfoValues,
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
//	CWDebugLog("len %d", len);
//	CWDebugLog("vendorInfosCount %d", valPtr->vendorInfos.vendorInfosCount);
	for(i = 0; i < valPtr->vendorInfos.vendorInfosCount; i++) {
//		CWDebugLog("vendorInfosCount %d vs %d", i, valPtr->vendorInfos.vendorInfosCount);
		(valPtr->vendorInfos.vendorInfos)[i].vendorIdentifier = CWProtocolRetrieve32(msgPtr);
		(valPtr->vendorInfos.vendorInfos)[i].type = CWProtocolRetrieve16(msgPtr);																
		(valPtr->vendorInfos.vendorInfos)[i].length = CWProtocolRetrieve16(msgPtr);
		(valPtr->vendorInfos.vendorInfos)[i].valuePtr = (int*) (CWProtocolRetrieveRawBytes(msgPtr, (valPtr->vendorInfos.vendorInfos)[i].length));
		
		if((valPtr->vendorInfos.vendorInfos)[i].valuePtr == NULL) return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		
		if((valPtr->vendorInfos.vendorInfos)[i].length == 4) {
			*((valPtr->vendorInfos.vendorInfos)[i].valuePtr) = ntohl(*((valPtr->vendorInfos.vendorInfos)[i].valuePtr));
		}
		
//		CWDebugLog("AC Descriptor Vendor ID: %d", (valPtr->vendorInfos.vendorInfos)[i].vendorIdentifier);
//		CWDebugLog("AC Descriptor Type: %d", (valPtr->vendorInfos.vendorInfos)[i].type);
//		CWDebugLog("AC Descriptor Value: %d", *((valPtr->vendorInfos.vendorInfos)[i].valuePtr));
	}		
//	CWDebugLog("AC Descriptor Out");
	CWParseMessageElementEnd();
}

CWBool CWParseACIPv4List(CWProtocolMessage *msgPtr, int len, ACIPv4ListValues *valPtr) {
	int i;
	CWParseMessageElementStart();
	
	if(len == 0 || ((len % 4) != 0)) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Malformed AC IPv4 List Messame Element");
	
	valPtr->ACIPv4ListCount = (len/4);
	
	CW_CREATE_ARRAY_ERR(valPtr->ACIPv4List, valPtr->ACIPv4ListCount, int, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < valPtr->ACIPv4ListCount; i++) {
		struct sockaddr_in addr;
		(valPtr->ACIPv4List)[i] = CWProtocolRetrieve32(msgPtr);
//		CWDebugLog("AC IPv4 List (%d): %d", i+1, (valPtr->ACIPv4List)[i]);
		addr.sin_addr.s_addr = (valPtr->ACIPv4List)[i];
		addr.sin_family = AF_INET;
		addr.sin_port = 1024;
		CWUseSockNtop(&addr, CWDebugLog(str););
	}
	
	CWParseMessageElementEnd();
}

CWBool CWParseACIPv6List(CWProtocolMessage *msgPtr, int len, ACIPv6ListValues *valPtr) 
{
	int i;
	CWParseMessageElementStart();
	
	if(len == 0 || ((len % 16) != 0)) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Malformed AC IPv6 List Messame Element");
	
	valPtr->ACIPv6ListCount = (len/16);
	
	CW_CREATE_ARRAY_ERR(valPtr->ACIPv6List, valPtr->ACIPv6ListCount, struct in6_addr, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < valPtr->ACIPv6ListCount; i++) {
		struct sockaddr_in6 addr;
   		
		/*
                 * BUG ML09
                 * 19/10/2009 - Donato Capitella
                 */                
		void *ptr;
                ptr =  CWProtocolRetrieveRawBytes(msgPtr, 16);
                CW_COPY_MEMORY(&((valPtr->ACIPv6List)[i]), ptr, 16);
                CW_FREE_OBJECT(ptr);
		CW_COPY_MEMORY(&(addr.sin6_addr), &((valPtr->ACIPv6List)[i]), 16);
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(CW_CONTROL_PORT);
		
//		CWUseSockNtop(&addr, CWDebugLog("AC IPv6 List: %s",str););
	}
	
	CWParseMessageElementEnd();
}

/* ------------------------------------ Elena Agostini: OLD HOSTAPD IEEE BINDING ------------------------------------ */
CWBool CWParseDeleteStation(CWProtocolMessage *msgPtr, int len, int * radioID, char ** address) 
{
	int Length=0;
	
	//CWParseMessageElementStart();	 sostituire al posto delle righe successive quando passerò valPtr alla funzione CWarseAddStation
	/*--------------------------------------------------------------------------------------*/
	int oldOffset;												
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);	
	oldOffset = msgPtr->offset;
	/*----------------------------------------------------------------------------------*/
	
	(*radioID) = CWProtocolRetrieve8(msgPtr);
	Length = CWProtocolRetrieve8(msgPtr);
	(*address) = (unsigned char*)CWProtocolRetrieveRawBytes(msgPtr, Length);
	    
 /*   CWDebugLog("ADD MAC: %02X:%02X:%02X:%02X:%02X:%02X", (unsigned char)(*address)[0],
														 (unsigned char)(*address)[1],
														 (unsigned char)(*address)[2],
														 (unsigned char)(*address)[3],
														 (unsigned char)(*address)[4],
														 (unsigned char)(*address)[5]);
*/
	CWParseMessageElementEnd();  
}

CWBool CWParseAddStation(CWProtocolMessage *msgPtr, int len, int * radioID, char ** address) 
{
	int Length=0;
	
	//CWParseMessageElementStart();	 sostituire al posto delle righe successive quando passerò valPtr alla funzione CWarseAddStation
	/*--------------------------------------------------------------------------------------*/
	int oldOffset;												
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);	
	oldOffset = msgPtr->offset;
	/*----------------------------------------------------------------------------------*/
	
	(*radioID) = CWProtocolRetrieve8(msgPtr);
	Length = CWProtocolRetrieve8(msgPtr);
	(*address) = (unsigned char*)CWProtocolRetrieveRawBytes(msgPtr, Length);
	
	/*    
    CWDebugLog("ADD MAC: %02X:%02X:%02X:%02X:%02X:%02X", (unsigned char)(*address)[0],
														 (unsigned char)(*address)[1],
														  (unsigned char)(*address)[2],
														   (unsigned char)(*address)[3],
														    (unsigned char)(*address)[4],
														     (unsigned char)(*address)[5]);
	*/
	//CWWTPsend_command_to_hostapd_SET_ADDR( tmp_mac,7);												     

	CWParseMessageElementEnd();  
}
/* ------------------------------------------------------------------------------------------ */

/* +++++++++++++++++++++++++ Elena Agostini - 10/2014 IEEE BINDING +++++++++++++++++++++++++ */
CWBool CWParse80211Station(CWProtocolMessage *msgPtr, int len, int * radioID, short int * assID, char * flags, char ** address, short int * capability, int * wlanID, int * supportedRatesLen, char ** supportedRates) 
{
	//CWParseMessageElementStart();	sostituire al posto delle righe successive quando passerò valPtr alla funzione CWarseAddStation
	/*--------------------------------------------------------------------------------------*/
	int oldOffset;												
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);	
	oldOffset = msgPtr->offset;
	/*----------------------------------------------------------------------------------*/
	
	(*radioID) = CWProtocolRetrieve8(msgPtr);
	(*assID) = CWProtocolRetrieve16(msgPtr);
	(*flags) = CWProtocolRetrieve8(msgPtr);
	(*address) = (unsigned char*)CWProtocolRetrieveRawBytes(msgPtr, ETH_ALEN);
	(*capability) = CWProtocolRetrieve16(msgPtr);
	(*wlanID) = CWProtocolRetrieve8(msgPtr);
	
	(*supportedRatesLen) = len-(1+2+1+ETH_ALEN+2+1);

	CW_CREATE_ARRAY_CALLOC_ERR((*supportedRates), (*supportedRatesLen)+1, char,  return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	CW_COPY_MEMORY((*supportedRates), (unsigned char*)CWProtocolRetrieveRawBytes(msgPtr, (*supportedRatesLen)), (*supportedRatesLen));
	
	CWParseMessageElementEnd();
}

/* +++++++++++++++++++++++++ Elena Agostini - 09/2014: NEW IEEE BINDING +++++++++++++++++++++++++ */
CWBool CWParseACAddWlan(CWProtocolMessage *msgPtr, int len, ACInterfaceRequestInfo * valPtr) {
	unsigned short int capabilityInfo=0;
	int index=0;
	
	CWParseMessageElementStart();
	
	valPtr->operation=CW_OP_ADD_WLAN;
	//Radio ID
	valPtr->radioID = CWProtocolRetrieve8(msgPtr);
	//Wlan ID
	valPtr->wlanID = CWProtocolRetrieve8(msgPtr);
	//Capability
	valPtr->capabilityBit = CWProtocolRetrieve16(msgPtr);
	//key Index
	valPtr->keyIndex = CWProtocolRetrieve8(msgPtr);
	//Key Status
	valPtr->keyStatus = CWProtocolRetrieve8(msgPtr);
	//key Length
	valPtr->keyLength = CWProtocolRetrieve16(msgPtr);
	//Key
	CW_COPY_MEMORY(valPtr->key, CWProtocolRetrieveRawBytes(msgPtr, WLAN_KEY_LEN), WLAN_KEY_LEN);
	//Group TSC
	CW_COPY_MEMORY(valPtr->groupTSC, CWProtocolRetrieveRawBytes(msgPtr, WLAN_GROUP_TSC_LEN), WLAN_GROUP_TSC_LEN);
	//qos
	valPtr->qos = CWProtocolRetrieve8(msgPtr);
	//Auth TYpe
	valPtr->authType = CWProtocolRetrieve8(msgPtr);
	//MAC Mode
	valPtr->MACmode = CWProtocolRetrieve8(msgPtr);
	//Tunnel Mode
	valPtr->tunnelMode = CWProtocolRetrieve8(msgPtr);
	//Suppress SSID
	valPtr->suppressSSID = CWProtocolRetrieve8(msgPtr);
	//SSID
	CW_CREATE_ARRAY_CALLOC_ERR(valPtr->SSID, len-CW_MSG_IEEE_ADD_WLAN_MIN_LEN+1, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	CW_COPY_MEMORY(valPtr->SSID, CWProtocolRetrieveRawBytes(msgPtr, len-CW_MSG_IEEE_ADD_WLAN_MIN_LEN), len-CW_MSG_IEEE_ADD_WLAN_MIN_LEN);	
		
	CWParseMessageElementEnd();
}

CWBool CWParseACDelWlan(CWProtocolMessage *msgPtr, int len, ACInterfaceRequestInfo * valPtr) {
	int index=0;
	
	CWParseMessageElementStart();
	
	valPtr->operation=CW_OP_DEL_WLAN;
	//Radio ID
	valPtr->radioID = CWProtocolRetrieve8(msgPtr);
	//Wlan ID
	valPtr->wlanID = CWProtocolRetrieve8(msgPtr);
	
	CWParseMessageElementEnd();
}

CWBool CWParseACUpdateWlan(CWProtocolMessage *msgPtr, int len, ACInterfaceRequestInfo * valPtr) {
	unsigned short int capabilityInfo=0;
	int index=0;
	
	CWParseMessageElementStart();
	
	valPtr->operation=CW_OP_UPDATE_WLAN;
	//Radio ID
	valPtr->radioID = CWProtocolRetrieve8(msgPtr);
	//Wlan ID
	valPtr->wlanID = CWProtocolRetrieve8(msgPtr);
	//Capability
	valPtr->capabilityBit = CWProtocolRetrieve16(msgPtr);
	//key Index
	valPtr->keyIndex = CWProtocolRetrieve8(msgPtr);
	//Key Status
	valPtr->keyStatus = CWProtocolRetrieve8(msgPtr);
	//key Length
	valPtr->keyLength = CWProtocolRetrieve8(msgPtr);
	//Key
	CW_COPY_MEMORY(valPtr->key, CWProtocolRetrieveRawBytes(msgPtr, WLAN_KEY_LEN), WLAN_KEY_LEN);
	
	CWParseMessageElementEnd();
}

CWBool CWParseCWControlIPv4Addresses(CWProtocolMessage *msgPtr, int len, CWProtocolIPv4NetworkInterface *valPtr) {
	CWParseMessageElementStart();

	valPtr->addr.sin_addr.s_addr = htonl(CWProtocolRetrieve32(msgPtr));
	valPtr->addr.sin_family = AF_INET;
	valPtr->addr.sin_port = htons(CW_CONTROL_PORT);
	
	CWUseSockNtop((&(valPtr->addr)), CWDebugLog("Interface Address: %s", str););
	
	valPtr->WTPCount = CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("WTP Count: %d",	valPtr->WTPCount);
	
	CWParseMessageElementEnd();
}

CWBool CWParseCWControlIPv6Addresses(CWProtocolMessage *msgPtr, int len, CWProtocolIPv6NetworkInterface *valPtr) {
	CWParseMessageElementStart();
	
	CW_COPY_MEMORY(&(valPtr->addr.sin6_addr), CWProtocolRetrieveRawBytes(msgPtr, 16), 16);
	valPtr->addr.sin6_family = AF_INET6;
	valPtr->addr.sin6_port = htons(CW_CONTROL_PORT);
	
	CWUseSockNtop((&(valPtr->addr)), CWDebugLog("Interface Address: %s", str););
	
	valPtr->WTPCount = CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("WTP Count: %d",	valPtr->WTPCount);
	
	CWParseMessageElementEnd();
}

CWBool CWParseCWTimers (CWProtocolMessage *msgPtr, int len, CWProtocolConfigureResponseValues *valPtr)
{
	CWParseMessageElementStart();
	
	valPtr->discoveryTimer	= CWProtocolRetrieve8(msgPtr);	
//	CWDebugLog("Discovery Timer: %d", valPtr->discoveryTimer);
	valPtr->echoRequestTimer = CWProtocolRetrieve8(msgPtr);
//	CWDebugLog("Echo Timer: %d", valPtr->echoRequestTimer);
	
	CWParseMessageElementEnd();
}

/*
 * Elena Agostini - 02/2014
 *
 * ECN Support Msg Elem MUST be included in Join Request/Response Messages
 */
CWBool CWParseACECNSupport(CWProtocolMessage *msgPtr, int len, int *valPtr) {
	CWParseMessageElementStart();
	
	*valPtr = CWProtocolRetrieve8(msgPtr);
	
	CWParseMessageElementEnd();
}

CWBool CWParseDecryptErrorReportPeriod (CWProtocolMessage *msgPtr, int len, WTPDecryptErrorReportValues *valPtr)
{
	CWParseMessageElementStart();
	
	valPtr->radioID = CWProtocolRetrieve8(msgPtr);
	valPtr->reportInterval = CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("Decrypt Error Report Period: %d - %d", valPtr->radioID, valPtr->reportInterval);
	
	CWParseMessageElementEnd();
}

CWBool CWParseIdleTimeout (CWProtocolMessage *msgPtr, int len, CWProtocolConfigureResponseValues *valPtr)
{
	CWParseMessageElementStart();
	
	valPtr->idleTimeout = CWProtocolRetrieve32(msgPtr);	
//	CWDebugLog("Idle Timeout: %d", valPtr->idleTimeout);
		
	CWParseMessageElementEnd();
}

CWBool CWParseWTPFallback (CWProtocolMessage *msgPtr, int len, CWProtocolConfigureResponseValues *valPtr)
{
	CWParseMessageElementStart();
	
	valPtr->fallback = CWProtocolRetrieve8(msgPtr);	
//	CWDebugLog("WTP Fallback: %d", valPtr->fallback);
		
	CWParseMessageElementEnd();
}

void CWWTPResetRebootStatistics(WTPRebootStatisticsInfo *rebootStatistics)
{
	rebootStatistics->rebootCount=0;
	rebootStatistics->ACInitiatedCount=0;
	rebootStatistics->linkFailurerCount=0;
	rebootStatistics->SWFailureCount=0;
	rebootStatistics->HWFailuireCount=0;
	rebootStatistics->otherFailureCount=0;
	rebootStatistics->unknownFailureCount=0;
	rebootStatistics->lastFailureType=NOT_SUPPORTED;
}	

