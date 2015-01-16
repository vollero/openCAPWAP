/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	802.11 Information Elements
 * 
 ***************************************/
#include "CWWTP.h"

/* +++++++++++++++++++ ASSEMBLE +++++++++++++++++++++ */
/* FIXED LEN IE */
CWBool CW80211AssembleIEFrameControl(char * frame, int * offset, int frameType, int frameSubtype) {
	
	short int val = IEEE80211_FC(frameType, frameSubtype);
	
	CW_COPY_MEMORY(frame, &(val), LEN_IE_FRAME_CONTROL);
	(*offset) += LEN_IE_FRAME_CONTROL;
	
	return CW_TRUE;
}

CWBool CW80211AssembleIEFrameControlData(char * frame, int * offset, int frameType, int frameSubtype, int toDS, int fromDS) {
		
	short int val = IEEE80211_FC(frameType, frameSubtype);
	if(toDS == 1)
		SETBIT(val,8);
	else
		CLEARBIT(val,8);
		
	if(fromDS == 1)
		SETBIT(val,9);
	else
		CLEARBIT(val,9);

	CW_COPY_MEMORY(frame, &(val), LEN_IE_FRAME_CONTROL);
	(*offset) += LEN_IE_FRAME_CONTROL;
	
	return CW_TRUE;
}

CWBool CW80211AssembleIEDuration(char * frame, int * offset, int value) {
	
	short int val = htons(host_to_le16(value));
	
	CW_COPY_MEMORY(frame, &(val), LEN_IE_DURATION);
	(*offset) += LEN_IE_DURATION;
	
	return CW_TRUE;
}

CWBool CW80211AssembleIESequenceNumber(char * frame, int * offset, int value) {
	
	short int val = htons(host_to_le16(value));
	
	CW_COPY_MEMORY(frame, &(val), LEN_IE_SEQ_CTRL);
	(*offset) += LEN_IE_SEQ_CTRL;
	
	return CW_TRUE;
}


CWBool CW80211AssembleIEAddr(char * frame, int * offset, char * value) {
	//Broadcast
	if(value == NULL)
		memset(frame, 0xff, ETH_ALEN);
	else
		CW_COPY_MEMORY(frame, value, ETH_ALEN);
		
	(*offset) += ETH_ALEN;
	
	return CW_TRUE;
}

CWBool CW80211AssembleIEBeaconInterval(char * frame, int * offset, short int value) {
	
	short int val = htons(host_to_le16(value));
	
	CW_COPY_MEMORY(frame, &(val), LEN_IE_BEACON_INT);
	(*offset) += LEN_IE_BEACON_INT;
	
	return CW_TRUE;
}

CWBool CW80211AssembleIECapability(char * frame, int * offset, short int value) {

	CW_COPY_MEMORY(frame, &(value), LEN_IE_CAPABILITY);
	(*offset) += LEN_IE_CAPABILITY;
	
	return CW_TRUE;
}

CWBool CW80211AssembleIEAuthAlgoNum(char * frame, int * offset, short int value) {

	CW_COPY_MEMORY(frame, &(value), LEN_IE_AUTH_ALG);
	(*offset) += LEN_IE_AUTH_ALG;
	
	return CW_TRUE;
}

CWBool CW80211AssembleIEAuthTransNum(char * frame, int * offset, short int value) {

	CW_COPY_MEMORY(frame, &(value), LEN_IE_AUTH_TRANS);
	(*offset) += LEN_IE_AUTH_TRANS;
	
	return CW_TRUE;
}

CWBool CW80211AssembleIEStatusCode(char * frame, int * offset, short int value) {

	CW_COPY_MEMORY(frame, &(value), LEN_IE_STATUS_CODE);
	(*offset) += LEN_IE_STATUS_CODE;
	
	return CW_TRUE;
}

CWBool CW80211SetAssociationID(short int * assID) {
	
	srand(time(NULL));
	(*assID) = rand()%256;
	
	return CW_TRUE;
}

CWBool CW80211AssembleIEAssID(char * frame, int * offset, short int value) {
	value |= BIT(14);
	value |= BIT(15);
	CW_COPY_MEMORY(frame, &(value), LEN_IE_ASSOCIATION_ID);
	(*offset) += LEN_IE_ASSOCIATION_ID;
	
	return CW_TRUE;
}

/* VARIABLE LEN IE */

CWBool CW80211AssembleIESSID(char * frame, int * offset, char * value) {
	//Type
	unsigned char val=IE_TYPE_SSID;	
	CW_COPY_MEMORY(frame, &(val), IE_TYPE_LEN);
	(*offset) += IE_TYPE_LEN;
	
	//len
	val=strlen(value);
	CW_COPY_MEMORY((frame+IE_TYPE_LEN), &(val), IE_SIZE_LEN);
	(*offset) += IE_SIZE_LEN;
	
	//value
	CW_COPY_MEMORY((frame+IE_TYPE_LEN+IE_SIZE_LEN), value, strlen(value));
	(*offset) += strlen(value);

	return CW_TRUE;
}

float mapSupportedRatesValues(float rate, short int mode)
{
	
	if(mode == CW_80211_SUPP_RATES_CONVERT_VALUE_TO_FRAME)
	{
		if(rate == 1)
				return 2;
		if(rate == 2)
				return 4;
		if(rate == 5.5)
				return 11;
		if(rate == 6)
				return 12;
		if(rate == 9)
				return 18;
		if(rate == 11)
				return 22;
		if(rate == 12)
				return 24;
		if(rate == 18)
				return 36;
		if(rate == 22)
				return 44;
		if(rate == 24)
				return 48;
		if(rate == 33)
				return 66;
		if(rate == 36)
				return 72;
		if(rate == 48)
				return 96;
		if(rate == 54)
				return 108;
	}
	
	if(mode == CW_80211_SUPP_RATES_CONVERT_FRAME_TO_VALUE)
	{
		if(rate == 2)
				return 1;
		if(rate == 4)
				return 2;
		if(rate == 11)
				return 5.5;
		if(rate == 12)
				return 6;
		if(rate == 18)
				return 9;
		if(rate == 22)
				return 11;
		if(rate == 24)
				return 12;
		if(rate == 36)
				return 18;
		if(rate == 44)
				return 22;
		if(rate == 48)
				return 24;
		if(rate == 66)
				return 33;
		if(rate == 72)
				return 36;
		if(rate == 96)
				return 48;
		if(rate == 108)
				return 54;
	}
	
	return -1;
}

CWBool CW80211AssembleIESupportedRates(char * frame, int * offset, char * value, int numRates) {
	
	char val=IE_TYPE_SUPP_RATES;	
	CW_COPY_MEMORY(frame, &(val), IE_TYPE_LEN);
	(*offset) += IE_TYPE_LEN;
	
	if(numRates <= 0)
		return CW_FALSE;
		
	CW_COPY_MEMORY((frame+IE_TYPE_LEN), &(numRates), IE_SIZE_LEN);
	(*offset) += IE_SIZE_LEN;
	
	CW_COPY_MEMORY((frame+IE_TYPE_LEN+IE_SIZE_LEN), value, numRates);
	(*offset) += numRates;
	
	return CW_TRUE;
}

CWBool CW80211AssembleIEDSSS(char * frame, int * offset, char value) {
	
	char val=IE_TYPE_DSSS;	
	CW_COPY_MEMORY(frame, &(val), IE_TYPE_LEN);
	(*offset) += IE_TYPE_LEN;
	
	val=1;
	CW_COPY_MEMORY((frame+IE_TYPE_LEN), &(val), IE_SIZE_LEN);
	(*offset) += IE_SIZE_LEN;
	
	CW_COPY_MEMORY((frame+IE_TYPE_LEN+IE_SIZE_LEN), &(value), 1);
	(*offset) += 1;

	return CW_TRUE;
}

CWBool CW80211AssembleIEMaxIdlePeriod(char * frame, int * offset, short int value) {
	
	char val=IE_TYPE_BSS_MAX_IDLE_PERIOD;	
	CW_COPY_MEMORY(frame, &(val), IE_TYPE_LEN);
	(*offset) += IE_TYPE_LEN;
	
	val=300;
	CW_COPY_MEMORY((frame+IE_TYPE_LEN), &(val), IE_SIZE_LEN);
	(*offset) += IE_SIZE_LEN;
	
/*
		unsigned int val;
		*pos++ = WLAN_EID_BSS_MAX_IDLE_PERIOD;
		*pos++ = 3;
		val = hapd->conf->ap_max_inactivity;
		if (val > 68000)
			val = 68000;
		val *= 1000;
		val /= 1024;
		if (val == 0)
			val = 1;
		if (val > 65535)
			val = 65535;
		WPA_PUT_LE16(pos, val);
		pos += 2;
		*pos++ = 0x00; // TODO: Protected Keep-Alive Required
 */
	CW_COPY_MEMORY((frame+IE_TYPE_LEN+IE_SIZE_LEN), &(value), 1);
	(*offset) += 1;

	return CW_TRUE;
}

//802.3
CWBool CW8023AssembleHdrLength(char * frame, int * offset, short int value) {

	CW_COPY_MEMORY(frame, &(value), 2);
	(*offset) += 2;
	
	return CW_TRUE;
}
/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

/* ------------------ PARSE ---------------------- */
CWBool CW80211ParseFrameIEControl(char * frameReceived, int * offsetFrameReceived, short int * value) {
	
	CW_COPY_MEMORY(value,frameReceived, LEN_IE_FRAME_CONTROL);
	(*offsetFrameReceived) += LEN_IE_FRAME_CONTROL;
	
	return CW_TRUE;
}

CWBool CW80211ParseFrameIEDuration(char * frameReceived, int * offsetFrameReceived, short int * value) {
	
	CW_COPY_MEMORY(value,frameReceived, LEN_IE_DURATION);
	(*offsetFrameReceived) += LEN_IE_DURATION;
	
	return CW_TRUE;
}

CWBool CW80211ParseFrameIEAddr(char * frameReceived, int * offsetFrameReceived, unsigned char * addr) {
	
	CW_COPY_MEMORY(addr, frameReceived, ETH_ALEN);
	(*offsetFrameReceived) += ETH_ALEN;
	
	return CW_TRUE;
}

CWBool CW80211ParseFrameIESeqCtrl(char * frameReceived, int * offsetFrameReceived, short int * value) {
	
	CW_COPY_MEMORY(value,frameReceived, LEN_IE_SEQ_CTRL);
	(*offsetFrameReceived) += LEN_IE_SEQ_CTRL;
	
	return CW_TRUE;
}

CWBool CW80211ParseFrameIEStatusCode(char * frameReceived, int * offsetFrameReceived, short int * value) {
	
	CW_COPY_MEMORY(value,frameReceived, LEN_IE_STATUS_CODE);
	(*offsetFrameReceived) += LEN_IE_STATUS_CODE;
	
	return CW_TRUE;
}

CWBool CW80211ParseFrameIEReasonCode(char * frameReceived, int * offsetFrameReceived, short int * value) {
	
	CW_COPY_MEMORY(value,frameReceived, LEN_IE_REASON_CODE);
	(*offsetFrameReceived) += LEN_IE_REASON_CODE;
	
	return CW_TRUE;
}

CWBool CW80211ParseFrameIEAuthAlgo(char * frameReceived, int * offsetFrameReceived, short int * value) {
	
	CW_COPY_MEMORY(value,frameReceived, LEN_IE_AUTH_ALG);
	(*offsetFrameReceived) += LEN_IE_AUTH_ALG;
	
	return CW_TRUE;
}

CWBool CW80211ParseFrameIEAuthTransaction(char * frameReceived, int * offsetFrameReceived, short int * value) {
	
	CW_COPY_MEMORY(value,frameReceived, LEN_IE_AUTH_TRANS);
	(*offsetFrameReceived) += LEN_IE_AUTH_TRANS;
	
	return CW_TRUE;
}

CWBool CW80211ParseFrameIECapability(char * frameReceived, int * offsetFrameReceived, short int * value) {
	
	CW_COPY_MEMORY(value,frameReceived, LEN_IE_CAPABILITY);
	(*offsetFrameReceived) += LEN_IE_CAPABILITY;
	
	return CW_TRUE;
}

CWBool CW80211ParseFrameIEAssID(char * frameReceived, int * offsetFrameReceived, short int * value) {
	
	CW_COPY_MEMORY(value,frameReceived, LEN_IE_ASSOCIATION_ID);
	(*offsetFrameReceived) += LEN_IE_ASSOCIATION_ID;
	
	return CW_TRUE;
}

CWBool CW80211ParseFrameIEListenInterval(char * frameReceived, int * offsetFrameReceived, short int * value) {
	
	CW_COPY_MEMORY(value,frameReceived, LEN_IE_LISTEN_INTERVAL);
	(*offsetFrameReceived) += LEN_IE_LISTEN_INTERVAL;
	
	return CW_TRUE;
}

CWBool CW80211ParseFrameIESSID(char * frameReceived, int * offsetFrameReceived, char ** value) {
	
	if(frameReceived[0] != IE_TYPE_SSID)
		return CW_FALSE;
	
	(*offsetFrameReceived)++;
	
	short int len = frameReceived[1];
	if(len == 0)
		return CW_FALSE;
		
	(*offsetFrameReceived)++;
	
	CW_CREATE_ARRAY_CALLOC_ERR((*value), len+1, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return CW_FALSE;});
	CW_COPY_MEMORY((*value),&(frameReceived[2]), len);
	(*offsetFrameReceived) += len;
	
	return CW_TRUE;
}

CWBool CW80211ParseFrameIESupportedRates(char * frameReceived, int * offsetFrameReceived, char ** value, int * lenIE) {
	
	if(frameReceived[0] != IE_TYPE_SUPP_RATES)
		return CW_FALSE;
	
	(*offsetFrameReceived)++;
	
	short int len = frameReceived[1];
	if(len == 0)
		return CW_FALSE;
	
	(*offsetFrameReceived)++;	

	(*lenIE) = len;
	
	CW_CREATE_ARRAY_CALLOC_ERR((*value), len+1, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return CW_FALSE;});
	CW_COPY_MEMORY((*value),&(frameReceived[2]), len);
	(*offsetFrameReceived) += len;
	
	return CW_TRUE;
}

/*
 * Scan ieee80211 frame body arguments
 */
ParseRes ieee802_11_parse_elems(const u8 *start, size_t len,
				struct ieee802_11_elems *elems,
				int show_errors)
{
	size_t left = len;
	const u8 *pos = start;
	int unknown = 0;

	os_memset(elems, 0, sizeof(*elems));

	while (left >= 2) {
		u8 id, elen;

		id = *pos++;
		elen = *pos++;
		left -= 2;

		if (elen > left) {
			if (show_errors) {
				CWLog("IEEE 802.11 element "
					   "parse failed (id=%d elen=%d "
					   "left=%lu)",
					   id, elen, (unsigned long) left);
				//wpa_hexdump(MSG_MSGDUMP, "IEs", start, len);
			}
			return ParseFailed;
		}

		switch (id) {
		case WLAN_EID_SSID:
			elems->ssid = pos;
			elems->ssid_len = elen;
			CWLog("SSID[0]: %c", elems->ssid[0]);
			break;
		case WLAN_EID_SUPP_RATES:
			elems->supp_rates = pos;
			elems->supp_rates_len = elen;
			CWLog("SUPP RATES[0]: %c", elems->supp_rates[0]);
			break;
		case WLAN_EID_DS_PARAMS:
			elems->ds_params = pos;
			elems->ds_params_len = elen;
			break;
/*	
		case WLAN_EID_CF_PARAMS:
		case WLAN_EID_TIM:
			break;
		case WLAN_EID_CHALLENGE:
			elems->challenge = pos;
			elems->challenge_len = elen;
			break;
		case WLAN_EID_ERP_INFO:
			elems->erp_info = pos;
			elems->erp_info_len = elen;
			break;
		case WLAN_EID_EXT_SUPP_RATES:
			elems->ext_supp_rates = pos;
			elems->ext_supp_rates_len = elen;
			break;
		case WLAN_EID_VENDOR_SPECIFIC:
			if (ieee802_11_parse_vendor_specific(pos, elen,
							     elems,
							     show_errors))
				unknown++;
			break;
		
		case WLAN_EID_RSN:
			elems->rsn_ie = pos;
			elems->rsn_ie_len = elen;
			break;
		case WLAN_EID_PWR_CAPABILITY:
			break;
		case WLAN_EID_SUPPORTED_CHANNELS:
			elems->supp_channels = pos;
			elems->supp_channels_len = elen;
			break;
		case WLAN_EID_MOBILITY_DOMAIN:
			elems->mdie = pos;
			elems->mdie_len = elen;
			break;
		case WLAN_EID_FAST_BSS_TRANSITION:
			elems->ftie = pos;
			elems->ftie_len = elen;
			break;
		case WLAN_EID_TIMEOUT_INTERVAL:
			elems->timeout_int = pos;
			elems->timeout_int_len = elen;
			break;
		case WLAN_EID_HT_CAP:
			elems->ht_capabilities = pos;
			elems->ht_capabilities_len = elen;
			break;
		case WLAN_EID_HT_OPERATION:
			elems->ht_operation = pos;
			elems->ht_operation_len = elen;
			break;
		case WLAN_EID_VHT_CAP:
			elems->vht_capabilities = pos;
			elems->vht_capabilities_len = elen;
			break;
		case WLAN_EID_VHT_OPERATION:
			elems->vht_operation = pos;
			elems->vht_operation_len = elen;
			break;
		case WLAN_EID_VHT_OPERATING_MODE_NOTIFICATION:
			if (elen != 1)
				break;
			elems->vht_opmode_notif = pos;
			break;
		case WLAN_EID_LINK_ID:
			if (elen < 18)
				break;
			elems->link_id = pos;
			break;
		case WLAN_EID_INTERWORKING:
			elems->interworking = pos;
			elems->interworking_len = elen;
			break;
		case WLAN_EID_QOS_MAP_SET:
			if (elen < 16)
				break;
			elems->qos_map_set = pos;
			elems->qos_map_set_len = elen;
			break;
		case WLAN_EID_EXT_CAPAB:
			elems->ext_capab = pos;
			elems->ext_capab_len = elen;
			break;
		case WLAN_EID_BSS_MAX_IDLE_PERIOD:
			if (elen < 3)
				break;
			elems->bss_max_idle_period = pos;
			break;
		case WLAN_EID_SSID_LIST:
			elems->ssid_list = pos;
			elems->ssid_list_len = elen;
			break;
*/
		default:
			unknown++;
			if (!show_errors)
				break;
			CWLog("IEEE 802.11 element parse "
				   "ignored unknown element (id=%d elen=%d)",
				   id, elen);
			break;
		}

		left -= elen;
		pos += elen;
	}

	if (left)
		return ParseFailed;

	return unknown ? ParseUnknown : ParseOK;
}

/* ----------------------------------------------- */

/* +++++++++++++++++++++ ASSEMBLE +++++++++++++++++++++++ */
//Genera beacon frame
char * CW80211AssembleBeacon(WTPBSSInfo * WTPBSSInfoPtr, int *offset) {

	char * beaconFrame;
	CW_CREATE_ARRAY_CALLOC_ERR(beaconFrame, (MGMT_FRAME_FIXED_LEN_BEACON+MGMT_FRAME_IE_FIXED_LEN+strlen(WTPBSSInfoPtr->interfaceInfo->SSID)+1), char, { CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return NULL;}); //MAC80211_HEADER_FIXED_LEN+MAC80211_BEACON_BODY_MANDATORY_MIN_LEN+2+strlen(interfaceInfo->SSID)+10+1), char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	(*offset)=0;
	
	//frame control: 2 byte
	if(!CW80211AssembleIEFrameControl(&(beaconFrame[(*offset)]), offset, WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_BEACON))
		return NULL;
	
	//duration: 2 byte
	if(!CW80211AssembleIEDuration(&(beaconFrame[(*offset)]), offset, 0))
		return NULL;
	
	//da: 6 byte. Broadcast
	if(!CW80211AssembleIEAddr(&(beaconFrame[(*offset)]), offset, NULL))
			return NULL;
	
	//sa: 6 byte
	if(!CW80211AssembleIEAddr(&(beaconFrame[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->MACaddr))
			return NULL;

	//bssid: 6 byte
	if(!CW80211AssembleIEAddr(&(beaconFrame[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->BSSID))
			return NULL;
	
	//2 (sequence ctl) + 8 (timestamp): vengono impostati in automatico
	(*offset) += LEN_IE_SEQ_CTRL;
	(*offset) += LEN_IE_TIMESTAMP;
	
	//beacon interval: 2 byte
	if(!CW80211AssembleIEBeaconInterval(&(beaconFrame[(*offset)]), offset, 100))
			return NULL;
	
	//capability: 2 byte
	if(!CW80211AssembleIECapability(&(beaconFrame[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->capabilityBit))
			return NULL;
			
	//SSID
	if(!CW80211AssembleIESSID(&(beaconFrame[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->SSID))
		return NULL;
	
	return beaconFrame;
}

//Genera probe response
char * CW80211AssembleProbeResponse(WTPBSSInfo * WTPBSSInfoPtr, struct CWFrameProbeRequest *request, int *offset)
{
	if(request == NULL)
		return NULL;
		
	CWLog("[CW80211] Assemble Probe response per SSID: %s", WTPBSSInfoPtr->interfaceInfo->ifName);
	(*offset)=0;
	/* ***************** PROBE RESPONSE FRAME FIXED ******************** */
	char * frameProbeResponse;
	CW_CREATE_ARRAY_CALLOC_ERR(frameProbeResponse, MGMT_FRAME_FIXED_LEN_PROBE_RESP+MGMT_FRAME_IE_FIXED_LEN*3+strlen(WTPBSSInfoPtr->interfaceInfo->SSID)+CW_80211_MAX_SUPP_RATES+1+1, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return NULL;});
	
	//frame control: 2 byte
	if(!CW80211AssembleIEFrameControl(&(frameProbeResponse[(*offset)]), offset, WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_PROBE_RESP))
		return NULL;
	
	//duration: 2 byte
	if(!CW80211AssembleIEDuration(&(frameProbeResponse[(*offset)]), offset, 0))
		return NULL;
	
	//da: 6 byte
	if(request)
	{
		if(!CW80211AssembleIEAddr(&(frameProbeResponse[(*offset)]), offset, request->SA))
			return NULL;
	}
	else
	{
		if(!CW80211AssembleIEAddr(&(frameProbeResponse[(*offset)]), offset, NULL))
			return NULL;
	}

	//sa: 6 byte
	if(!CW80211AssembleIEAddr(&(frameProbeResponse[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->MACaddr))
			return NULL;

	//bssid: 6 byte
	if(!CW80211AssembleIEAddr(&(frameProbeResponse[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->BSSID))
			return NULL;
	
	//2 (sequence ctl) + 8 (timestamp): vengono impostati in automatico
	(*offset) += LEN_IE_SEQ_CTRL;
	(*offset) += LEN_IE_TIMESTAMP;
	
	//beacon interval: 2 byte
	if(!CW80211AssembleIEBeaconInterval(&(frameProbeResponse[(*offset)]), offset, 100))
			return NULL;
	
	//capability: 2 byte
	if(!CW80211AssembleIECapability(&(frameProbeResponse[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->capabilityBit))
			return NULL;

	/* *************************************************** */
		
	//SSID
	if(!CW80211AssembleIESSID(&(frameProbeResponse[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->SSID))
		return NULL;

	//Supported Rates
	int indexRates=0;
	unsigned char suppRate[CW_80211_MAX_SUPP_RATES];
	for(indexRates=0; indexRates < WTP_NL80211_BITRATE_NUM && indexRates < CW_80211_MAX_SUPP_RATES && indexRates < WTPBSSInfoPtr->phyInfo->lenSupportedRates; indexRates++)
		suppRate[indexRates] = (char) mapSupportedRatesValues(WTPBSSInfoPtr->phyInfo->phyMbpsSet[indexRates], CW_80211_SUPP_RATES_CONVERT_VALUE_TO_FRAME);
	
	if(!CW80211AssembleIESupportedRates(&(frameProbeResponse[(*offset)]), offset, suppRate, indexRates))
		return NULL;

	//DSSS
	unsigned char channel = CW_WTP_DEFAULT_RADIO_CHANNEL+1;
	if(!CW80211AssembleIEDSSS(&(frameProbeResponse[(*offset)]), offset, channel))
		return NULL;
		
	return frameProbeResponse;
}

//Genera auth response
char * CW80211AssembleAuthResponse(char * addrAP, struct CWFrameAuthRequest *request, int *offset)
{
	if(request == NULL)
		return NULL;
		
	CWLog("[CW80211] Assemble Auth response");
	(*offset)=0;

	/* ***************** FRAME FIXED ******************** */
	char * frameAuthResponse;
	CW_CREATE_ARRAY_CALLOC_ERR(frameAuthResponse, MGMT_FRAME_FIXED_LEN_AUTH, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return NULL;});
	
	//frame control: 2 byte
	if(!CW80211AssembleIEFrameControl(&(frameAuthResponse[(*offset)]), offset, WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_AUTH))
		return NULL;
	
	//duration: 2 byte
	if(!CW80211AssembleIEDuration(&(frameAuthResponse[(*offset)]), offset, 0))
		return NULL;
	
	//da: 6 byte
	if(request)
	{
		if(!CW80211AssembleIEAddr(&(frameAuthResponse[(*offset)]), offset, request->SA))
			return NULL;
	}
	else
	{
		if(!CW80211AssembleIEAddr(&(frameAuthResponse[(*offset)]), offset, NULL))
			return NULL;
	}
	
	//sa: 6 byte
	if(!CW80211AssembleIEAddr(&(frameAuthResponse[(*offset)]), offset, addrAP))
			return NULL;
	
	//bssid: 6 byte
	if(!CW80211AssembleIEAddr(&(frameAuthResponse[(*offset)]), offset, addrAP))
			return NULL;
	
	//2 (sequence ctl)
	(*offset) += LEN_IE_SEQ_CTRL;
	
	//Auth Algorithm Number: 2 byte
	if(!CW80211AssembleIEAuthAlgoNum(&(frameAuthResponse[(*offset)]), offset, IE_AUTH_OPEN_SYSTEM))
			return NULL;

	//Auth Algorithm Number: 2 byte (valore seq: 2)
	if(!CW80211AssembleIEAuthTransNum(&(frameAuthResponse[(*offset)]), offset, 2))
		return NULL;

	//Status Code: 2 byte (valore: 0 status code success)
	if(!CW80211AssembleIEStatusCode(&(frameAuthResponse[(*offset)]), offset, IE_STATUS_CODE_SUCCESS))
		return NULL;
	
	/* ************************************************* */
		
	return frameAuthResponse;
}


//Genera association response
char * CW80211AssembleAssociationResponse(WTPBSSInfo * WTPBSSInfoPtr, WTPSTAInfo * thisSTA, struct CWFrameAssociationRequest *request, int *offset)
{
	if(request == NULL)
		return NULL;
		
	CWLog("[CW80211] Assemble Association response");
	
	(*offset)=0;
	
	/* ***************** FRAME FIXED ******************** */
	char * frameAssociationResponse;
	CW_CREATE_ARRAY_CALLOC_ERR(frameAssociationResponse, MGMT_FRAME_FIXED_LEN_ASSOCIATION+MGMT_FRAME_IE_FIXED_LEN*3+CW_80211_MAX_SUPP_RATES+1, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return NULL;});
	
	//frame control: 2 byte
	if(!CW80211AssembleIEFrameControl(&(frameAssociationResponse[(*offset)]), offset, WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_ASSOC_RESP))
		return NULL;
	
	//duration: 2 byte
	if(!CW80211AssembleIEDuration(&(frameAssociationResponse[(*offset)]), offset, 0))
		return NULL;
	
	//da: 6 byte
	if(request)
	{
		if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, request->SA))
			return NULL;
	}
	else
	{
		if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, NULL))
			return NULL;
	}
	
	//sa: 6 byte
	if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->MACaddr))
			return NULL;
	
	//bssid: 6 byte
	if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->BSSID))
			return NULL;
	
	//2 (sequence ctl)
	(*offset) += LEN_IE_SEQ_CTRL;
	
	//capability: 2 byte
	if(!CW80211AssembleIECapability(&(frameAssociationResponse[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->capabilityBit))
			return NULL;
	/* ************************************************* */

	//Status Code: 2 byte (valore: 0 status code success)
	if(!CW80211AssembleIEStatusCode(&(frameAssociationResponse[(*offset)]), offset, IE_STATUS_CODE_SUCCESS))
		return NULL;
	
	//Association ID: 2 byte
	if(!CW80211AssembleIEAssID(&(frameAssociationResponse[(*offset)]), offset, thisSTA->staAID))
		return NULL;
	
	//Supported Rates
	//TODO: Capability Re-set? Use STA capability value?
	int indexRates=0;
	unsigned char suppRate[CW_80211_MAX_SUPP_RATES];
	for(indexRates=0; indexRates < WTP_NL80211_BITRATE_NUM && indexRates < CW_80211_MAX_SUPP_RATES && indexRates < WTPBSSInfoPtr->phyInfo->lenSupportedRates; indexRates++)
		suppRate[indexRates] = (char) mapSupportedRatesValues(WTPBSSInfoPtr->phyInfo->phyMbpsSet[indexRates], CW_80211_SUPP_RATES_CONVERT_VALUE_TO_FRAME);
		
	if(!CW80211AssembleIESupportedRates(&(frameAssociationResponse[(*offset)]), offset, suppRate, indexRates))
		return NULL;
	
	/*
	 * idle timeout
	if(!CW80211AssembleIESupportedRates(&(frameAssociationResponse[(*offset)]), offset, suppRate, indexRates))
		return NULL;
	*/

	return frameAssociationResponse;
}

//Genera reassociation response
char * CW80211AssembleReassociationResponse(WTPBSSInfo * WTPBSSInfoPtr, WTPSTAInfo * thisSTA, struct CWFrameAssociationRequest *request, int *offset)
{
	if(request == NULL)
		return NULL;
		
	CWLog("[CW80211] Assemble Association response");
	
	(*offset)=0;
	
	/* ***************** FRAME FIXED ******************** */
	char * frameAssociationResponse;
	CW_CREATE_ARRAY_CALLOC_ERR(frameAssociationResponse, MGMT_FRAME_FIXED_LEN_ASSOCIATION+MGMT_FRAME_IE_FIXED_LEN*3+CW_80211_MAX_SUPP_RATES+1, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return NULL;});
	
	//frame control: 2 byte
	if(!CW80211AssembleIEFrameControl(&(frameAssociationResponse[(*offset)]), offset, WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_REASSOC_RESP))
		return NULL;
	
	//duration: 2 byte
	if(!CW80211AssembleIEDuration(&(frameAssociationResponse[(*offset)]), offset, 0))
		return NULL;
	
	//da: 6 byte
	if(request)
	{
		if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, request->SA))
			return NULL;
	}
	else
	{
		if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, NULL))
			return NULL;
	}
	
	//sa: 6 byte
	if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->MACaddr))
			return NULL;
	
	//bssid: 6 byte
	if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->BSSID))
			return NULL;
	
	//2 (sequence ctl)
	(*offset) += LEN_IE_SEQ_CTRL;
	
	//capability: 2 byte
	if(!CW80211AssembleIECapability(&(frameAssociationResponse[(*offset)]), offset, WTPBSSInfoPtr->interfaceInfo->capabilityBit))
			return NULL;
	/* ************************************************* */

	//Status Code: 2 byte (valore: 0 status code success)
	if(!CW80211AssembleIEStatusCode(&(frameAssociationResponse[(*offset)]), offset, IE_STATUS_CODE_SUCCESS))
		return NULL;
	
	//Association ID: 2 byte
	if(!CW80211AssembleIEAssID(&(frameAssociationResponse[(*offset)]), offset, thisSTA->staAID))
		return NULL;
	
	//Supported Rates
	//TODO: Capability Re-set? Use STA capability value?
	int indexRates=0;
	unsigned char suppRate[CW_80211_MAX_SUPP_RATES];
	for(indexRates=0; indexRates < WTP_NL80211_BITRATE_NUM && indexRates < CW_80211_MAX_SUPP_RATES && indexRates < WTPBSSInfoPtr->phyInfo->lenSupportedRates; indexRates++)
		suppRate[indexRates] = (char) mapSupportedRatesValues(WTPBSSInfoPtr->phyInfo->phyMbpsSet[indexRates], CW_80211_SUPP_RATES_CONVERT_VALUE_TO_FRAME);
		
	if(!CW80211AssembleIESupportedRates(&(frameAssociationResponse[(*offset)]), offset, suppRate, indexRates))
		return NULL;
	
	//idle timeout
	
	return frameAssociationResponse;
}

char * CW80211AssembleAssociationResponseAC(unsigned char * MACAddr, unsigned char * BSSID,  short int capabilityBit, short int staAID, unsigned char * suppRate, int suppRatesLen, struct CWFrameAssociationRequest *request, int *offset)
{
	if(request == NULL || BSSID == NULL || MACAddr == NULL || suppRate == NULL)
		return NULL;
		
	CWLog("[CW80211] Assemble Association response AC side");
	
	(*offset)=0;
	
	/* ***************** FRAME FIXED ******************** */
	char * frameAssociationResponse;
	CW_CREATE_ARRAY_CALLOC_ERR(frameAssociationResponse, MGMT_FRAME_FIXED_LEN_ASSOCIATION+MGMT_FRAME_IE_FIXED_LEN+CW_80211_MAX_SUPP_RATES+1, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return NULL;});
	
	//frame control: 2 byte
	if(!CW80211AssembleIEFrameControl(&(frameAssociationResponse[(*offset)]), offset, WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_ASSOC_RESP))
		return NULL;
	
	//duration: 2 byte
	if(!CW80211AssembleIEDuration(&(frameAssociationResponse[(*offset)]), offset, 0))
		return NULL;
	
	//da: 6 byte
	if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, request->SA))
		return NULL;
	
	//sa: 6 byte
	if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, MACAddr))
			return NULL;

	//bssid: 6 byte
	if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, BSSID))
			return NULL;

	//2 (sequence ctl)
	(*offset) += LEN_IE_SEQ_CTRL;
	
	//capability: 2 byte
	if(!CW80211AssembleIECapability(&(frameAssociationResponse[(*offset)]), offset, capabilityBit))
			return NULL;
	/* ************************************************* */

	//Status Code: 2 byte (valore: 0 status code success)
	if(!CW80211AssembleIEStatusCode(&(frameAssociationResponse[(*offset)]), offset, IE_STATUS_CODE_SUCCESS))
		return NULL;
	
	//Association ID: 2 byte
	if(!CW80211AssembleIEAssID(&(frameAssociationResponse[(*offset)]), offset, staAID))
		return NULL;
	
	if(suppRatesLen > 0)
	{
		//Supported Rates
		if(!CW80211AssembleIESupportedRates(&(frameAssociationResponse[(*offset)]), offset, suppRate, suppRatesLen))
			return NULL;
	}
	
	return frameAssociationResponse;
}

char * CW80211AssembleReassociationResponseAC(unsigned char * MACAddr, unsigned char * BSSID,  short int capabilityBit, short int staAID, unsigned char * suppRate, int suppRatesLen, struct CWFrameAssociationRequest *request, int *offset)
{
	if(request == NULL || BSSID == NULL || MACAddr == NULL || suppRate == NULL)
		return NULL;
		
	CWLog("[CW80211] Assemble Reassociation response AC side");
	
	(*offset)=0;
	
	/* ***************** FRAME FIXED ******************** */
	char * frameAssociationResponse;
	CW_CREATE_ARRAY_CALLOC_ERR(frameAssociationResponse, MGMT_FRAME_FIXED_LEN_ASSOCIATION+MGMT_FRAME_IE_FIXED_LEN+CW_80211_MAX_SUPP_RATES+1, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return NULL;});
	
	//frame control: 2 byte
	if(!CW80211AssembleIEFrameControl(&(frameAssociationResponse[(*offset)]), offset, WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_REASSOC_RESP))
		return NULL;
	
	//duration: 2 byte
	if(!CW80211AssembleIEDuration(&(frameAssociationResponse[(*offset)]), offset, 0))
		return NULL;
	
	//da: 6 byte
	if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, request->SA))
		return NULL;
	
	//sa: 6 byte
	if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, MACAddr))
			return NULL;

	//bssid: 6 byte
	if(!CW80211AssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, BSSID))
			return NULL;

	//2 (sequence ctl)
	(*offset) += LEN_IE_SEQ_CTRL;
	
	//capability: 2 byte
	if(!CW80211AssembleIECapability(&(frameAssociationResponse[(*offset)]), offset, capabilityBit))
			return NULL;
	/* ************************************************* */

	//Status Code: 2 byte (valore: 0 status code success)
	if(!CW80211AssembleIEStatusCode(&(frameAssociationResponse[(*offset)]), offset, IE_STATUS_CODE_SUCCESS))
		return NULL;
	
	//Association ID: 2 byte
	if(!CW80211AssembleIEAssID(&(frameAssociationResponse[(*offset)]), offset, staAID))
		return NULL;
	
	//Supported Rates
	if(!CW80211AssembleIESupportedRates(&(frameAssociationResponse[(*offset)]), offset, suppRate, suppRatesLen))
		return NULL;
	
	return frameAssociationResponse;
}


char *  CW80211AssembleACK(WTPBSSInfo * WTPBSSInfoPtr, char * DA, int *offset) {
	if(DA == NULL)
		return NULL;
		
	CWLog("[CW80211] Assemble ACK response per SSID: %s", WTPBSSInfoPtr->interfaceInfo->ifName);
	(*offset)=0;
	/* ***************** PROBE RESPONSE FRAME FIXED ******************** */
	char * frameACK;
	CW_CREATE_ARRAY_CALLOC_ERR(frameACK, DATA_FRAME_FIXED_LEN_ACK+1, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return NULL;});
	
	//frame control: 2 byte
	if(!CW80211AssembleIEFrameControl(&(frameACK[(*offset)]), offset, WLAN_FC_TYPE_DATA, WLAN_FC_STYPE_ACK))
		return NULL;
	
	//duration: 2 byte
	if(!CW80211AssembleIEDuration(&(frameACK[(*offset)]), offset, 0))
		return NULL;
	
	//da: 6 byte
	if(!CW80211AssembleIEAddr(&(frameACK[(*offset)]), offset, DA))
		return NULL;
	
	return frameACK;
}

unsigned char *  CW80211AssembleDataFrameHdr(unsigned char * SA, unsigned char * DA, unsigned char * BSSID, int *offset, int toDS, int fromDS) {
	if(DA == NULL || SA == NULL)
		return NULL;
	
//	CWLog("****** 802.11 FRAME HDR ******");
	(*offset)=0;

	unsigned char * frameACK;
	CW_CREATE_ARRAY_CALLOC_ERR(frameACK, HLEN_80211, unsigned char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return NULL;});
	
	//frame control: 2 byte
	if(!CW80211AssembleIEFrameControlData(&(frameACK[(*offset)]), offset, WLAN_FC_TYPE_DATA, WLAN_FC_STYPE_DATA, toDS, fromDS))
		return NULL;
	
	//duration: 2 byte
	if(!CW80211AssembleIEDuration(&(frameACK[(*offset)]), offset, 0))
		return NULL;
	
	if(toDS == 1 && fromDS == 0)
	{
		//BSSID: 6 byte
		if(!CW80211AssembleIEAddr(&(frameACK[(*offset)]), offset, BSSID))
			return NULL;
/*		if(BSSID != NULL)
			CWLog("** BSSID: %02x:%02x:%02x:%02x:%02x", (int)BSSID[0], (int)BSSID[1], (int)BSSID[2], (int)BSSID[3], (int)BSSID[4], (int)BSSID[5]);
*/
		//SA: 6 byte
		if(!CW80211AssembleIEAddr(&(frameACK[(*offset)]), offset, SA))
			return NULL;
//		CWLog("** SA: %02x:%02x:%02x:%02x:%02x", (int)SA[0], (int)SA[1], (int)SA[2], (int)SA[3], (int)SA[4], (int)SA[5]);
		
		//DA: 6 byte
		if(!CW80211AssembleIEAddr(&(frameACK[(*offset)]), offset, DA))
			return NULL;
//		CWLog("** DA: %02x:%02x:%02x:%02x:%02x", (int)DA[0], (int)DA[1], (int)DA[2], (int)DA[3], (int)DA[4], (int)DA[5]);
	}
	else if(fromDS == 1 && toDS == 0)
	{
		//DA: 6 byte
		if(!CW80211AssembleIEAddr(&(frameACK[(*offset)]), offset, DA))
			return NULL;
//		CWLog("** DA: %02x:%02x:%02x:%02x:%02x", (int)DA[0], (int)DA[1], (int)DA[2], (int)DA[3], (int)DA[4], (int)DA[5]);
		
		//BSSID: 6 byte
		if(!CW80211AssembleIEAddr(&(frameACK[(*offset)]), offset, BSSID))
			return NULL;
		
/*		if(BSSID != NULL)
			CWLog("** BSSID: %02x:%02x:%02x:%02x:%02x", (int)BSSID[0], (int)BSSID[1], (int)BSSID[2], (int)BSSID[3], (int)BSSID[4], (int)BSSID[5]);
*/
		//SA: 6 byte
		if(!CW80211AssembleIEAddr(&(frameACK[(*offset)]), offset, SA))
			return NULL;
//		CWLog("** SA: %02x:%02x:%02x:%02x:%02x", (int)SA[0], (int)SA[1], (int)SA[2], (int)SA[3], (int)SA[4], (int)SA[5]);
	}
	else return NULL;
	
	//2 (sequence ctl)
	if(!CW80211AssembleIESequenceNumber(&(frameACK[(*offset)]), offset, 0))
		return NULL;
		
	return frameACK;
}
/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

/* -------------------- PARSE -------------------- */
CWBool CW80211ParseProbeRequest(char * frame, struct CWFrameProbeRequest * probeRequest) {
	int offset=0;
	
	if(probeRequest == NULL)
		return CW_FALSE;
	
	//Frame Control
	if(!CW80211ParseFrameIEControl(frame, &(offset), &(probeRequest->frameControl)))
		return CW_FALSE;
	
	//Duration
	if(!CW80211ParseFrameIEControl((frame+offset), &(offset), &(probeRequest->duration)))
		return CW_FALSE;
		
	//DA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), probeRequest->DA))
		return CW_FALSE;
	
	//SA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), probeRequest->SA))
		return CW_FALSE;
		
	//BSSID
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), probeRequest->BSSID))
		return CW_FALSE;
	
	//Seq Ctrl
	if(!CW80211ParseFrameIESeqCtrl((frame+offset), &(offset), &(probeRequest->seqCtrl)))
		return CW_FALSE;
	
	//Add parsing variable elements
	if(!CW80211ParseFrameIESSID((frame+offset), &(offset), &(probeRequest->SSID)))
		return CW_FALSE;

	return CW_TRUE;
}

CWBool CW80211ParseAuthRequest(char * frame, struct CWFrameAuthRequest * authRequest) {
	int offset=0;
	
	if(authRequest == NULL)
		return CW_FALSE;
		
	//Frame Control
	if(!CW80211ParseFrameIEControl(frame, &(offset), &(authRequest->frameControl)))
		return CW_FALSE;
	
	//Duration
	if(!CW80211ParseFrameIEControl((frame+offset), &(offset), &(authRequest->duration)))
		return CW_FALSE;
		
	//DA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), authRequest->DA))
		return CW_FALSE;
	
	//SA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), authRequest->SA))
		return CW_FALSE;
		
	//BSSID
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), authRequest->BSSID))
		return CW_FALSE;
	
	//Seq Ctrl
	if(!CW80211ParseFrameIESeqCtrl((frame+offset), &(offset), &(authRequest->seqCtrl)))
		return CW_FALSE;
	
	//Auth Algo
	if(!CW80211ParseFrameIEAuthAlgo((frame+offset), &(offset), &(authRequest->authAlg)))
		return CW_FALSE;
		
	//Auth Trans
	if(!CW80211ParseFrameIEAuthTransaction((frame+offset), &(offset), &(authRequest->authTransaction)))
		return CW_FALSE;

	//Status Code
	if(!CW80211ParseFrameIEStatusCode((frame+offset), &(offset), &(authRequest->statusCode)))
		return CW_FALSE;
	
	return CW_TRUE;
}

CWBool CW80211ParseAuthResponse(char * frame, struct CWFrameAuthResponse * authResponse) {
	int offset=0;
	
	if(authResponse == NULL)
		return CW_FALSE;
		
	//Frame Control
	if(!CW80211ParseFrameIEControl(frame, &(offset), &(authResponse->frameControl)))
		return CW_FALSE;
	
	//Duration
	if(!CW80211ParseFrameIEDuration((frame+offset), &(offset), &(authResponse->duration)))
		return CW_FALSE;
	
	//DA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), &(authResponse->DA)))
		return CW_FALSE;
	
	//SA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), authResponse->SA))
		return CW_FALSE;
		
	//BSSID
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), authResponse->BSSID))
		return CW_FALSE;
	
	//Seq Ctrl
	if(!CW80211ParseFrameIESeqCtrl((frame+offset), &(offset), &(authResponse->seqCtrl)))
		return CW_FALSE;
	
	//Auth Algo
	if(!CW80211ParseFrameIEAuthAlgo((frame+offset), &(offset), &(authResponse->authAlg)))
		return CW_FALSE;
		
	//Auth Trans
	if(!CW80211ParseFrameIEAuthTransaction((frame+offset), &(offset), &(authResponse->authTransaction)))
		return CW_FALSE;

	//Status Code
	if(!CW80211ParseFrameIEStatusCode((frame+offset), &(offset), &(authResponse->statusCode)))
		return CW_FALSE;
	
	return CW_TRUE;
}

CWBool CW80211ParseAssociationRequest(char * frame, struct CWFrameAssociationRequest * assocRequest) {
	int offset=0;
	
	if(assocRequest == NULL)
		return CW_FALSE;
		
	//Frame Control
	if(!CW80211ParseFrameIEControl(frame, &(offset), &(assocRequest->frameControl)))
		return CW_FALSE;
	
	//Duration
	if(!CW80211ParseFrameIEControl((frame+offset), &(offset), &(assocRequest->duration)))
		return CW_FALSE;
		
	//DA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), assocRequest->DA))
		return CW_FALSE;
	
	//SA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), assocRequest->SA))
		return CW_FALSE;
		
	//BSSID
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), assocRequest->BSSID))
		return CW_FALSE;
	
	//Seq Ctrl
	if(!CW80211ParseFrameIESeqCtrl((frame+offset), &(offset), &(assocRequest->seqCtrl)))
		return CW_FALSE;
	
	//Capability	
	if(!CW80211ParseFrameIECapability((frame+offset), &(offset), &(assocRequest->capabilityBit)))
		return CW_FALSE;
	
	//Listen Interval	
	if(!CW80211ParseFrameIEListenInterval((frame+offset), &(offset), &(assocRequest->listenInterval)))
		return CW_FALSE;
	
	//SSID		
	if(!CW80211ParseFrameIESSID((frame+offset), &(offset), &(assocRequest->SSID)))
		return CW_FALSE;
	
	//Supported Rates
	if(!CW80211ParseFrameIESupportedRates((frame+offset), &(offset), &(assocRequest->supportedRates),  &(assocRequest->supportedRatesLen)))
		return CW_FALSE;

	return CW_TRUE;
}

CWBool CW80211ParseAssociationResponse(char * frame, struct CWFrameAssociationResponse * assocResponse) {
	int offset=0;
	
	if(assocResponse == NULL)
		return CW_FALSE;
		
	//Frame Control
	if(!CW80211ParseFrameIEControl(frame, &(offset), &(assocResponse->frameControl)))
		return CW_FALSE;
	
	//Duration
	if(!CW80211ParseFrameIEControl((frame+offset), &(offset), &(assocResponse->duration)))
		return CW_FALSE;
		
	//DA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), assocResponse->DA))
		return CW_FALSE;
	
	//SA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), assocResponse->SA))
		return CW_FALSE;
		
	//BSSID
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), assocResponse->BSSID))
		return CW_FALSE;
	
	//Seq Ctrl
	if(!CW80211ParseFrameIESeqCtrl((frame+offset), &(offset), &(assocResponse->seqCtrl)))
		return CW_FALSE;
	
	//Capability	
	if(!CW80211ParseFrameIECapability((frame+offset), &(offset), &(assocResponse->capabilityBit)))
		return CW_FALSE;
	
	//Status Code	
	if(!CW80211ParseFrameIEStatusCode((frame+offset), &(offset), &(assocResponse->statusCode)))
		return CW_FALSE;
		
	//Ass ID	
	if(!CW80211ParseFrameIEAssID((frame+offset), &(offset), &(assocResponse->assID)))
		return CW_FALSE;
	
	//Supported Rates
	if(!CW80211ParseFrameIESupportedRates((frame+offset), &(offset), &(assocResponse->supportedRates),  &(assocResponse->supportedRatesLen)))
		return CW_FALSE;

	
	return CW_TRUE;
}

CWBool CW80211ParseDeauthDisassociationRequest(char * frame, struct CWFrameDeauthDisassociationRequest * disassocRequest) {
	int offset=0;
	
	if(disassocRequest == NULL)
		return CW_FALSE;
		
	//Frame Control
	if(!CW80211ParseFrameIEControl(frame, &(offset), &(disassocRequest->frameControl)))
		return CW_FALSE;
	
	//Duration
	if(!CW80211ParseFrameIEControl((frame+offset), &(offset), &(disassocRequest->duration)))
		return CW_FALSE;
		
	//DA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), disassocRequest->DA))
		return CW_FALSE;
	
	//SA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), disassocRequest->SA))
		return CW_FALSE;
		
	//BSSID
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), disassocRequest->BSSID))
		return CW_FALSE;
	
	//Seq Ctrl
	if(!CW80211ParseFrameIESeqCtrl((frame+offset), &(offset), &(disassocRequest->seqCtrl)))
		return CW_FALSE;
	
	//Reason Code
	if(!CW80211ParseFrameIEReasonCode((frame+offset), &(offset), &(disassocRequest->reasonCode)))
		return CW_FALSE;

	return CW_TRUE;
}

CWBool CW80211ParseDataFrameToDS(char * frame, struct CWFrameDataHdr * dataFrame) {
	int offset=0;
	
	if(dataFrame == NULL)
		return CW_FALSE;
		
	//Frame Control
	if(!CW80211ParseFrameIEControl(frame, &(offset), &(dataFrame->frameControl)))
		return CW_FALSE;
	
	//Duration
	if(!CW80211ParseFrameIEControl((frame+offset), &(offset), &(dataFrame->duration)))
		return CW_FALSE;
	
	//BSSID
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), dataFrame->BSSID))
		return CW_FALSE;
	
	//SA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), dataFrame->SA))
		return CW_FALSE;
	
	//DA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), dataFrame->DA))
		return CW_FALSE;
	
	//Seq Ctrl
	if(!CW80211ParseFrameIESeqCtrl((frame+offset), &(offset), &(dataFrame->seqCtrl)))
		return CW_FALSE;

	return CW_TRUE;
}


CWBool CW80211ParseDataFrameFromDS(char * frame, struct CWFrameDataHdr * dataFrame) {
	int offset=0;
	
	if(dataFrame == NULL)
		return CW_FALSE;
		
	//Frame Control
	if(!CW80211ParseFrameIEControl(frame, &(offset), &(dataFrame->frameControl)))
		return CW_FALSE;
	
	//Duration
	if(!CW80211ParseFrameIEControl((frame+offset), &(offset), &(dataFrame->duration)))
		return CW_FALSE;
	
	//DA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), dataFrame->DA))
		return CW_FALSE;

	//BSSID
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), dataFrame->BSSID))
		return CW_FALSE;
	
	//SA
	if(!CW80211ParseFrameIEAddr((frame+offset), &(offset), dataFrame->SA))
		return CW_FALSE;
	
	//Seq Ctrl
	if(!CW80211ParseFrameIESeqCtrl((frame+offset), &(offset), &(dataFrame->seqCtrl)))
		return CW_FALSE;

	return CW_TRUE;
}
