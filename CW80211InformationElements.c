/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	802.11 Information Elements
 * 
 ***************************************/
#include "CWWTP.h"

/* +++++++++++++++++++ ASSEMBLE +++++++++++++++++++++ */
/* FIXED LEN IE */
CWBool CWAssembleIEFrameControl(char * frame, int * offset, int frameType, int frameSubtype) {
	
	short int val = IEEE80211_FC(frameType, frameSubtype);
	
	CW_COPY_MEMORY(frame, &(val), LEN_IE_FRAME_CONTROL);
	(*offset) += LEN_IE_FRAME_CONTROL;
	
	return CW_TRUE;
}

CWBool CWAssembleIEDuration(char * frame, int * offset, int value) {
	
	short int val = htons(host_to_le16(value));
	
	CW_COPY_MEMORY(frame, &(val), LEN_IE_DURATION);
	(*offset) += LEN_IE_DURATION;
	
	return CW_TRUE;
}

CWBool CWAssembleIEAddr(char * frame, int * offset, char * value) {
	//Broadcast
	if(value == NULL)
		memset(frame, 0xff, ETH_ALEN);
	else
		CW_COPY_MEMORY(frame, value, ETH_ALEN);
		
	(*offset) += ETH_ALEN;
	
	return CW_TRUE;
}

CWBool CWAssembleIEBeaconInterval(char * frame, int * offset, short int value) {
	
	short int val = htons(host_to_le16(value));
	
	CW_COPY_MEMORY(frame, &(val), LEN_IE_BEACON_INT);
	(*offset) += LEN_IE_BEACON_INT;
	
	return CW_TRUE;
}

CWBool CWAssembleIECapability(char * frame, int * offset, short int value) {

	CW_COPY_MEMORY(frame, &(value), LEN_IE_CAPABILITY);
	(*offset) += LEN_IE_CAPABILITY;
	
	return CW_TRUE;
}

CWBool CWAssembleIEAuthAlgoNum(char * frame, int * offset, short int value) {

	CW_COPY_MEMORY(frame, &(value), LEN_IE_AUTH_ALG);
	(*offset) += LEN_IE_AUTH_ALG;
	
	return CW_TRUE;
}

CWBool CWAssembleIEAuthTransNum(char * frame, int * offset, short int value) {

	CW_COPY_MEMORY(frame, &(value), LEN_IE_AUTH_TRANS);
	(*offset) += LEN_IE_AUTH_TRANS;
	
	return CW_TRUE;
}

CWBool CWAssembleIEStatusCode(char * frame, int * offset, short int value) {

	CW_COPY_MEMORY(frame, &(value), LEN_IE_STATUS_CODE);
	(*offset) += LEN_IE_STATUS_CODE;
	
	return CW_TRUE;
}

CWBool CWAssembleIEAssID(char * frame, int * offset, short int value) {

	value |= BIT(14);
	value |= BIT(15);
	CW_COPY_MEMORY(frame, &(value), LEN_IE_ASSOCIATION_ID);
	(*offset) += LEN_IE_ASSOCIATION_ID;
	
	return CW_TRUE;
}

/* VARIABLE LEN IE */

CWBool CWAssembleIESSID(char * frame, int * offset, char * value) {
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

CWBool CWAssembleIESupportedRates(char * frame, int * offset, char * value, int numRates) {
	
	short int index=0;
	
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

CWBool CWAssembleIEDSSS(char * frame, int * offset, char value) {
	
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

CWBool CW80211ParseFrameIESSID(char * frameReceived, int * offsetFrameReceived, char ** value) {
	
	if(frameReceived[0] != IE_TYPE_SSID)
		return CW_FALSE;

	short int len = frameReceived[1];
	if(len == 0)
		return CW_FALSE;
	
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
