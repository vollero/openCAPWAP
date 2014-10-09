/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	802.11 Management Frame
 * 
 ***************************************/
#include "CWWTP.h"

/* +++++++++++++++++++++ ASSEMBLE +++++++++++++++++++++++ */
//Genera probe response
char * CW80211AssembleProbeResponse(WTPBSSInfo * WTPBSSInfoPtr, struct CWFrameProbeRequest *request, int *offset)
{
	int index=0;
	
	CWLog("Probe response per ifname: %s", WTPBSSInfoPtr->interfaceInfo->ifName);
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
char * CW80211AssembleAuthResponse(WTPInterfaceInfo * interfaceInfo, struct CWFrameAuthRequest *request, int *offset)
{
	CWLog("Auth response per ifname: %s", interfaceInfo->ifName);
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
	if(!CW80211AssembleIEAddr(&(frameAuthResponse[(*offset)]), offset, interfaceInfo->MACaddr))
			return NULL;
	
	//bssid: 6 byte
	if(!CW80211AssembleIEAddr(&(frameAuthResponse[(*offset)]), offset, interfaceInfo->BSSID))
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
	CWLog("Association response per ifname: %s", WTPBSSInfoPtr->interfaceInfo->ifName);
	
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
	thisSTA->staAID = 1234;
	if(!CW80211AssembleIEAssID(&(frameAssociationResponse[(*offset)]), offset, thisSTA->staAID))
		return NULL;
	
	//Supported Rates
	int indexRates=0;
	unsigned char suppRate[CW_80211_MAX_SUPP_RATES];
	for(indexRates=0; indexRates < WTP_NL80211_BITRATE_NUM && indexRates < CW_80211_MAX_SUPP_RATES && indexRates < WTPBSSInfoPtr->phyInfo->lenSupportedRates; indexRates++)
		suppRate[indexRates] = (char) mapSupportedRatesValues(WTPBSSInfoPtr->phyInfo->phyMbpsSet[indexRates], CW_80211_SUPP_RATES_CONVERT_VALUE_TO_FRAME);
		
	if(!CW80211AssembleIESupportedRates(&(frameAssociationResponse[(*offset)]), offset, suppRate, indexRates))
		return NULL;
	
	return frameAssociationResponse;
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


/* ------------------------------------------------ */


CW_THREAD_RETURN_TYPE CWWTPBSSManagement(void *arg){
	struct WTPBSSInfo * BSSInfo = (struct WTPBSSInfo *) arg;
	
	CWLog("Dentro Thread ssid: %s", BSSInfo->interfaceInfo->SSID);

	//Start reading from AP readers
	CW80211ManagementFrameEvent(&(BSSInfo->interfaceInfo->nl_mgmt), CW80211EventReceive, BSSInfo->interfaceInfo->nl_cb);
}

void CW80211ManagementFrameEvent(struct nl_handle **handle, cw_sock_handler handler, void * cb)
{
	//Set file descriptor of socket to non-blocking state
	nl_socket_set_nonblocking(*handle);
	int nlSocketFD = nl_socket_get_fd(*handle);
	while(1)
	{
		int result;
		fd_set readset;
		do {
		   FD_ZERO(&readset);
		   FD_SET(nlSocketFD, &readset);
		   result = select(nlSocketFD + 1, &readset, NULL, NULL, NULL);
		} while (result == -1 && errno == EINTR);
		
		if (result > 0) {
		   if (FD_ISSET(nlSocketFD, &readset)) {
			   
				//The nlSocketFD has data available to be read
			 handler(cb, (*handle));
		   }
		}
		else if (result < 0) {
		   CWLog("Error on select(): %s", strerror(errno));
		}
	}			     
}

void CW80211EventReceive(void *cbPtr, void *handlePtr)
{
	struct nl_cb *cb = (struct nl_cb *) cbPtr;
	struct nl_handle * handle = (struct nl_handle *) handlePtr;
	
	int res;

	CWLog("nl80211: Event message available");
	res = nl_recvmsgs(handle, cb);
	if (res < 0) {
		CWLog("nl80211: %s->nl_recvmsgs failed: %d, %s",  __func__, res, strerror(res));
	}
}

void CW80211EventProcess(WTPBSSInfo * WTPBSSInfoPtr, int cmd, struct nlattr **tb)
{
	char * frameResponse = NULL;
	WTPSTAInfo * thisSTA;
	
	u64 cookie_out;
	int frameRespLen=0, offsetFrameReceived=0;
	short int fc, stateSTA = CW_80211_STA_OFF;
	int frameLen;
	CWLog("nl80211: Drv Event %d (%s) received for %s", cmd, nl80211_command_to_string(cmd), WTPBSSInfoPtr->interfaceInfo->ifName);
	
	//union wpa_event_data data;
	if(tb[NL80211_ATTR_FRAME])
		frameLen = nla_len(tb[NL80211_ATTR_FRAME]);
	else
	{
		CWLog("[NL80211] Unexpected frame");
		return;
	}
	unsigned char frameReceived[frameLen+1];
	
	CW_COPY_MEMORY(frameReceived, nla_data(tb[NL80211_ATTR_FRAME]), frameLen);
	
	if(!CW80211ParseFrameIEControl(frameReceived, &(offsetFrameReceived), &fc))
		return;
	
	/* +++ PROBE Request/Response +++ */
	if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT && WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_PROBE_REQ)
	{
		/*
		ie = mgmt->u.probe_req.variable;
		if (frameLen < IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req))
			return;
		ie_len = frameLen - (IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req));
		
		if (ieee802_11_parse_elems(ie, ie_len, &elems, 0) == ParseFailed) {
			CWLog("Could not parse ProbeReq from " MACSTR,  MAC2STR(mgmt->sa));
			return;
		}
		if ((!elems.ssid || !elems.supp_rates)) {
			CWLog("STA " MACSTR " sent probe request without SSID or supported rates element", MAC2STR(mgmt->sa));
			return;
		}
	
		*/
		
		CWLog("[80211] Probe Request Received");
		struct CWFrameProbeRequest probeRequest;
		if(!CW80211ParseProbeRequest(frameReceived, &probeRequest))
		{
			CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
			return;
		}
		
		if(strcmp(probeRequest.SSID, WTPBSSInfoPtr->interfaceInfo->SSID))
		{
			CWLog("[80211] SSID is not the same of this interface. Aborted");
			return;
		}
		
		thisSTA = addSTABySA(WTPBSSInfoPtr, probeRequest.SA);
		if(thisSTA)
			thisSTA->state = CW_80211_STA_PROBE;
		else
			CWLog("[CW80211] Problem adding STA %02x:%02x:%02x:%02x:%02x:%02x", (int) probeRequest.SA[0], (int) probeRequest.SA[1], (int) probeRequest.SA[2], (int) probeRequest.SA[3], (int) probeRequest.SA[4], (int) probeRequest.SA[5]);
			
		frameResponse = CW80211AssembleProbeResponse(WTPBSSInfoPtr, &(probeRequest), &frameRespLen);
	}
	
	/* +++ AUTH +++ */
	if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT && WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_AUTH)
	{
		CWLog("[80211] Auth Request Received");
		
		struct CWFrameAuthRequest authRequest;
		if(!CW80211ParseAuthRequest(frameReceived, &authRequest))
		{
			CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
			return;
		}
		
		thisSTA = findSTABySA(WTPBSSInfoPtr, authRequest.SA);
		if(thisSTA)
		{
			if(thisSTA->state == CW_80211_STA_PROBE)
				thisSTA->state = CW_80211_STA_AUTH;
			else
			{
					CWLog("[CW80211] STA %02x:%02x:%02x:%02x:%02x:%02x hasn't send a Probe Request before sending Auth Request.", (int) authRequest.SA[0], (int) authRequest.SA[1], (int) authRequest.SA[2], (int) authRequest.SA[3], (int) authRequest.SA[4], (int) authRequest.SA[5]);
					return;
			}
		}
		else
			CWLog("[CW80211] Problem adding STA %02x:%02x:%02x:%02x:%02x:%02x", (int) authRequest.SA[0], (int) authRequest.SA[1], (int) authRequest.SA[2], (int) authRequest.SA[3], (int) authRequest.SA[4], (int) authRequest.SA[5]);
			
		frameResponse = CW80211AssembleAuthResponse(WTPBSSInfoPtr->interfaceInfo, &authRequest, &frameRespLen);
	}
	
	/* +++ Association Response +++ */
	if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT && WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_ASSOC_REQ)
	{
		CWLog("[80211] Association Request Received");
		struct CWFrameAssociationRequest assocRequest;
		if(!CW80211ParseAssociationRequest(frameReceived, &assocRequest))
		{
			CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
			return;
		}
		
		thisSTA = findSTABySA(WTPBSSInfoPtr, assocRequest.SA);
		if(thisSTA)
		{
			if(thisSTA->state == CW_80211_STA_AUTH)
				thisSTA->state = CW_80211_STA_ASSOCIATION;
			else
			{
				CWLog("[CW80211] STA %02x:%02x:%02x:%02x:%02x:%02x hasn't send an Auth Request before sending Association Request.", (int) assocRequest.SA[0], (int) assocRequest.SA[1], (int) assocRequest.SA[2], (int) assocRequest.SA[3], (int) assocRequest.SA[4], (int) assocRequest.SA[5]);
				return;
			}
		}
		else
			CWLog("[CW80211] Problem adding STA %02x:%02x:%02x:%02x:%02x:%02x", (int) assocRequest.SA[0], (int) assocRequest.SA[1], (int) assocRequest.SA[2], (int) assocRequest.SA[3], (int) assocRequest.SA[4], (int) assocRequest.SA[5]);
		
		thisSTA->capabilityBit = assocRequest.capabilityBit;
		thisSTA->listenInterval = assocRequest.listenInterval;
		
		//Send Association Frame
		if(!CWSendFrameMgmtFromWTPtoAC(frameReceived, frameLen))
			return;
		
		//Local Mac
		frameResponse = CW80211AssembleAssociationResponse(WTPBSSInfoPtr, thisSTA, &assocRequest, &frameRespLen);
	}
	
	if(frameResponse)
	{
		if(!CW80211SendFrame(WTPBSSInfoPtr, 0, CW_FALSE, frameResponse, frameRespLen, &(cookie_out), 1,1))
			CWLog("NL80211: Errore CW80211SendFrame");
	}
	
	/* +++ Dissassociation or Deauthentication Frame: cleanup of STA parameters +++ */
	if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT && (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_DEAUTH || WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_DISASSOC))
	{
		CWLog("[CW80211] Deauth/Disassociation Request Received");
		struct CWFrameDeauthDisassociationRequest disassocRequest;
		if(!CW80211ParseDeauthDisassociationRequest(frameReceived, &disassocRequest))
		{
			CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
			return;
		}
		
		if(!delSTABySA(WTPBSSInfoPtr, disassocRequest.SA))
			CWLog("[CW80211] Problem deleting STA %02x:%02x:%02x:%02x:%02x:%02x", (int) disassocRequest.SA[0], (int) disassocRequest.SA[1], (int) disassocRequest.SA[2], (int) disassocRequest.SA[3], (int) disassocRequest.SA[4], (int) disassocRequest.SA[5]);
	}
}

WTPSTAInfo * addSTABySA(WTPBSSInfo * WTPBSSInfoPtr, char * sa) {
	int indexSTA;
	
	if(sa == NULL)
		return NULL;
		
	for(indexSTA=0; indexSTA < WTP_MAX_STA; indexSTA++)
	{
		//Se gia c'era, riazzero tutto
		if(WTPBSSInfoPtr->staList[indexSTA].address != NULL && !strcmp(WTPBSSInfoPtr->staList[indexSTA].address, sa))
		{
			WTPBSSInfoPtr->staList[indexSTA].state = CW_80211_STA_OFF;
			return &(WTPBSSInfoPtr->staList[indexSTA]);
		}
	}
	
	for(indexSTA=0; indexSTA < WTP_MAX_STA; indexSTA++)
	{
		if(WTPBSSInfoPtr->staList[indexSTA].address == NULL || WTPBSSInfoPtr->staList[indexSTA].state == CW_80211_STA_OFF)
		{
			CW_CREATE_ARRAY_CALLOC_ERR(WTPBSSInfoPtr->staList[indexSTA].address, ETH_ALEN+1, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return NULL;});
			CW_COPY_MEMORY(WTPBSSInfoPtr->staList[indexSTA].address, sa, ETH_ALEN);
			
			return &(WTPBSSInfoPtr->staList[indexSTA]);
		}
	}
	
	return NULL;
}

WTPSTAInfo * findSTABySA(WTPBSSInfo * WTPBSSInfoPtr, char * sa) {
	int indexSTA;
	
	if(sa == NULL)
		return NULL;
		
	for(indexSTA=0; indexSTA < WTP_MAX_STA; indexSTA++)
	{
		if(WTPBSSInfoPtr->staList[indexSTA].address != NULL && !strcmp(WTPBSSInfoPtr->staList[indexSTA].address, sa))
			return &(WTPBSSInfoPtr->staList[indexSTA]);
	}
	
	return NULL;
}

CWBool delSTABySA(WTPBSSInfo * WTPBSSInfoPtr, char * sa) {
	int indexSTA;
	
	if(sa == NULL)
		return CW_FALSE;
		
	for(indexSTA=0; indexSTA < WTP_MAX_STA; indexSTA++)
	{
		if(WTPBSSInfoPtr->staList[indexSTA].address != NULL && !strcmp(WTPBSSInfoPtr->staList[indexSTA].address, sa))
		{
			CW_FREE_OBJECT(WTPBSSInfoPtr->staList[indexSTA].address);
			WTPBSSInfoPtr->staList[indexSTA].address = NULL;
			WTPBSSInfoPtr->staList[indexSTA].state = CW_80211_STA_OFF;
			//Altro da liberare?
			return CW_TRUE;
		}
	}
	
	return CW_FALSE;
}

CWBool CWSendFrameMgmtFromWTPtoAC(char * frameReceived, int frameLen)
{
	CWProtocolMessage* frameMsg = NULL;
	CWBindingDataListElement* listElement = NULL;
		
	if (!extract802_11_Frame(&frameMsg, frameReceived, frameLen)){
		CWLog("THR FRAME: Error extracting a frameMsg");
		return CW_FALSE;
	}
					
	CWLog("CW80211: Send 802.11 management(len:%d) to AC", frameLen);

	CW_CREATE_OBJECT_ERR(listElement, CWBindingDataListElement, return CW_FALSE;);
	listElement->frame = frameMsg;
	listElement->bindingValues = NULL;
	listElement->frame->data_msgType = CW_IEEE_802_11_FRAME_TYPE; //CW_DATA_MSG_FRAME_TYPE; // CW_IEEE_802_11_FRAME_TYPE;

	CWLockSafeList(gFrameList);
	CWAddElementToSafeListTail(gFrameList, listElement, sizeof(CWBindingDataListElement));
	CWUnlockSafeList(gFrameList);
	
	return CW_TRUE;
}
