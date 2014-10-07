/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	802.11 Management Frame
 * 
 ***************************************/
#include "CWWTP.h"

/* +++++++++++++++++++++ ASSEMBLE +++++++++++++++++++++++ */
//Genera probe response
char * CW80211AssembleProbeResponse(WTPInterfaceInfo * interfaceInfo, struct CWFrameProbeRequest *request, int *offset)
{
	int index=0;
	
	CWLog("Probe response per ifname: %s", interfaceInfo->ifName);
	(*offset)=0;
	/* ***************** PROBE RESPONSE FRAME FIXED ******************** */
	char * frameProbeResponse;
	CW_CREATE_ARRAY_CALLOC_ERR(frameProbeResponse, MGMT_FRAME_FIXED_LEN_PROBE_RESP+strlen(interfaceInfo->SSID)+9+1, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return NULL;});
	
	//frame control: 2 byte
	if(!CWAssembleIEFrameControl(&(frameProbeResponse[(*offset)]), offset, WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_PROBE_RESP))
		return NULL;
	
	//duration: 2 byte
	if(!CWAssembleIEDuration(&(frameProbeResponse[(*offset)]), offset, 0))
		return NULL;
	
	//da: 6 byte
	if(request)
	{
		if(!CWAssembleIEAddr(&(frameProbeResponse[(*offset)]), offset, request->SA))
			return NULL;
	}
	else
	{
		if(!CWAssembleIEAddr(&(frameProbeResponse[(*offset)]), offset, NULL))
			return NULL;
	}

	//sa: 6 byte
	if(!CWAssembleIEAddr(&(frameProbeResponse[(*offset)]), offset, interfaceInfo->MACaddr))
			return NULL;

	//bssid: 6 byte
	if(!CWAssembleIEAddr(&(frameProbeResponse[(*offset)]), offset, interfaceInfo->BSSID))
			return NULL;
	
	//2 (sequence ctl) + 8 (timestamp): vengono impostati in automatico
	(*offset) += LEN_IE_SEQ_CTRL;
	(*offset) += LEN_IE_TIMESTAMP;
	
	//beacon interval: 2 byte
	if(!CWAssembleIEBeaconInterval(&(frameProbeResponse[(*offset)]), offset, 100))
			return NULL;
	
	//capability: 2 byte
	if(!CWAssembleIECapability(&(frameProbeResponse[(*offset)]), offset, interfaceInfo->capabilityBit))
			return NULL;

	/* *************************************************** */
		
	//SSID
	if(!CWAssembleIESSID(&(frameProbeResponse[(*offset)]), offset, interfaceInfo->SSID))
		return NULL;

	//Supported Rates
	unsigned char suppRate = 2;
	if(!CWAssembleIESupportedRates(&(frameProbeResponse[(*offset)]), offset, &(suppRate), 1))
		return NULL;

	//DSSS
	unsigned char channel = CW_WTP_DEFAULT_RADIO_CHANNEL+1;
	if(!CWAssembleIEDSSS(&(frameProbeResponse[(*offset)]), offset, channel))
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
	if(!CWAssembleIEFrameControl(&(frameAuthResponse[(*offset)]), offset, WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_AUTH))
		return NULL;
	
	//duration: 2 byte
	if(!CWAssembleIEDuration(&(frameAuthResponse[(*offset)]), offset, 0))
		return NULL;
	
	//da: 6 byte
	if(request)
	{
		if(!CWAssembleIEAddr(&(frameAuthResponse[(*offset)]), offset, request->SA))
			return NULL;
	}
	else
	{
		if(!CWAssembleIEAddr(&(frameAuthResponse[(*offset)]), offset, NULL))
			return NULL;
	}
	
	//sa: 6 byte
	if(!CWAssembleIEAddr(&(frameAuthResponse[(*offset)]), offset, interfaceInfo->MACaddr))
			return NULL;
	
	//bssid: 6 byte
	if(!CWAssembleIEAddr(&(frameAuthResponse[(*offset)]), offset, interfaceInfo->BSSID))
			return NULL;
	
	//2 (sequence ctl)
	(*offset) += LEN_IE_SEQ_CTRL;
	
	//Auth Algorithm Number: 2 byte
	if(!CWAssembleIEAuthAlgoNum(&(frameAuthResponse[(*offset)]), offset, IE_AUTH_OPEN_SYSTEM))
			return NULL;

	//Auth Algorithm Number: 2 byte (valore seq: 2)
	if(!CWAssembleIEAuthTransNum(&(frameAuthResponse[(*offset)]), offset, 2))
		return NULL;

	//Status Code: 2 byte (valore: 0 status code success)
	if(!CWAssembleIEStatusCode(&(frameAuthResponse[(*offset)]), offset, IE_STATUS_CODE_SUCCESS))
		return NULL;
	
	/* ************************************************* */
		
	return frameAuthResponse;
}

//Genera association response
char * CW80211AssembleAssociationResponse(WTPInterfaceInfo * interfaceInfo, struct CWFrameAssociationRequest *request, int *offset)
{
	CWLog("Association response per ifname: %s", interfaceInfo->ifName);
	
	(*offset)=0;
	
	/* ***************** FRAME FIXED ******************** */
	char * frameAssociationResponse;
	CW_CREATE_ARRAY_CALLOC_ERR(frameAssociationResponse, MGMT_FRAME_FIXED_LEN_ASSOCIATION+MGMT_FRAME_IE_FIXED_LEN+strlen(interfaceInfo->SSID)+1, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return NULL;});
	
	//frame control: 2 byte
	if(!CWAssembleIEFrameControl(&(frameAssociationResponse[(*offset)]), offset, WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_ASSOC_RESP))
		return NULL;
	
	//duration: 2 byte
	if(!CWAssembleIEDuration(&(frameAssociationResponse[(*offset)]), offset, 0))
		return NULL;
	
	//da: 6 byte
	if(request)
	{
		if(!CWAssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, request->SA))
			return NULL;
	}
	else
	{
		if(!CWAssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, NULL))
			return NULL;
	}
	
	//sa: 6 byte
	if(!CWAssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, interfaceInfo->MACaddr))
			return NULL;
	
	//bssid: 6 byte
	if(!CWAssembleIEAddr(&(frameAssociationResponse[(*offset)]), offset, interfaceInfo->BSSID))
			return NULL;
	
	//2 (sequence ctl)
	(*offset) += LEN_IE_SEQ_CTRL;
	
	//capability: 2 byte
	if(!CWAssembleIECapability(&(frameAssociationResponse[(*offset)]), offset, interfaceInfo->capabilityBit))
			return NULL;
	/* ************************************************* */

	//Status Code: 2 byte (valore: 0 status code success)
	if(!CWAssembleIEStatusCode(&(frameAssociationResponse[(*offset)]), offset, IE_STATUS_CODE_SUCCESS))
		return NULL;
	
	//Association ID: 2 byte
	short int val=1234;
	if(!CWAssembleIEAssID(&(frameAssociationResponse[(*offset)]), offset, val))
		return NULL;
	
	//Supported Rates
	unsigned char suppRate = 2;
	if(!CWAssembleIESupportedRates(&(frameAssociationResponse[(*offset)]), offset, &(suppRate), 1))
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
	
	//Add parsing variable elements
	
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
	
	//Seq Ctrl
	if(!CW80211ParseFrameIECapability((frame+offset), &(offset), &(assocRequest->seqCtrl)))
		return CW_FALSE;
		
	//Add parsing variable elements
	
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

void CW80211EventProcess(WTPInterfaceInfo * interfaceInfo, int cmd, struct nlattr **tb)
{
	char * frameResponse = NULL;
	u64 cookie_out;
	int frameRespLen=0, offsetFrameReceived=0;
	short int fc;
	int frameLen;
	CWLog("nl80211: Drv Event %d (%s) received for %s", cmd, nl80211_command_to_string(cmd), interfaceInfo->ifName);
	
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
		
		if(strcmp(probeRequest.SSID, interfaceInfo->SSID))
		{
			CWLog("[80211] SSID is not the same of this interface. Aborted");
			return;
		}
			
		frameResponse = CW80211AssembleProbeResponse(interfaceInfo, &(probeRequest), &frameRespLen);
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
					
		frameResponse = CW80211AssembleAuthResponse(interfaceInfo, &authRequest, &frameRespLen);
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
		
		frameResponse = CW80211AssembleAssociationResponse(interfaceInfo, &assocRequest, &frameRespLen);
	}
	
	if(frameResponse)
		if(!CW80211SendFrame(interfaceInfo, 0, CW_FALSE, frameResponse, frameRespLen, &(cookie_out), 1,1))
			CWLog("NL80211: Errore CW80211SendFrame");
}
