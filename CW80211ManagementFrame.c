/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	802.11 Management Frame
 * 
 ***************************************/
#include "CWWTP.h"

struct CWTimerAssociationInfo {
	WTPBSSInfo * BSSInfo;
	WTPSTAInfo * staInfo;
};

/* ------------------------------------------------ */
CW_THREAD_RETURN_TYPE CWWTPBSSManagement(void *arg){
	struct WTPBSSInfo * BSSInfo = (struct WTPBSSInfo *) arg;
	
	CWLog("Dentro Thread ssid: %s", BSSInfo->interfaceInfo->SSID);

	//Start reading from AP readers
	CW80211ManagementFrameEvent(&(BSSInfo->interfaceInfo->nl_mgmt), CW80211EventReceive, BSSInfo->interfaceInfo->nl_cb, BSSInfo);
}

void CW80211ManagementFrameEvent(struct nl_handle **handleMgmt, cw_sock_handler handler, void * cb, struct WTPBSSInfo * BSSInfo)
{
	//Set file descriptor of socket to non-blocking state
	nl_socket_set_nonblocking(*handleMgmt);
	int nlSocketFDmgmt = nl_socket_get_fd(*handleMgmt);
	CWBool exitThread=CW_FALSE;
	
	while(1)
	{
		//On delete BSS
		CWThreadMutexLock(&(BSSInfo->bssMutex));
		exitThread = BSSInfo->destroyBSS;
		CWThreadMutexUnlock(&(BSSInfo->bssMutex));
		if(exitThread == CW_TRUE)
			CWExitThread();
			
		int result;
		fd_set readset;
		do {
		   FD_ZERO(&readset);
		   FD_SET(nlSocketFDmgmt, &readset);
		   result = select(nlSocketFDmgmt + 1, &readset, NULL, NULL, NULL);
		} while (result == -1 && errno == EINTR);
		
		if (result > 0) {
		   if (FD_ISSET(nlSocketFDmgmt, &readset)) {
			 handler(cb, (*handleMgmt));
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

void CW80211EventProcess(WTPBSSInfo * WTPBSSInfoPtr, int cmd, struct nlattr **tb, char * frameBuffer)
{
	char * frameResponse = NULL;
	WTPSTAInfo * thisSTA;
	
	u64 cookie_out;
	int frameRespLen=0, offsetFrameReceived=0;
	short int fc, stateSTA = CW_80211_STA_OFF;
	int frameLen;
	CWLog("nl80211: Drv Event %d (%s) received for %s", cmd, nl80211_command_to_string(cmd), WTPBSSInfoPtr->interfaceInfo->ifName);
	
	//union wpa_event_data data;
	if(!tb[NL80211_ATTR_FRAME])
	{
		CWLog("[NL80211] Unexpected frame");
		CW80211HandleClass3Frame(WTPBSSInfoPtr, cmd, tb, frameBuffer);
		return;
	}
	
	frameLen = nla_len(tb[NL80211_ATTR_FRAME]);
	unsigned char frameReceived[frameLen+1];
	CW_COPY_MEMORY(frameReceived, nla_data(tb[NL80211_ATTR_FRAME]), frameLen);
	
	if(!CW80211ParseFrameIEControl(frameReceived, &(offsetFrameReceived), &fc))
		return;
	
	/* +++ PROBE Request/Response: non aggiungo handler della STA fino ad un auth +++ */
	if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT && WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_PROBE_REQ)
	{
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
		
		//Split MAC: invia probe request ad AC per conoscenza
#ifdef SPLIT_MAC
		if(!CWSendFrameMgmtFromWTPtoAC(frameReceived, frameLen))
			return;
#endif

		//In ogni caso, risponde il WTP direttamente senza attendere AC
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
		
		thisSTA = addSTABySA(WTPBSSInfoPtr, authRequest.SA);
		if(thisSTA)
			thisSTA->state = CW_80211_STA_AUTH;
		else
		{
			CWLog("[CW80211] Problem adding STA %02x:%02x:%02x:%02x:%02x:%02x", (int) authRequest.SA[0], (int) authRequest.SA[1], (int) authRequest.SA[2], (int) authRequest.SA[3], (int) authRequest.SA[4], (int) authRequest.SA[5]);
			return;
		}
		
		//Split MAC: invia auth ad AC ed attende il frame di risposta
#ifdef SPLIT_MAC
		frameResponse=NULL;
		if(!CWSendFrameMgmtFromWTPtoAC(frameReceived, frameLen))
			return;
#else
		//Local MAC: invia direttamente auth a STA
		frameResponse = CW80211AssembleAuthResponse(WTPBSSInfoPtr->interfaceInfo->MACaddr, &authRequest, &frameRespLen);
		if(!CWStartAssociationRequestTimer(thisSTA, WTPBSSInfoPtr))
			CWLog("[CW80211] Problem starting timer association request");
#endif
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
			if(thisSTA->state == CW_80211_STA_AUTH || thisSTA->state == CW_80211_STA_ASSOCIATION)
				thisSTA->state = CW_80211_STA_ASSOCIATION;
			else
			{
				CWLog("[CW80211] STA %02x:%02x:%02x:%02x:%02x:%02x hasn't send an Auth or Assoc Request before sending Association Request.", (int) assocRequest.SA[0], (int) assocRequest.SA[1], (int) assocRequest.SA[2], (int) assocRequest.SA[3], (int) assocRequest.SA[4], (int) assocRequest.SA[5]);
				return;
			}
		}
		else
		{
			CWLog("[CW80211] Problem adding STA %02x:%02x:%02x:%02x:%02x:%02x", (int) assocRequest.SA[0], (int) assocRequest.SA[1], (int) assocRequest.SA[2], (int) assocRequest.SA[3], (int) assocRequest.SA[4], (int) assocRequest.SA[5]);
			return CW_FALSE;
		}
		thisSTA->capabilityBit = assocRequest.capabilityBit;
		thisSTA->listenInterval = assocRequest.listenInterval;
		thisSTA->lenSupportedRates = assocRequest.supportedRatesLen;
		
		CW_CREATE_ARRAY_CALLOC_ERR(thisSTA->supportedRates, thisSTA->lenSupportedRates+1, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return CW_FALSE;});
		CW_COPY_MEMORY(thisSTA->supportedRates, assocRequest.supportedRates, thisSTA->lenSupportedRates);

		//Send Association Frame
		if(!CWSendFrameMgmtFromWTPtoAC(frameReceived, frameLen))
			return;
		
		//Local MAC
#ifndef SPLIT_MAC
		//Ass ID is a random number
		CW80211SetAssociationID(&(thisSTA->staAID));
		frameResponse = CW80211AssembleAssociationResponse(WTPBSSInfoPtr, thisSTA, &assocRequest, &frameRespLen);
		//Send Association Frame Response
		if(!CWSendFrameMgmtFromWTPtoAC(frameResponse, frameRespLen))
			return;
#else
		frameResponse = NULL;
#endif
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
		
		thisSTA = findSTABySA(WTPBSSInfoPtr, disassocRequest.SA);
		if(thisSTA)
		{
			//Deauth elimina dal BSS la STA
			if(WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_DEAUTH)
			{
				if(thisSTA->radioAdd==CW_TRUE)
				{
					if(!nl80211CmdDelStation(WTPBSSInfoPtr, disassocRequest.SA))
					{
						CWLog("[CW80211] Problem deleting STA %02x:%02x:%02x:%02x:%02x:%02x", (int) disassocRequest.SA[0], (int) disassocRequest.SA[1], (int) disassocRequest.SA[2], (int) disassocRequest.SA[3], (int) disassocRequest.SA[4], (int) disassocRequest.SA[5]);
						return;
					}
					
					if(thisSTA)
						thisSTA->radioAdd=CW_FALSE;
				}
				if(!delSTABySA(WTPBSSInfoPtr, disassocRequest.SA))
					CWLog("[CW80211] Problem deleting STA %02x:%02x:%02x:%02x:%02x:%02x", (int) disassocRequest.SA[0], (int) disassocRequest.SA[1], (int) disassocRequest.SA[2], (int) disassocRequest.SA[3], (int) disassocRequest.SA[4], (int) disassocRequest.SA[5]);
				
			}
			//Disassociation regredisce di stato
			else
			{
				if(thisSTA)
				{
					if(thisSTA->state == CW_80211_STA_ASSOCIATION)
						thisSTA->state = CW_80211_STA_AUTH;
				}
			}
		}
		else
			CWLog("STA hasn't an handler");
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


void CW80211HandleClass3Frame(WTPBSSInfo * WTPBSSInfoPtr, int cmd, struct nlattr **tb, char * frameBuffer)
{
	char * frameResponse = NULL;
	WTPSTAInfo * thisSTA;
	u64 cookie_out;
	int frameRespLen=0, offsetFrameReceived=0;
	short int fc, stateSTA = CW_80211_STA_OFF;
	int frameLen;
	CWLog("nl80211: Devo gestire un frame di classe 3 (%s) received for %s", nl80211_command_to_string(cmd), WTPBSSInfoPtr->interfaceInfo->ifName);
	
	//Deauth?
	return;
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

CWBool CWStartAssociationRequestTimer(WTPSTAInfo * staInfo, WTPBSSInfo * WTPBSSInfoPtr) {
	
	struct CWTimerAssociationInfo * infoTimer;
	CW_CREATE_OBJECT_ERR(infoTimer, struct CWTimerAssociationInfo, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	infoTimer->staInfo = staInfo;
	infoTimer->BSSInfo = WTPBSSInfoPtr;
	
	staInfo->staAssociationRequestTimerID = timer_add(CW_WTP_STA_ASSOCIATION_REQUEST_TIMER,
					0,
					&CWWTPAssociationRequestTimerExpiredHandler,
					infoTimer);
	
	if (staInfo->staAssociationRequestTimerID == -1)
		return CW_FALSE;
		
	CWDebugLog("STA %d Association Request Timer Started");
	
	return CW_TRUE;
}

void CWWTPAssociationRequestTimerExpiredHandler(void *arg) {

	struct CWTimerAssociationInfo * info = (struct CWTimerAssociationInfo *) arg;
	
	CWLog("[CW80211] Association Timer Raised");
	if((info != NULL) && (info->staInfo != NULL) && info->staInfo->address != NULL && info->staInfo->state == CW_80211_STA_ASSOCIATION)
		return;
	
	if(!nl80211CmdDelStation(info->BSSInfo, info->staInfo->address))
	{
		CWLog("[CW80211] Problem deleting STA %02x:%02x:%02x:%02x:%02x:%02x", (int) info->staInfo->address[0], (int) info->staInfo->address[1], (int) info->staInfo->address[2], (int) info->staInfo->address[3], (int) info->staInfo->address[4], (int) info->staInfo->address[5]);
		return;
	}
	
	info->staInfo->radioAdd=CW_FALSE;
	
	if(!delSTABySA(info->BSSInfo, info->staInfo->address))
		CWLog("[CW80211] Problem deleting STA %02x:%02x:%02x:%02x:%02x:%02x", (int) info->staInfo->address[0], (int) info->staInfo->address[1], (int) info->staInfo->address[2], (int) info->staInfo->address[3], (int) info->staInfo->address[4], (int) info->staInfo->address[5]);
	
	CWLog("[CW80211] Association Timer Raised. STA deleted");
}
