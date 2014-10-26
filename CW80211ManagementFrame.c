/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	802.11 Management Frame
 * 
 ***************************************/
#include "CWWTP.h"

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
/*
	nl_socket_set_nonblocking(*handleEvent);
	int nlSocketFDevent = nl_socket_get_fd(*handleEvent);

	int dataRawSock;	

	struct sockaddr_ll addr;
	
	if ((dataRawSock=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0) 	{
		CWDebugLog("THR FRAME: Error creating socket");
		CWExitThread();
	}
    memset(&addr, 0, sizeof(addr));
	
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_pkttype = PACKET_HOST;
	addr.sll_ifindex = BSSInfo->interfaceInfo->realWlanID;
	CWLog("BSSInfo->interfaceInfo->realWlanID: %d", BSSInfo->interfaceInfo->realWlanID);
	
	if ((bind(dataRawSock, (struct sockaddr*)&addr, sizeof(addr)))<0) {
 		CWDebugLog("THR FRAME: Error binding socket");
 		CWExitThread();
 	}
	*/
	/*
	struct sockaddr_nl local;

	dataRawSock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (dataRawSock < 0) {
		CWLog("netlink: Failed to open netlink socket: %s", strerror(errno));
		return;
	}

	os_memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;
	if (bind(dataRawSock, (struct sockaddr *) &local, sizeof(local)) < 0)
	{
		CWLog("netlink: Failed to bind netlink socket: %s", strerror(errno));
		return;
	}

	CWLog("DOPO DI BIND. dataRawSock: %d", dataRawSock);

	int maxFD=0;
	if(nlSocketFD > dataRawSock)
		maxFD = nlSocketFD;
	else
		maxFD = dataRawSock;
*/
/*
	struct ifreq ifr;
	struct sockaddr_ll addr;

	dataRawSock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (dataRawSock < 0) {
		perror("socket[PF_PACKET,SOCK_RAW]");
		return;
	}

        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", BSSInfo->interfaceInfo->ifName);
        if (ioctl(dataRawSock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		return;
        }

//MTU: hostap_set_iface_flags(drv, 1))
	
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
	CWLog("Opening raw packet socket for ifindex %d", addr.sll_ifindex);

	if (bind(dataRawSock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		return;
	}
	
CWLog("nlSocketFDmgmt: %d, nlSocketFDevent: %d, dataRawSock: %d", nlSocketFDmgmt, nlSocketFDevent, dataRawSock);
	int maxFD=0;
	if(nlSocketFDmgmt > nlSocketFDevent)
		maxFD = nlSocketFDmgmt;
	else
		maxFD = nlSocketFDevent;
 	
 	if(dataRawSock > maxFD)
		maxFD = dataRawSock;
		
CWLog("maxFD: %d", maxFD);
	*/
	while(1)
	{
		int result;
		fd_set readset;
		do {
		   FD_ZERO(&readset);
		   FD_SET(nlSocketFDmgmt, &readset);
		//   FD_SET(nlSocketFDevent, &readset);
		 //  FD_SET(dataRawSock, &readset);
		   result = select(nlSocketFDmgmt + 1, &readset, NULL, NULL, NULL);
		} while (result == -1 && errno == EINTR);
		
		if (result > 0) {
		   if (FD_ISSET(nlSocketFDmgmt, &readset)) {
			   
			   CWLog("Ricevuto mgmt");
				//The nlSocketFD has data available to be read
			 handler(cb, (*handleMgmt));
		   }
		 /*  else if(FD_ISSET(nlSocketFDevent, &readset))
		   {
			   CWLog("RICEVUTO EVENTO");
			   handler(cb, (*handleEvent));
		   }
		   else if(FD_ISSET(dataRawSock, &readset))
		   {
			   CWLog("RICEVUTO dataRawSock");
			  CW80211EventDataReceive(dataRawSock, BSSInfo);
		   }
			else
			{
				CWLog("SUCCESSO QUALCOSA");
			}
		*/   
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

/*
void CW80211EventDataReceive(int dataRawSock, struct WTPBSSInfo * BSSInfo)
{
	CWLog("Dentro CW80211EventDataReceive");
	
	int n,encaps_len;
	unsigned char buffer[CW_BUFFER_SIZE];
	unsigned char buf80211[CW_BUFFER_SIZE];
	CWProtocolMessage* frame=NULL;
	CWBindingDataListElement* listElement=NULL;
	struct ifreq ethreq;
	
	char * frameResponse = NULL;
	WTPSTAInfo * thisSTA;
	u64 cookie_out;
	int frameRespLen=0, offsetFrameReceived=0;
	short int fc, stateSTA = CW_80211_STA_OFF;
	int frameLen;
	struct CWFrameDataHdr dataFrame;
	
	
	n = recvfrom(dataRawSock,buffer,sizeof(buffer),0,NULL,NULL);
	if(n<0)
	{
		CWLog("n: %d", n);
		return;
	}
	
	CWLog("Letti %d byte", n);
	encaps_len = from_8023_to_80211(buffer, n, buf80211, BSSInfo->interfaceInfo->MACaddr);
	
	
	
	if (!extract802_11_Frame(&frame, buf80211, encaps_len)){
		CWLog("THR FRAME: Error extracting a frame");
		CWExitThread();
	}
	
	
	CWLog("nl80211: Parse frame");
	
	
	CWLog("CW80211: Parse del frame control");
	if(!CW80211ParseFrameIEControl(frame->msg, &(offsetFrameReceived), &(dataFrame.frameControl)))
		return;
	
	/*
	CWLog("CW80211: Frame Control %02x", dataFrame.frameControl);
	//Duration
	if(!CW80211ParseFrameIEControl((frameBuffer+offsetFrameReceived), &(offsetFrameReceived), &(dataFrame.duration)))
		return CW_FALSE;
	CWLog("CW80211: Duration %02x", dataFrame.duration);

	//DA
	if(!CW80211ParseFrameIEAddr((frameBuffer+offsetFrameReceived), &(offsetFrameReceived), dataFrame.DA))
		return CW_FALSE;
	CWLog("CW80211: DA %02x:%02x:%02x:%02x:%02x:%02x", (int)dataFrame.DA[0], (int)dataFrame.DA[1], (int)dataFrame.DA[2], (int)dataFrame.DA[3], (int)dataFrame.DA[4], (int)dataFrame.DA[5]);
	
	//SA
	if(!CW80211ParseFrameIEAddr((frameBuffer+offsetFrameReceived), &(offsetFrameReceived), dataFrame.SA))
		return CW_FALSE;
	CWLog("CW80211: SA %02x:%02x:%02x:%02x:%02x:%02x", (int)dataFrame.SA[0], (int)dataFrame.SA[1], (int)dataFrame.SA[2], (int)dataFrame.SA[3], (int)dataFrame.SA[4], (int)dataFrame.SA[5]);
		
	//BSSID
	if(!CW80211ParseFrameIEAddr((frameBuffer+offsetFrameReceived), &(offsetFrameReceived), dataFrame.BSSID))
		return CW_FALSE;
	CWLog("CW80211: BSSID %02x:%02x:%02x:%02x:%02x:%02x", (int)dataFrame.BSSID[0], (int)dataFrame.BSSID[1], (int)dataFrame.BSSID[2], (int)dataFrame.BSSID[3], (int)dataFrame.BSSID[4], (int)dataFrame.BSSID[5]);
	
	
	CWLog("CW80211: type: %02x, subtype: %02x", (int)WLAN_FC_GET_TYPE(dataFrame.frameControl), (int)WLAN_FC_GET_STYPE(dataFrame.frameControl));
	// +++ DATA +++
	if (WLAN_FC_GET_TYPE(dataFrame.frameControl) == WLAN_FC_TYPE_DATA)
	{
		if(WLAN_FC_GET_STYPE(dataFrame.frameControl) == WLAN_FC_STYPE_NULLFUNC)
		{
			CWLog("[80211] Pure frame null func");
			//frameResponse = CW80211AssembleACK(WTPBSSInfoPtr, tb[NL80211_ATTR_MAC], &frameRespLen);
		}
		else if(WLAN_FC_GET_STYPE(dataFrame.frameControl) == WLAN_FC_STYPE_DATA)
		{
			CWLog("[80211] Pure frame data");
		}
		else if(WLAN_FC_GET_STYPE(dataFrame.frameControl) == WLAN_FC_STYPE_CFACK)
		{
			CWLog("[80211] WLAN_FC_STYPE_CFACK");
		}
	}
	else
		CWLog("NO DATA FRAME");
	
	
	CWLog("Recv 802.11 data(len:%d) from %s",encaps_len, BSSInfo->interfaceInfo->ifName);
}
*/

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
	
	/* +++ PROBE Request/Response +++ */
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
		
		thisSTA = addSTABySA(WTPBSSInfoPtr, probeRequest.SA);
		if(thisSTA && thisSTA->state != CW_80211_STA_ASSOCIATION)
			thisSTA->state = CW_80211_STA_PROBE;
		else
			CWLog("[CW80211] Problem adding STA %02x:%02x:%02x:%02x:%02x:%02x", (int) probeRequest.SA[0], (int) probeRequest.SA[1], (int) probeRequest.SA[2], (int) probeRequest.SA[3], (int) probeRequest.SA[4], (int) probeRequest.SA[5]);
		
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
		
		thisSTA = findSTABySA(WTPBSSInfoPtr, authRequest.SA);
		if(thisSTA)
		{
			if(thisSTA->state == CW_80211_STA_PROBE || thisSTA->state == CW_80211_STA_AUTH)
				thisSTA->state = CW_80211_STA_AUTH;
			else
			{
				CWLog("[CW80211] STA %02x:%02x:%02x:%02x:%02x:%02x hasn't send a Probe Request before sending Auth Request.", (int) authRequest.SA[0], (int) authRequest.SA[1], (int) authRequest.SA[2], (int) authRequest.SA[3], (int) authRequest.SA[4], (int) authRequest.SA[5]);
				return;
			}
		}
		else
		{
			CWLog("[CW80211] Problem adding STA %02x:%02x:%02x:%02x:%02x:%02x", (int) authRequest.SA[0], (int) authRequest.SA[1], (int) authRequest.SA[2], (int) authRequest.SA[3], (int) authRequest.SA[4], (int) authRequest.SA[5]);
			return CW_FALSE;
		}
		
		//Split MAC: invia auth ad AC ed attende il frame di risposta
#ifdef SPLIT_MAC
		frameResponse=NULL;
		if(!CWSendFrameMgmtFromWTPtoAC(frameReceived, frameLen))
			return;
#else
		//Local MAC: invia direttamente auth a STA
		frameResponse = CW80211AssembleAuthResponse(WTPBSSInfoPtr->interfaceInfo->MACaddr, &authRequest, &frameRespLen);
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
	
	if(frameBuffer == NULL  || !tb[NL80211_ATTR_MAC])
	{
		if(frameBuffer == NULL)
			CWLog("frameBuffer == NULL");
		if(!tb[NL80211_ATTR_MAC])
			CWLog("!tb[NL80211_ATTR_MAC]");
		return;
	}
	
	struct CWFrameDataHdr dataFrame;
	
	CWLog("CW80211: Parse del frame control");
	if(!CW80211ParseFrameIEControl(frameBuffer, &(offsetFrameReceived), &(dataFrame.frameControl)))
		return;
	
	CWLog("CW80211: Frame Control %02x", dataFrame.frameControl);
	//Duration
	if(!CW80211ParseFrameIEControl((frameBuffer+offsetFrameReceived), &(offsetFrameReceived), &(dataFrame.duration)))
		return CW_FALSE;
	CWLog("CW80211: Duration %02x", dataFrame.duration);

	//DA
	if(!CW80211ParseFrameIEAddr((frameBuffer+offsetFrameReceived), &(offsetFrameReceived), dataFrame.DA))
		return CW_FALSE;
	CWLog("CW80211: DA %02x:%02x:%02x:%02x:%02x:%02x", (int)dataFrame.DA[0], (int)dataFrame.DA[1], (int)dataFrame.DA[2], (int)dataFrame.DA[3], (int)dataFrame.DA[4], (int)dataFrame.DA[5]);
	
	//SA
	if(!CW80211ParseFrameIEAddr((frameBuffer+offsetFrameReceived), &(offsetFrameReceived), dataFrame.SA))
		return CW_FALSE;
	CWLog("CW80211: SA %02x:%02x:%02x:%02x:%02x:%02x", (int)dataFrame.SA[0], (int)dataFrame.SA[1], (int)dataFrame.SA[2], (int)dataFrame.SA[3], (int)dataFrame.SA[4], (int)dataFrame.SA[5]);
		
	//BSSID
	if(!CW80211ParseFrameIEAddr((frameBuffer+offsetFrameReceived), &(offsetFrameReceived), dataFrame.BSSID))
		return CW_FALSE;
	CWLog("CW80211: BSSID %02x:%02x:%02x:%02x:%02x:%02x", (int)dataFrame.BSSID[0], (int)dataFrame.BSSID[1], (int)dataFrame.BSSID[2], (int)dataFrame.BSSID[3], (int)dataFrame.BSSID[4], (int)dataFrame.BSSID[5]);
	
	
	CWLog("CW80211: type: %02x, subtype: %02x", (int)WLAN_FC_GET_TYPE(dataFrame.frameControl), (int)WLAN_FC_GET_STYPE(dataFrame.frameControl));
	
	/* +++ DATA +++ */
	if (WLAN_FC_GET_TYPE(dataFrame.frameControl) == WLAN_FC_TYPE_DATA)
	{
		if(WLAN_FC_GET_STYPE(dataFrame.frameControl) == WLAN_FC_STYPE_NULLFUNC)
		{
			CWLog("[80211] Pure frame null func");
			frameResponse = CW80211AssembleACK(WTPBSSInfoPtr, tb[NL80211_ATTR_MAC], &frameRespLen);
		}
		else if(WLAN_FC_GET_STYPE(dataFrame.frameControl) == WLAN_FC_STYPE_DATA)
		{
			CWLog("[80211] Pure frame data");
		}
		else if(WLAN_FC_GET_STYPE(dataFrame.frameControl) == WLAN_FC_STYPE_CFACK)
		{
			CWLog("[80211] WLAN_FC_STYPE_CFACK");
		}
	}

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
