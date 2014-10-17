/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	NL80211 Integration + libnl
 * 
 ***************************************/
#include "CWWTP.h"

/*****************************************************
 * Interaction with nl80211 cmd
 *****************************************************/
 
CWBool nl80211CmdGetPhyInfo(int indexPhy, struct WTPSinglePhyInfo * singlePhyInfo){
	struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;
	
//	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);
	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_GET_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, indexPhy);
//	NLA_PUT_FLAG(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
	
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, CB_getPhyInfo, singlePhyInfo);
	if( ret != 0)
		return CW_FALSE;
		
	msg = NULL;
	
	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

CWBool nl80211CmdSetNewInterface(int indexPhy, WTPInterfaceInfo * interfaceInfo){
		struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;
	
	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_NEW_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, indexPhy);
	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, interfaceInfo->ifName);
	
	enum nl80211_iftype typeIf = NL80211_IFTYPE_STATION;
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, typeIf);
	
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, CB_setNewInterface, interfaceInfo);
	CWLog("ret: %d", ret);

	if( ret != 0)
		return CW_FALSE;
		
	msg = NULL;

	//retrive MAC address
	CW_CREATE_ARRAY_CALLOC_ERR(interfaceInfo->MACaddr, MAC_ADDR_LEN, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	getInterfaceMacAddr(interfaceInfo->ifName, interfaceInfo->MACaddr);

      CWLog("Ethernet %02x:%02x:%02x:%02x:%02x:%02x\n", 
      (int) interfaceInfo->MACaddr[0],
      (int) interfaceInfo->MACaddr[1],
      (int) interfaceInfo->MACaddr[2],
      (int) interfaceInfo->MACaddr[3],
      (int) interfaceInfo->MACaddr[4],
      (int) interfaceInfo->MACaddr[5]);
 

	CWLog("Interface %s created", interfaceInfo->ifName);
	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

CWBool nl80211CmdDelInterface(int indexPhy, char * ifName){
		struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;
	
	int index = if_nametoindex(ifName);

	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_DEL_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, indexPhy);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, index);
	
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, NULL, NULL);
	CWLog("ret: %d", ret);

	if( ret != 0)
		return CW_FALSE;
		
	msg = NULL;

	CWLog("Interface %s deleted", ifName);
	
	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

CWBool nl80211CmdSetInterfaceAPType(char * interface){
		struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;

	int index = if_nametoindex(interface);
	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_SET_INTERFACE, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, index);
	enum nl80211_iftype typeIf = NL80211_IFTYPE_AP;
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, typeIf);
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, NULL, NULL);
	CWLog("ret: %d", ret);
	if( ret != 0)
		return CW_FALSE;
		
	msg = NULL;
	
	CWLog("Interface %s now is AP mode", interface);

	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

CWBool nl80211CmdSetInterfaceSTAType(char * interface){
	struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;

	int index = if_nametoindex(interface);
	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_SET_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, index);
	enum nl80211_iftype typeIf = NL80211_IFTYPE_STATION;
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, typeIf);
	
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, NULL, NULL);
	CWLog("nl80211CmdSetInterfaceSTAType ret: %d", ret);
	if( ret != 0)
		return CW_FALSE;
		
	msg = NULL;
	
	CWLog("Interface %s now is STA mode", interface);

	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

CWBool nl80211CmdSetChannelInterface(char * interface, int channel){
	struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;

	int index = if_nametoindex(interface);
	
	CWLog("Interface %s (%d) for channel %d", interface, index, channel);

	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_SET_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, index);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, channel);
	//NLA_PUT_U32(msg, NL80211_ATTR_CHANNEL_WIDTH, NL80211_CHAN_WIDTH_80);
		
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, NULL, NULL);
	CWLog("ret: %d", ret);
	if( ret != 0)
		return CW_FALSE;
		
	msg = NULL;
	
	CWLog("Interface %s now channel %d", interface, channel);

	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

CWBool nl80211CmdGetChannelInterface(char * interface, int * channel){
	struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;

	int index = if_nametoindex(interface);
	
	CWLog("Interface %s (%d) for channel %d", interface, index, channel);

	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_GET_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, 0);
		
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, CB_getChannelInterface, channel);
	CWLog("ret: %d", ret);
	if( ret != 0)
		return CW_FALSE;
		
	msg = NULL;

	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

/*
 * N.B. For beacon params: src/ap/beacon.c: ieee802_11_build_ap_params
 * For start ap: src/driver/driver_nl80211.c :wpa_driver_nl80211_set_ap
 */
CWBool nl80211CmdStartAP(WTPInterfaceInfo * interfaceInfo){
	struct nl_msg *msg;
	int offset=0;
	int ifIndex = interfaceInfo->realWlanID;//if_nametoindex(ifName);
		
	struct ieee80211_mgmt *head = NULL;
	u8 *tail = NULL;
	size_t head_len = 0, tail_len = 0;
	struct wpa_driver_ap_params * params;
	u8 *pos, *tailpos;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;
	
	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_NEW_BEACON, 0);

/* ***************** BEACON FRAME: DO IT BETTER ******************** */
	char * beaconFrame;
	CW_CREATE_ARRAY_CALLOC_ERR(beaconFrame, (MGMT_FRAME_FIXED_LEN_BEACON+MGMT_FRAME_IE_FIXED_LEN+strlen(interfaceInfo->SSID)+IE_TYPE_DSSS+1), char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);); //MAC80211_HEADER_FIXED_LEN+MAC80211_BEACON_BODY_MANDATORY_MIN_LEN+2+strlen(interfaceInfo->SSID)+10+1), char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	offset=0;
	
	//frame control: 2 byte
	if(!CW80211AssembleIEFrameControl(&(beaconFrame[offset]), &(offset), WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_BEACON))
		return CW_FALSE;
	
	//duration: 2 byte
	if(!CW80211AssembleIEDuration(&(beaconFrame[offset]), &(offset), 0))
		return CW_FALSE;
	
	//da: 6 byte. Broadcast
	if(!CW80211AssembleIEAddr(&(beaconFrame[offset]), &(offset), NULL))
			return CW_FALSE;
	
	//sa: 6 byte
	if(!CW80211AssembleIEAddr(&(beaconFrame[offset]), &(offset), interfaceInfo->MACaddr))
			return CW_FALSE;

	//bssid: 6 byte
	if(!CW80211AssembleIEAddr(&(beaconFrame[offset]), &(offset), interfaceInfo->BSSID))
			return CW_FALSE;
	
	//2 (sequence ctl) + 8 (timestamp): vengono impostati in automatico
	offset += LEN_IE_SEQ_CTRL;
	offset += LEN_IE_TIMESTAMP;
	
	//beacon interval: 2 byte
	if(!CW80211AssembleIEBeaconInterval(&(beaconFrame[offset]), &(offset), 100))
			return CW_FALSE;
	
	//capability: 2 byte
	if(!CW80211AssembleIECapability(&(beaconFrame[offset]), &(offset), interfaceInfo->capabilityBit))
			return CW_FALSE;
			
	//SSID
	if(!CW80211AssembleIESSID(&(beaconFrame[offset]), &(offset), interfaceInfo->SSID))
		return CW_FALSE;
		
	//DSSS
	unsigned char channel = CW_WTP_DEFAULT_RADIO_CHANNEL+1;
	if(!CW80211AssembleIEDSSS(&(beaconFrame[offset]), &(offset), channel))
		return CW_FALSE;
/* *************************************************** */
	
	NLA_PUT(msg, NL80211_ATTR_BEACON_HEAD, offset, beaconFrame);
	//NLA_PUT(msg, NL80211_ATTR_BEACON_TAIL, NULL, params->tail);	
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifIndex);
	NLA_PUT_U32(msg, NL80211_ATTR_BEACON_INTERVAL, 1);
	NLA_PUT_U32(msg, NL80211_ATTR_DTIM_PERIOD, 1);
	
	NLA_PUT(msg, NL80211_ATTR_SSID, strlen(interfaceInfo->SSID), interfaceInfo->SSID);
	if(interfaceInfo->authType == NL80211_AUTHTYPE_OPEN_SYSTEM)
		NLA_PUT_U32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
	//TODO: else
			
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, NULL, NULL);
	CWLog("ret: %d", ret);
	if( ret != 0)
		return CW_FALSE;
		
	msg = NULL;
	
	CWLog("Interface %s started AP activity", interfaceInfo->ifName);
	
	return CW_TRUE;
	
 nla_put_failure:
	CWLog("failure");
	nlmsg_free(msg);
	return CW_FALSE;
}

CWBool nl80211CmdNewStation(WTPBSSInfo * infoBSS, WTPSTAInfo staInfo){
	struct nl_msg *msg;
	
	CWLog("NL80211_CMD_NEW_STATION. WLanID: %d, MacAddr[0](%02x) - MacAddr[5](%02x)", infoBSS->interfaceInfo->realWlanID, (int)staInfo.address[0], (int)staInfo.address[5]);
	
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;
	
	genlmsg_put(msg, 0, 0, infoBSS->BSSNLSock.nl80211_id, 0, 0, NL80211_CMD_NEW_STATION, 0);
	/* WLAN ID */
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, infoBSS->interfaceInfo->realWlanID);
	/* STA MAC Addr */
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, staInfo.address);
	/* SUPPORTED RATES */
	int lenRates=0;
	if(infoBSS->phyInfo->lenSupportedRates < CW_80211_MAX_SUPP_RATES)
		lenRates = infoBSS->phyInfo->lenSupportedRates;
	else
		lenRates = CW_80211_MAX_SUPP_RATES;
	NLA_PUT(msg, NL80211_ATTR_STA_SUPPORTED_RATES, lenRates, infoBSS->phyInfo->phyMbpsSet);
	
	CWLog("lenRates: %d", lenRates);
	int i;
	for(i=0; i<lenRates; i++)
		CWLog("Rate[%d]: %f", i, infoBSS->phyInfo->phyMbpsSet[i]);
	
	/* Association ID */
	NLA_PUT_U16(msg, NL80211_ATTR_STA_AID, staInfo.staAID);
	CWLog("staInfo.staAID: %x", staInfo.staAID);
	/* Listen Interval */
	NLA_PUT_U16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL, staInfo.listenInterval);	
	CWLog("staInfo.listenInterval: %x", staInfo.listenInterval);
	/* Capability */
	NLA_PUT_U16(msg, NL80211_ATTR_STA_CAPABILITY, staInfo.capabilityBit);
	CWLog("staInfo.capabilityBit: %d", staInfo.capabilityBit);

	int ret = nl80211_send_recv_cb_input(&(infoBSS->BSSNLSock), msg, NULL, NULL);
	CWLog("ret: %d", ret);
	if( ret != 0)
		return CW_FALSE;
	
	CWLog("[NL80211] New station ok. Waiting for data from STA %02x:%02x:%02x:%02x:%02x:%02x", (int)staInfo.address[0], (int)staInfo.address[1], (int)staInfo.address[2], (int)staInfo.address[3], (int)staInfo.address[4], (int)staInfo.address[5]);
	msg = NULL;
	
	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

CWBool nl80211CmdSetStation(WTPBSSInfo * infoBSS, WTPSTAInfo staInfo){
	struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;
	
	CWLog("NL80211_CMD_SET_STATION");
	genlmsg_put(msg, 0, 0, infoBSS->BSSNLSock.nl80211_id, 0, 0, NL80211_CMD_SET_STATION, 0);
	/* WLAN ID */
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, infoBSS->interfaceInfo->realWlanID);
	/* STA MAC Addr */
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, staInfo.address);
	/* SUPPORTED RATES */
	int lenRates=0;
	if(infoBSS->phyInfo->lenSupportedRates < CW_80211_MAX_SUPP_RATES)
		lenRates = infoBSS->phyInfo->lenSupportedRates;
	else
		lenRates = CW_80211_MAX_SUPP_RATES;
	NLA_PUT(msg, NL80211_ATTR_STA_SUPPORTED_RATES, lenRates, infoBSS->phyInfo->phyMbpsSet);
	
	/* Capability */
	NLA_PUT_U16(msg, NL80211_ATTR_STA_CAPABILITY, staInfo.capabilityBit);

	int ret = nl80211_send_recv_cb_input(&(infoBSS->BSSNLSock), msg, NULL, NULL);
	CWLog("ret: %d", ret);
	if( ret != 0)
		return CW_FALSE;
	
	CWLog("[NL80211] Set STA %02x:%02x:%02x:%02x:%02x:%02x ok", (int)staInfo.address[0], (int)staInfo.address[1], (int)staInfo.address[2], (int)staInfo.address[3], (int)staInfo.address[4], (int)staInfo.address[5]);
	msg = NULL;
	
	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

CWBool nl80211CmdDelStation(WTPBSSInfo * infoBSS, char * macAddress){
	struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;
	
	genlmsg_put(msg, 0, 0, infoBSS->BSSNLSock.nl80211_id, 0, 0, NL80211_CMD_DEL_STATION, 0);
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, macAddress);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, infoBSS->interfaceInfo->realWlanID);

	int ret = nl80211_send_recv_cb_input(&(infoBSS->BSSNLSock), msg, NULL, NULL);
	CWLog("ret: %d", ret);
	if( ret != 0)
		return CW_FALSE;
	
	CWLog("[NL80211] Del STA %02x:%02x:%02x:%02x:%02x:%02x ok", (int)macAddress[0], (int)macAddress[1], (int)macAddress[2], (int)macAddress[3], (int)macAddress[4], (int)macAddress[5]);
	msg = NULL;
	
	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

int nl80211_set_bss(WTPInterfaceInfo * interfaceInfo, int cts, int preamble)
/*
			   int slot, int ht_opmode, int ap_isolate,
			   int *basic_rates)
*/			   
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_SET_BSS, 0);

	if (cts >= 0)
		NLA_PUT_U8(msg, NL80211_ATTR_BSS_CTS_PROT, cts);
	if (preamble >= 0)
		NLA_PUT_U8(msg, NL80211_ATTR_BSS_SHORT_PREAMBLE, preamble);
/*	if (slot >= 0)
		NLA_PUT_U8(msg, NL80211_ATTR_BSS_SHORT_SLOT_TIME, slot);
	if (ht_opmode >= 0)
		NLA_PUT_U16(msg, NL80211_ATTR_BSS_HT_OPMODE, ht_opmode);
	if (ap_isolate >= 0)
		NLA_PUT_U8(msg, NL80211_ATTR_AP_ISOLATE, ap_isolate);

	if (basic_rates) {
		u8 rates[NL80211_MAX_SUPP_RATES];
		u8 rates_len = 0;
		int i;

		for (i = 0; i < NL80211_MAX_SUPP_RATES && basic_rates[i] >= 0;
		     i++)
			rates[rates_len++] = basic_rates[i] / 5;

		NLA_PUT(msg, NL80211_ATTR_BSS_BASIC_RATES, rates_len, rates);
	}
*/

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, interfaceInfo->realWlanID);

	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, NULL, NULL);
	CWLog("ret nl80211_set_bss: %d", ret);
	if( ret != 0)
		return CW_FALSE;
		
	msg = NULL;

	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

/*
 * N.B. For beacon params: src/ap/beacon.c: ieee802_11_build_ap_params
 * For start ap: src/driver/driver_nl80211.c :wpa_driver_nl80211_set_ap
 */
CWBool nl80211CmdStopAP(char * ifName){
	struct nl_msg *msg;
	int ifIndex = if_nametoindex(ifName);
	
	struct ieee80211_mgmt *head = NULL;
	u8 *tail = NULL;
	size_t head_len = 0, tail_len = 0;
	struct wpa_driver_ap_params * params;
	u8 *pos, *tailpos;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;
	
	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_DEL_BEACON, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifIndex);
	
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, NULL, NULL);
	CWLog("ret: %d", ret);

	if( ret != 0)
		return CW_FALSE;
		
	msg = NULL;
	
	CWLog("Interrotta azione di AP di interfaccia %d", ifIndex);


	return CW_TRUE;
	
 nla_put_failure:
	CWLog("failure");
	nlmsg_free(msg);
	return CW_FALSE;
}

int nl80211GetTxqParams(struct nl80211SocketUnit *nlSockUnit, WTPQosValues * qosValues, int ifindex)
{
	struct nl_msg *msg;
	struct nlattr *txq, *params;
	int flags=0;
	
	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	genlmsg_put(msg, 0, 0, nlSockUnit->nl80211_id, 0, flags, NL80211_CMD_GET_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
	
	if (nl80211_send_recv_cb_input(nlSockUnit, msg, CB_getQoSValues, qosValues) == 0)
	{
		CWLog("[NL80211] ERROR: nl80211_send_recv_cb_input");
		return 0;
	}

	msg = NULL;
	
	return 1;
	
 nla_put_failure:
	nlmsg_free(msg);
	return -1;
}

/************************************
 * AP: Registra ricezione mgmt frame
 ***********************************/
 
int CW80211SetAPTypeFrame(WTPInterfaceInfo * interfaceInfo, int radioID, WTPBSSInfo * WTPBSSInfoPtr)
{
	static const int stypes[] = {
		WLAN_FC_STYPE_AUTH,
		WLAN_FC_STYPE_ASSOC_REQ,
		WLAN_FC_STYPE_REASSOC_REQ,
		WLAN_FC_STYPE_DISASSOC,
		WLAN_FC_STYPE_DEAUTH,
		WLAN_FC_STYPE_ACTION,
		WLAN_FC_STYPE_PROBE_REQ,
/* Beacon doesn't work as mac80211 doesn't currently allow
 * it, but it wouldn't really be the right thing anyway as
 * it isn't per interface ... maybe just dump the scan
 * results periodically for OLBC?
 */
		/* WLAN_FC_STYPE_BEACON, */
	};
	unsigned int i;

	//Creo callback specifica per interfaccia e poi la assegno al nl_mgmt
	if(CW80211InitNlCb(WTPBSSInfoPtr) == -1)
		return -1;

	interfaceInfo->nl_mgmt = NULL;
	if (nl80211_alloc_mgmt_handle(interfaceInfo) != 0)
		return -1;
	
	CWLog("nl80211: Subscribe to mgmt frames with AP handle %p", interfaceInfo->nl_mgmt);

	for (i = 0; i < ARRAY_SIZE(stypes); i++) {
		if (nl80211_register_frame(interfaceInfo, interfaceInfo->nl_mgmt, (WLAN_FC_TYPE_MGMT << 2) | (stypes[i] << 4), NULL, 0) < 0) {
			goto out_err;
		}	
	}

	if (nl80211_register_spurious_class3(interfaceInfo))
		goto out_err;

/*
	if (nl80211_get_wiphy_data_ap(interfaceInfo, radioID) == NULL)
		goto out_err;
*/
	//nl80211_mgmt_handle_register_eloop(interfaceInfo);
	
	return 0;

out_err:
	nl_destroy_handles(&interfaceInfo->nl_mgmt);
	return -1;
}

int nl80211_alloc_mgmt_handle(WTPInterfaceInfo * interfaceInfo)
{
	if (interfaceInfo->nl_mgmt) {
		CWLog("nl80211: Mgmt reporting already on! (nl_mgmt=%p)", interfaceInfo->nl_mgmt);
		return -1;
	}

	interfaceInfo->nl_mgmt = nl_create_handle(interfaceInfo->nl_cb, "mgmt");
	if (interfaceInfo->nl_mgmt == NULL)
	{
		CWLog("nl80211: nl80211_alloc_mgmt_handle error");
		return -1;
	}
	
	return 0;
}

int nl80211_register_frame(WTPInterfaceInfo * interfaceInfo,
				  struct nl_handle *nl_handle,
				  u16 type, const u8 *match, size_t match_len)
{
	struct nl_msg *msg;
	int ret = -1;
	char buf[30];

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	CWLog("nl80211: Register frame type=0x%x (%d) nl_handle=%p interface: %d", type, type, nl_handle, interfaceInfo->realWlanID);
	
	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_REGISTER_FRAME, 0);
	//Associo la ricezione dei frame management all'interfaccia in questione
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, interfaceInfo->realWlanID);
	NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, type);
	NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, match_len, match);
	
	//Corretto questo netlink global?
	ret = send_and_recv(&(globalNLSock), nl_handle, msg, NULL, NULL);
	
	CWLog("ret: %d", ret);
	if( ret != 0)
	{
		CWLog("nl80211: Register frame command failed (type=%u): ret=%d (%s)", type, ret, strerror(-ret));
		return CW_FALSE;
	}
	
	CWLog("nl80211: Register frame command OK (type=%u)", type);
	
	msg = NULL;
	
	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

/**
 *  @NL80211_CMD_UNEXPECTED_FRAME: Used by an application controlling an AP
 *	(or GO) interface (i.e. hostapd) to ask for unexpected frames to
 *	implement sending deauth to stations that send unexpected class 3
 *	frames. Also used as the event sent by the kernel when such a frame
 *	is received.
 *	For the event, the %NL80211_ATTR_MAC attribute carries the TA and
 *	other attributes like the interface index are present.
 *	If used as the command it must have an interface index and you can
 *	only unsubscribe from the event by closing the socket. Subscription
 *	is also for %NL80211_CMD_UNEXPECTED_4ADDR_FRAME events.
 **/
int nl80211_register_spurious_class3(WTPInterfaceInfo * interfaceInfo)
{
	struct nl_msg *msg;
	int ret = -1;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_UNEXPECTED_FRAME, 0);
	//Associo la ricezione dei frame management all'interfaccia in questione
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, interfaceInfo->realWlanID);
	
	ret = send_and_recv(&(globalNLSock), interfaceInfo->nl_mgmt, msg, NULL, NULL);
	
	msg = NULL;
	if (ret) {
		CWLog("nl80211: Register spurious class3 failed: ret=%d (%s)", ret, strerror(-ret));
		goto nla_put_failure;
	}
	
	CWLog("nl80211_register_spurious_class3 ret: %d", ret);
	ret = 0;
	
nla_put_failure:
	nlmsg_free(msg);
	return ret;
}
 
/*
 * Lettura dal socket con eloop_*. Hostapd functions
 */
 /*
void nl80211_mgmt_handle_register_eloop(WTPInterfaceInfo * interfaceInfo)
{
	nl80211_register_eloop_read(&interfaceInfo->nl_mgmt,
				    wpa_driver_nl80211_event_receive,
				    interfaceInfo->nl_cb);
}

void nl80211_register_eloop_read(struct nl_handle **handle,
					eloop_sock_handler handler,
					void *eloop_data)
{
	nl_socket_set_nonblocking(*handle);
		
	int ret = eloop_register_read_sock(nl_socket_get_fd(*handle), handler, eloop_data, *handle);
	*handle = (void *) (((intptr_t) *handle) ^ ELOOP_SOCKET_INVALID);
}
*/


CWBool CW80211SendFrame(WTPBSSInfo * WTPBSSInfoPtr, unsigned int freq, unsigned int wait, char * buf, size_t buf_len, u64 *cookie_out, int no_cck, int no_ack)
{
	struct nl_msg *msg;
	u64 cookie;
	int ret = -1;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;
	
	CWLog("nl80211: CMD_FRAME freq=%u wait=%u no_cck=%d no_ack=%d", freq, wait, no_cck, no_ack);

	genlmsg_put(msg, 0, 0, WTPBSSInfoPtr->BSSNLSock.nl80211_id, 0, 0, NL80211_CMD_FRAME, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, WTPBSSInfoPtr->interfaceInfo->realWlanID);
	
	//Frame da inviare
	NLA_PUT(msg, NL80211_ATTR_FRAME, buf_len, buf);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, gRadiosInfo.radiosInfo[0].gWTPPhyInfo.phyFrequencyInfo.frequencyList[CW_WTP_DEFAULT_RADIO_CHANNEL].frequency);
	NLA_PUT_FLAG(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK);
	
	/*
	NLA_PUT_FLAG(msg, NL80211_ATTR_TX_NO_CCK_RATE);
	//int channel = 2417;
	//NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, channel);
	
	
	*/
	/*
	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
11060             (netdev && nla_put_u32(msg, NL80211_ATTR_IFINDEX,
11061                                         netdev->ifindex)) ||
11062             nla_put_u64(msg, NL80211_ATTR_WDEV, wdev_id(wdev)) ||
11063             nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq) ||
11064             
* (sig_dbm &&
11065              nla_put_u32(msg, NL80211_ATTR_RX_SIGNAL_DBM, sig_dbm)) ||
11066             nla_put(msg, NL80211_ATTR_FRAME, len, buf) ||
11067             (flags &&
11068              nla_put_u32(msg, NL80211_ATTR_RXMGMT_FLAGS, flags)))
11069                 goto nla_put_failure;
*/

	//Frequenza (canale) su cui inviare il frame
//	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, 2417);
	//Opzionale: tempo di attesa risposta
	//if (wait)
	//	NLA_PUT_U32(msg, NL80211_ATTR_DURATION, wait);
	/*
	 if (offchanok && ((drv->capa.flags & WPA_DRIVER_FLAGS_OFFCHANNEL_TX) ||
			  drv->test_use_roc_tx))
		NLA_PUT_FLAG(msg, NL80211_ATTR_OFFCHANNEL_TX_OK);
	*/
	//is used to decide whether to send the management frames at CCK rate or not in 2GHz band.
	//if (no_cck)
//		NLA_PUT_FLAG(msg, NL80211_ATTR_TX_NO_CCK_RATE);
	//attendi o no un ack
	/*if (no_ack)
		NLA_PUT_FLAG(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK);
*/

	//L'operazione ritorna un cookie
	cookie = 0;
//	ret = send_and_recv(&(globalNLSock), interfaceInfo->nl_mgmt, msg, CB_cookieHandler, &cookie);
	
	ret = nl80211_send_recv_cb_input(&(WTPBSSInfoPtr->BSSNLSock), msg, NULL, NULL); //CB_cookieHandler, &cookie);
//	ret = send_and_recv(drv, msg, CB_cookieHandler, &cookie);
	
	msg = NULL;
	if (ret) {
		
		CWLog("nl80211: Frame command failed: ret=%d (%s) (freq=%u wait=%u) nl_geterror: %s", ret, strerror(-ret), freq, wait, nl_geterror(ret));
		goto nla_put_failure;
	}
	CWLog("nl80211: Frame TX command accepted%s; cookie 0x%llx", no_ack ? " (no ACK)" : "", (long long unsigned int) cookie);

	/*if (cookie_out)
		*cookie_out = no_ack ? (u64) -1 : cookie;
	*/
	
	return CW_TRUE;
	
nla_put_failure:
	nlmsg_free(msg);
	return ret;
}



const char * nl80211_command_to_string(enum nl80211_commands cmd)
{
#define C2S(x) case x: return #x;
	switch (cmd) {
	C2S(NL80211_CMD_UNSPEC)
	C2S(NL80211_CMD_GET_WIPHY)
	C2S(NL80211_CMD_SET_WIPHY)
	C2S(NL80211_CMD_NEW_WIPHY)
	C2S(NL80211_CMD_DEL_WIPHY)
	C2S(NL80211_CMD_GET_INTERFACE)
	C2S(NL80211_CMD_SET_INTERFACE)
	C2S(NL80211_CMD_NEW_INTERFACE)
	C2S(NL80211_CMD_DEL_INTERFACE)
	C2S(NL80211_CMD_GET_KEY)
	C2S(NL80211_CMD_SET_KEY)
	C2S(NL80211_CMD_NEW_KEY)
	C2S(NL80211_CMD_DEL_KEY)
	C2S(NL80211_CMD_GET_BEACON)
	C2S(NL80211_CMD_SET_BEACON)
	C2S(NL80211_CMD_START_AP)
	C2S(NL80211_CMD_STOP_AP)
	C2S(NL80211_CMD_GET_STATION)
	C2S(NL80211_CMD_SET_STATION)
	C2S(NL80211_CMD_NEW_STATION)
	C2S(NL80211_CMD_DEL_STATION)
	C2S(NL80211_CMD_GET_MPATH)
	C2S(NL80211_CMD_SET_MPATH)
	C2S(NL80211_CMD_NEW_MPATH)
	C2S(NL80211_CMD_DEL_MPATH)
	C2S(NL80211_CMD_SET_BSS)
	C2S(NL80211_CMD_SET_REG)
	C2S(NL80211_CMD_REQ_SET_REG)
	C2S(NL80211_CMD_GET_MESH_CONFIG)
	C2S(NL80211_CMD_SET_MESH_CONFIG)
	C2S(NL80211_CMD_SET_MGMT_EXTRA_IE)
	C2S(NL80211_CMD_GET_REG)
	C2S(NL80211_CMD_GET_SCAN)
	C2S(NL80211_CMD_TRIGGER_SCAN)
	C2S(NL80211_CMD_NEW_SCAN_RESULTS)
	C2S(NL80211_CMD_SCAN_ABORTED)
	C2S(NL80211_CMD_REG_CHANGE)
	C2S(NL80211_CMD_AUTHENTICATE)
	C2S(NL80211_CMD_ASSOCIATE)
	C2S(NL80211_CMD_DEAUTHENTICATE)
	C2S(NL80211_CMD_DISASSOCIATE)
	C2S(NL80211_CMD_MICHAEL_MIC_FAILURE)
	C2S(NL80211_CMD_REG_BEACON_HINT)
	C2S(NL80211_CMD_JOIN_IBSS)
	C2S(NL80211_CMD_LEAVE_IBSS)
	C2S(NL80211_CMD_TESTMODE)
	C2S(NL80211_CMD_CONNECT)
	C2S(NL80211_CMD_ROAM)
	C2S(NL80211_CMD_DISCONNECT)
	C2S(NL80211_CMD_SET_WIPHY_NETNS)
	C2S(NL80211_CMD_GET_SURVEY)
	C2S(NL80211_CMD_NEW_SURVEY_RESULTS)
	C2S(NL80211_CMD_SET_PMKSA)
	C2S(NL80211_CMD_DEL_PMKSA)
	C2S(NL80211_CMD_FLUSH_PMKSA)
	C2S(NL80211_CMD_REMAIN_ON_CHANNEL)
	C2S(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL)
	C2S(NL80211_CMD_SET_TX_BITRATE_MASK)
	C2S(NL80211_CMD_REGISTER_FRAME)
	C2S(NL80211_CMD_FRAME)
	C2S(NL80211_CMD_FRAME_TX_STATUS)
	C2S(NL80211_CMD_SET_POWER_SAVE)
	C2S(NL80211_CMD_GET_POWER_SAVE)
	C2S(NL80211_CMD_SET_CQM)
	C2S(NL80211_CMD_NOTIFY_CQM)
	C2S(NL80211_CMD_SET_CHANNEL)
	C2S(NL80211_CMD_SET_WDS_PEER)
	C2S(NL80211_CMD_FRAME_WAIT_CANCEL)
	C2S(NL80211_CMD_JOIN_MESH)
	C2S(NL80211_CMD_LEAVE_MESH)
	C2S(NL80211_CMD_UNPROT_DEAUTHENTICATE)
	C2S(NL80211_CMD_UNPROT_DISASSOCIATE)
	C2S(NL80211_CMD_NEW_PEER_CANDIDATE)
	C2S(NL80211_CMD_GET_WOWLAN)
	C2S(NL80211_CMD_SET_WOWLAN)
	C2S(NL80211_CMD_START_SCHED_SCAN)
	C2S(NL80211_CMD_STOP_SCHED_SCAN)
	C2S(NL80211_CMD_SCHED_SCAN_RESULTS)
	C2S(NL80211_CMD_SCHED_SCAN_STOPPED)
	C2S(NL80211_CMD_SET_REKEY_OFFLOAD)
	C2S(NL80211_CMD_PMKSA_CANDIDATE)
	C2S(NL80211_CMD_TDLS_OPER)
	C2S(NL80211_CMD_TDLS_MGMT)
	C2S(NL80211_CMD_UNEXPECTED_FRAME)
	C2S(NL80211_CMD_PROBE_CLIENT)
	C2S(NL80211_CMD_REGISTER_BEACONS)
	C2S(NL80211_CMD_UNEXPECTED_4ADDR_FRAME)
	C2S(NL80211_CMD_SET_NOACK_MAP)
	C2S(NL80211_CMD_CH_SWITCH_NOTIFY)
	C2S(NL80211_CMD_START_P2P_DEVICE)
	C2S(NL80211_CMD_STOP_P2P_DEVICE)
	C2S(NL80211_CMD_CONN_FAILED)
	C2S(NL80211_CMD_SET_MCAST_RATE)
	C2S(NL80211_CMD_SET_MAC_ACL)
	C2S(NL80211_CMD_RADAR_DETECT)
	C2S(NL80211_CMD_GET_PROTOCOL_FEATURES)
	C2S(NL80211_CMD_UPDATE_FT_IES)
	C2S(NL80211_CMD_FT_EVENT)
	C2S(NL80211_CMD_CRIT_PROTOCOL_START)
	C2S(NL80211_CMD_CRIT_PROTOCOL_STOP)
	C2S(NL80211_CMD_GET_COALESCE)
	C2S(NL80211_CMD_SET_COALESCE)
	C2S(NL80211_CMD_CHANNEL_SWITCH)
	C2S(NL80211_CMD_VENDOR)
	C2S(NL80211_CMD_SET_QOS_MAP)
	default:
		return "NL80211_CMD_UNKNOWN";
	}
#undef C2S
}


/*****************************************************
 * Interaction with ioctl
 *****************************************************/

CWBool ioctlActivateInterface(char * interface){

	int ret;
	struct ifreq ifr;
	
	int ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (ioctl_sock < 0) {
		CWLog("nl80211: socket(PF_INET,SOCK_DGRAM) failed: %s", strerror(errno));
		
		return CW_FALSE;
	}
	
	os_memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, strlen(interface));
/*
	if (ioctl(ioctl_sock, SIOCGIFFLAGS, &ifr) != 0) {
		ret = errno ? -errno : -999;
		CWLog("1 Could not read interface wtpLan1 flags: %s", strerror(errno));
		exit(-1);
	}
*/
	int dev_up=1;

	ifr.ifr_flags |= IFF_UP;
	
	if (ioctl(ioctl_sock, SIOCSIFFLAGS, &ifr) != 0) {
		ret = errno ? -errno : -999;
		CWLog("2 Could not set interface %s flags (%s): %s", interface, dev_up ? "UP" : "DOWN", strerror(errno));
		
		return CW_FALSE;
	}
	
	CWLog("Interface %s set IFF_UP", interface);
	
	return CW_TRUE;
}
