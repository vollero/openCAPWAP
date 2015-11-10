/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	NL80211 Integration + libnl
 * 
 ***************************************/
#include "CWWTP.h"
 
CWBool nl80211CmdGetPhyInfo(int indexPhy, struct WTPSinglePhyInfo * singlePhyInfo){
	struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;
	
//	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);
	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_GET_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, gPhyInterfaceIndex[indexPhy]);
//	NLA_PUT_STRING(msg, NL80211_ATTR_WIPHY_NAME, "phy1");
	
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, CB_getPhyInfo, singlePhyInfo);
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Get phy info error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}

		
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
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, gPhyInterfaceIndex[indexPhy]);
	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, interfaceInfo->ifName);	
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyFrequencyInfo.frequencyList[CW_WTP_DEFAULT_RADIO_CHANNEL].frequency);
	enum nl80211_iftype typeIf = NL80211_IFTYPE_STATION;
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, typeIf);
	
	/*
	 * Tell cfg80211 that the interface belongs to the socket that created
	 * it, and the interface should be deleted when the socket is closed.
	 * NLA_PUT_FLAG(msg, NL80211_ATTR_IFACE_SOCKET_OWNER);
	 */
	
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, CB_setNewInterface, interfaceInfo);
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Set new interface error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}
		
	msg = NULL;

	//retrive MAC address
	CW_CREATE_ARRAY_CALLOC_ERR(interfaceInfo->MACaddr, MAC_ADDR_LEN, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	getInterfaceMacAddr(interfaceInfo->ifName, interfaceInfo->MACaddr);

	CWLog("[NL80211 INFO] Interface %s created", interfaceInfo->ifName);
	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}


CWBool nl80211CmdSetNewMonitorInterface(int indexPhy, WTPInterfaceInfo * interfaceInfo){
		struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;
	
	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_NEW_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, indexPhy);
	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, interfaceInfo->ifName);
	
	enum nl80211_iftype typeIf = NL80211_IFTYPE_MONITOR;
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, typeIf);
	
	/*struct nlattr *flags;
	flags = nla_nest_start(msg, NL80211_ATTR_MNTR_FLAGS);
	if (!flags)
		goto nla_put_failure;
	NLA_PUT_FLAG(msg, NL80211_MNTR_FLAG_COOK_FRAMES);
	nla_nest_end(msg, flags);
	NL80211_MNTR_FLAG_OTHER_BSS
	*/
	/*
	 * Tell cfg80211 that the interface belongs to the socket that created
	 * it, and the interface should be deleted when the socket is closed.
	 */
	NLA_PUT_FLAG(msg, NL80211_ATTR_IFACE_SOCKET_OWNER);
	
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, CB_setNewInterface, interfaceInfo);
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Create monitor interface error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}
		
	msg = NULL;

	//retrive MAC address
	CW_CREATE_ARRAY_CALLOC_ERR(interfaceInfo->MACaddr, MAC_ADDR_LEN, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	getInterfaceMacAddr(interfaceInfo->ifName, interfaceInfo->MACaddr);

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
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, gPhyInterfaceIndex[indexPhy]);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, index);
	
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, NULL, NULL);
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Del interface error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}
	
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
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Set AP interface error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}		
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
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Set STA interface error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}		
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

	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_SET_CHANNEL, 0); //NL80211_CMD_SET_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, index);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, channel);
//	NLA_PUT_U32(msg, NL80211_ATTR_CENTER_FREQ1, freq->center_freq1);
	
	//NLA_PUT_U32(msg, NL80211_ATTR_CHANNEL_WIDTH, NL80211_CHAN_WIDTH_80);
		
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, NULL, NULL);
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Set channel interface error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}
		
	msg = NULL;
	
	CWLog("Interface %s now channel %d", interface, channel);

	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

CWBool nl80211_get_channel_width(char * interface)
{
		struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;

	int index = if_nametoindex(interface);
	int indexPhy=1;
	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_GET_INTERFACE, 0); //NL80211_CMD_SET_WIPHY, 0);
//	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, indexPhy);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, index);
		
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, CBget_channel_width, NULL);
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Get Channel width error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}
		
	msg = NULL;
	
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

	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_GET_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, 0);
		
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, CB_getChannelInterface, channel);
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Get channel interface error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}
	
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
	
	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_START_AP, 0);

/* ***************** BEACON FRAME: DO IT BETTER ******************** */
CWLog("Start Beacon Generation");
	char * beaconFrame;
	CW_CREATE_ARRAY_CALLOC_ERR(beaconFrame, (MGMT_FRAME_FIXED_LEN_BEACON+MGMT_FRAME_IE_FIXED_LEN+strlen(interfaceInfo->SSID)+IE_TYPE_DSSS+1+(CW_80211_MAX_SUPP_RATES+gRadiosInfo.radiosInfo[0].gWTPPhyInfo.lenSupportedRates)+2+3), char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);); //MAC80211_HEADER_FIXED_LEN+MAC80211_BEACON_BODY_MANDATORY_MIN_LEN+2+strlen(interfaceInfo->SSID)+10+1), char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
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
	if(!CW80211AssembleIEBeaconInterval(&(beaconFrame[offset]), &(offset), htons(1)))
			return CW_FALSE;
	
	//capability: 2 byte
	if(!CW80211AssembleIECapability(&(beaconFrame[offset]), &(offset), interfaceInfo->capabilityBit))
			return CW_FALSE;
			
	//SSID
	if(!CW80211AssembleIESSID(&(beaconFrame[offset]), &(offset), interfaceInfo->SSID))
		return CW_FALSE;

	//Supported Rates
	int indexRates=0;
	unsigned char * suppRate;
	CW_CREATE_ARRAY_CALLOC_ERR(suppRate, gRadiosInfo.radiosInfo[0].gWTPPhyInfo.lenSupportedRates, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	for(indexRates=0; indexRates < WTP_NL80211_BITRATE_NUM && indexRates < gRadiosInfo.radiosInfo[0].gWTPPhyInfo.lenSupportedRates; indexRates++)
	{
		suppRate[indexRates] = (char) gRadiosInfo.radiosInfo[0].gWTPPhyInfo.supportedRates[indexRates];
		if(
			suppRate[indexRates] == 2 ||
			suppRate[indexRates] == 4 ||
			suppRate[indexRates] == 11 ||
			suppRate[indexRates] == 22
		)
			suppRate[indexRates] += 128;
			
			CWLog("Rate[%d]: %x", indexRates, suppRate[indexRates]);
	}
	
	if(!CW80211AssembleIESupportedRates(&(beaconFrame[offset]), &(offset), suppRate, indexRates))
		return CW_FALSE;
	
	//DSSS
	unsigned char channel = CW_WTP_DEFAULT_RADIO_CHANNEL+1;
	if(!CW80211AssembleIEDSSS(&(beaconFrame[offset]), &(offset), channel))
		return CW_FALSE;
	
	CWLog("Sto per mettere ERP");
	//ERP
	//aggiungi +3
	if(!CW80211AssembleIEERP(&(beaconFrame[offset]), &(offset), 0x04))
		return CW_FALSE;
/* *************************************************** */
	
	
/*	
	@NL80211_CMD_START_AP: Start AP operation on an AP interface, parameters
 *	are like for %NL80211_CMD_SET_BEACON, and additionally parameters that
 *	do not change are used, these include %NL80211_ATTR_BEACON_INTERVAL,
 *	%NL80211_ATTR_DTIM_PERIOD, %NL80211_ATTR_SSID,
 *	%NL80211_ATTR_HIDDEN_SSID, %NL80211_ATTR_CIPHERS_PAIRWISE,
 *	%NL80211_ATTR_CIPHER_GROUP, %NL80211_ATTR_WPA_VERSIONS,
 *	%NL80211_ATTR_AKM_SUITES, %NL80211_ATTR_PRIVACY,
 *	%NL80211_ATTR_AUTH_TYPE, %NL80211_ATTR_INACTIVITY_TIMEOUT,
 *	%NL80211_ATTR_ACL_POLICY and %NL80211_ATTR_MAC_ADDRS.
 *	The channel to use can be set on the interface or be given using the
 *	%NL80211_ATTR_WIPHY_FREQ and the attributes determining channel width.
 */
 
 int beaconInt = htons(1);
	NLA_PUT_U32(msg, NL80211_ATTR_BEACON_INTERVAL, beaconInt);
	NLA_PUT_U32(msg, NL80211_ATTR_DTIM_PERIOD, 1);
	NLA_PUT(msg, NL80211_ATTR_SSID, strlen(interfaceInfo->SSID), interfaceInfo->SSID);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, gRadiosInfo.radiosInfo[0].gWTPPhyInfo.phyFrequencyInfo.frequencyList[CW_WTP_DEFAULT_RADIO_CHANNEL].frequency);
	
	//NLA_PUT_U32(msg, NL80211_ATTR_CENTER_FREQ1, gRadiosInfo.radiosInfo[0].gWTPPhyInfo.phyFrequencyInfo.frequencyList[CW_WTP_DEFAULT_RADIO_CHANNEL].frequency);
		
	NLA_PUT(msg, NL80211_ATTR_BEACON_HEAD, offset, beaconFrame);
	//NLA_PUT(msg, NL80211_ATTR_BEACON_TAIL, NULL, params->tail);	
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifIndex);
	
	if(interfaceInfo->authType == NL80211_AUTHTYPE_OPEN_SYSTEM)
		NLA_PUT_U32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
	//TODO: else
			
	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, NULL, NULL);
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Start AP beacon error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}
		
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
	unsigned char * rateChar;
	int indexRates=0;
	int indexRates2=0;
		
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;
		
	CWLog("ADD STATION request");
	genlmsg_put(msg, 0, 0, infoBSS->BSSNLSock.nl80211_id, 0, 0, NL80211_CMD_NEW_STATION, 0);
	/* WLAN ID */
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, infoBSS->interfaceInfo->realWlanID);
	CWLog("wlanid: %d", infoBSS->interfaceInfo->realWlanID);
	/* STA MAC Addr */
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, staInfo.address);
	CWPrintEthernetAddress(staInfo.address, "STA address:");
	/* SUPPORTED RATES */
	int lenRates = staInfo.lenSupportedRates+staInfo.extSupportedRatesLen; //infoBSS->phyInfo->lenSupportedRates;
	CWLog("Len RATES tot: %d", lenRates);
	CW_CREATE_ARRAY_CALLOC_ERR(rateChar, lenRates, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return CW_FALSE;});
	for(indexRates=0; indexRates < staInfo.lenSupportedRates; indexRates++)
	{	
		rateChar[indexRates] = ((int)staInfo.supportedRates[indexRates]); /* / 0.5 */
		CWLog("Supported rates %d: %d", indexRates, rateChar[indexRates]);
	}
	
	if(staInfo.extSupportedRatesLen > 0)
	{
		for(indexRates2=0; indexRates < lenRates; indexRates2++, indexRates++)
		{	
			rateChar[indexRates2] = ((int)staInfo.extSupportedRates[indexRates2]);
			CWLog("Ext supported rates %d: %d", indexRates, rateChar[indexRates]);
		}
	}
	
	CWLog("len rates: %d", lenRates);
	NLA_PUT(msg, NL80211_ATTR_STA_SUPPORTED_RATES, lenRates, rateChar);
		
	/* Association ID */
	NLA_PUT_U16(msg, NL80211_ATTR_STA_AID, staInfo.staAID);
	CWLog("staAID: %x", staInfo.staAID);

	/* Listen Interval */
	NLA_PUT_U16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL, staInfo.listenInterval);
	CWLog("listenIntervaL: %x", staInfo.listenInterval);
	/* Capability */
	NLA_PUT_U16(msg, NL80211_ATTR_STA_CAPABILITY, staInfo.capabilityBit);
	
	CWLog("capabilityBit: %x", staInfo.capabilityBit);
	
	struct nl80211_sta_flag_update flags;
	os_memset(&flags, 0, sizeof(flags));
	//flags.mask |= BIT(NL80211_STA_FLAG_SHORT_PREAMBLE);
	flags.mask |= BIT(NL80211_STA_FLAG_AUTHORIZED);
	flags.set = flags.mask;
	NLA_PUT(msg, NL80211_ATTR_STA_FLAGS2, sizeof(flags), &flags);
	
	int ret = nl80211_send_recv_cb_input(&(infoBSS->BSSNLSock), msg, NULL, NULL);
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Add new STA error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}
	
	CWPrintEthernetAddress(staInfo.address, "New station ok. Waiting for data from STA");

	msg = NULL;
	
	CW_FREE_OBJECT(rateChar);
	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

CWBool nl80211CmdSetStation(WTPBSSInfo * infoBSS, WTPSTAInfo staInfo){

	struct nl_msg *msg;
	unsigned char * rateChar;
	int indexRates=0;
	int indexRates2=0;

	CWLog("SET/UPDATE STATION request");
	return CW_TRUE;
	
	/*
	 * TODO: This command give always an error if station is
	 * already associated. 
	 */	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;
	

	genlmsg_put(msg, 0, 0, infoBSS->BSSNLSock.nl80211_id, 0, 0, NL80211_CMD_SET_STATION, 0);
	/* WLAN ID */
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, infoBSS->interfaceInfo->realWlanID);
	CWLog("wlanid: %d", infoBSS->interfaceInfo->realWlanID);
	/* STA MAC Addr */
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, staInfo.address);
	CWPrintEthernetAddress(staInfo.address, "STA address:");
	/* SUPPORTED RATES */
	int lenRates = staInfo.lenSupportedRates+staInfo.extSupportedRatesLen; //infoBSS->phyInfo->lenSupportedRates;
	CWLog("Len RATES tot: %d", lenRates);
	CW_CREATE_ARRAY_CALLOC_ERR(rateChar, lenRates, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return CW_FALSE;});
	for(indexRates=0; indexRates < staInfo.lenSupportedRates; indexRates++)
	{	
		rateChar[indexRates] = ((int)staInfo.supportedRates[indexRates]); /* / 0.5 */
		CWLog("Supported rates %d: %d", indexRates, rateChar[indexRates]);
	}
	
	if(staInfo.extSupportedRatesLen > 0)
	{
		for(indexRates2=0; indexRates < lenRates; indexRates2++, indexRates++)
		{	
			rateChar[indexRates2] = ((int)staInfo.extSupportedRates[indexRates2]);
			CWLog("Ext supported rates %d: %d", indexRates, rateChar[indexRates]);
		}
	}

	CWLog("len rates: %d", lenRates);
	NLA_PUT(msg, NL80211_ATTR_STA_SUPPORTED_RATES, lenRates, rateChar);
		
	/* Association ID */
	NLA_PUT_U16(msg, NL80211_ATTR_STA_AID, staInfo.staAID);
	CWLog("staAID: %x", staInfo.staAID);

	/* Listen Interval */
	NLA_PUT_U16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL, staInfo.listenInterval);
	CWLog("listenIntervaL: %x", staInfo.listenInterval);
	/* Capability */
	NLA_PUT_U16(msg, NL80211_ATTR_STA_CAPABILITY, staInfo.capabilityBit);
	
	CWLog("capabilityBit: %x", staInfo.capabilityBit);
	
	struct nl80211_sta_flag_update flags;
	os_memset(&flags, 0, sizeof(flags));
	//flags.mask |= BIT(NL80211_STA_FLAG_SHORT_PREAMBLE);
	flags.mask |= BIT(NL80211_STA_FLAG_AUTHORIZED);
	flags.set = flags.mask;
	NLA_PUT(msg, NL80211_ATTR_STA_FLAGS2, sizeof(flags), &flags);
	int ret = nl80211_send_recv_cb_input(&(infoBSS->BSSNLSock), msg, NULL, NULL);
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Set update STA error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}
	
	CWPrintEthernetAddress(staInfo.address, "Set STA info ok");
	msg = NULL;
	
	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

CWBool nl80211CmdDelStation(WTPBSSInfo * infoBSS, unsigned char * macAddress){
	struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg)
		return CW_FALSE;
	
	genlmsg_put(msg, 0, 0, infoBSS->BSSNLSock.nl80211_id, 0, 0, NL80211_CMD_DEL_STATION, 0);
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, macAddress);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, infoBSS->interfaceInfo->realWlanID);

	int ret = nl80211_send_recv_cb_input(&(infoBSS->BSSNLSock), msg, NULL, NULL);
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Del STA error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}
	
	CWPrintEthernetAddress(macAddress, "Del STA ok");

	msg = NULL;
	
	return CW_TRUE;
	
 nla_put_failure:
	nlmsg_free(msg);
	return CW_FALSE;
}

int nl80211_set_bss(WTPInterfaceInfo * interfaceInfo, int radioIndex, int cts, int preamble)
/*
			   int slot, int ht_opmode, int ap_isolate,
			   int *basic_rates)
*/			   
{
	struct nl_msg *msg;
	int lenRates, indexRates=0;
	unsigned char * rateChar;
	
	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_SET_BSS, 0);

	if (cts >= 0)
		NLA_PUT_U8(msg, NL80211_ATTR_BSS_CTS_PROT, cts);
	if (preamble >= 0)
		NLA_PUT_U8(msg, NL80211_ATTR_BSS_SHORT_PREAMBLE, preamble);
		/*
	NLA_PUT_U8(msg, NL80211_ATTR_BSS_CTS_PROT, 0);
	NLA_PUT_U8(msg, NL80211_ATTR_BSS_SHORT_PREAMBLE, 0);
	NLA_PUT_U8(msg, NL80211_ATTR_BSS_SHORT_SLOT_TIME, 1);
//	NLA_PUT_U8(msg, NL80211_ATTR_AP_ISOLATE, 0);
*/

	CW_CREATE_ARRAY_CALLOC_ERR(rateChar, gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.lenSupportedRates, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	for(indexRates=0; indexRates < gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.lenSupportedRates; indexRates++)
	{
		rateChar[indexRates] = gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.supportedRates[indexRates];
		CWLog("BSS RATE rate1: %d - rate2: %d", gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.supportedRates[indexRates], rateChar[indexRates]);
	}
	NLA_PUT(msg, NL80211_ATTR_BSS_BASIC_RATES, lenRates, rateChar);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, interfaceInfo->realWlanID);

	int ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, NULL, NULL);
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Set BSS error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}		
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
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] STOP AP error: %d, %s", ret, strerror(-ret));
		return CW_FALSE;
	}
	
	msg = NULL;
	
	CWLog("Interface %s is no more an AP", ifName);


	return CW_TRUE;
	
 nla_put_failure:
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
 
int CW80211SetAPTypeFrame(WTPInterfaceInfo * interfaceInfo, WTPBSSInfo * WTPBSSInfoPtr)
{
	if(interfaceInfo == NULL || WTPBSSInfoPtr == NULL)
		return -1;
		
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
	CWLog("[NL80211 ERROR] Set AP Type Frame error");
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
	if( ret != 0)
	{
		CWLog("[NL80211 ERROR] Register frame command failed (type=%u): ret=%d (%s)", type, ret, strerror(-ret));
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
	
	ret = 0;
	
nla_put_failure:
	nlmsg_free(msg);
	return ret;
}
 
CWBool CW80211SendFrame(WTPBSSInfo * WTPBSSInfoPtr, unsigned int freq, unsigned int wait, char * buf, size_t buf_len, u64 *cookie_out, int no_cck, int no_ack)
{
	struct nl_msg *msg;
	u64 cookie;
	int ret = -1;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;
	
//	CWLog("nl80211: CMD_FRAME freq=%u wait=%u no_cck=%d no_ack=%d", freq, wait, no_cck, no_ack);

	genlmsg_put(msg, 0, 0, WTPBSSInfoPtr->BSSNLSock.nl80211_id, 0, 0, NL80211_CMD_FRAME, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, WTPBSSInfoPtr->interfaceInfo->realWlanID);
	
	//Frame da inviare
	NLA_PUT(msg, NL80211_ATTR_FRAME, buf_len, buf);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, gRadiosInfo.radiosInfo[0].gWTPPhyInfo.phyFrequencyInfo.frequencyList[CW_WTP_DEFAULT_RADIO_CHANNEL].frequency);
	NLA_PUT_FLAG(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK);
	
	//L'operazione ritorna un cookie
	cookie = 0;
	
	ret = nl80211_send_recv_cb_input(&(WTPBSSInfoPtr->BSSNLSock), msg, NULL, NULL); //CB_cookieHandler, &cookie);	
	msg = NULL;
	if (ret) {
		CWLog("[NL80211 ERROR]: Frame command failed: ret=%d (%s) (freq=%u wait=%u) nl_geterror: %s", ret, strerror(-ret), freq, wait, nl_geterror(ret));
		goto nla_put_failure;
	}
//	CWLog("nl80211: Frame TX command accepted%s; cookie 0x%llx", no_ack ? " (no ACK)" : "", (long long unsigned int) cookie);

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
		
	return CW_TRUE;
}

/*
	__u8 rtap_hdr[] = {
		0x00, 0x00, // radiotap version
		0x0e, 0x00, // radiotap length
		0x02, 0xc0, 0x00, 0x00, //bmap: flags, tx and rx flags
		IEEE80211_RADIOTAP_F_FRAG, // F_FRAG (fragment if required)
		0x00,       // padding
		0x00, 0x00, // RX and TX flags to indicate that
		0x00, 0x00, // this is the injected frame directly
	};

	__u8 rtap_hdr[] = {
		0x00, 0x00, // radiotap version
		0x0b, 0x00,
		0x04, 0x0c, 0x00, 0x00,
		0x6c, 
		0x0c, 
		0x01
	};

	__u8 rtap_hdr[] = {
			0x00, 0x00, // radiotap version
			0x0d, 0x00,
			0x04, 0x80, 0x02, 0x00,
			0x02,
			0x00, 0x00, 0x00, 0x00
		};

	u8 rtap_hdr[] = {
		0x00, 0x00, // <-- radiotap version
		0x19, 0x00, // <- radiotap header length
		0x6f, 0x08, 0x00, 0x00, // <-- bitmap
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
		0x00, // <-- flags (Offset +0x10)
		0x18, // <-- rate (0ffset +0x11)
		0x7b, 0x09, 0xc0, 0x00, // <-- channel
		0xde, // <-- antsignal
		0x00, // <-- antnoise
		0x01 // <-- antenna
	};
*/


int CWInjectFrameMonitor(int rawSocket, void *data, size_t len, int encrypt, int noack)
{
	unsigned char * bufToSend;
	
	if(len <= 0)
		return -1;
	
	u8 rtap_hdr[] = {
		0x00, 0x00, // <-- radiotap version
		0x0b, 0x00, // <- radiotap header length
		0x04, 0x0c, 0x00, 0x00, // <-- bitmap
		0x24, // <-- rate
		0x1b,//0x0c, //<-- tx power
		0x03 //<-- antenna
	};

	unsigned char * dataChar = (unsigned char *) data;
	
	struct CWFrameDataHdr frameData;
	CW80211ParseDataFrameFromDS(dataChar, &(frameData));

	CW_CREATE_ARRAY_CALLOC_ERR(bufToSend, (sizeof(rtap_hdr)+len), unsigned char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	CW_COPY_MEMORY(bufToSend, rtap_hdr, sizeof(rtap_hdr));	
	CW_COPY_MEMORY(bufToSend+sizeof(rtap_hdr), dataChar, len);
	
	struct iovec iov[1] = {
		{
			.iov_base = bufToSend,
			.iov_len = (sizeof(rtap_hdr)+len), 
		}
	};
	/*
	CWLog("Packet data size: %d", sizeof(rtap_hdr)+len);
	CWLog("Packet rtap_hdr: %d, len: %d\n", sizeof(rtap_hdr), len);
*//*	struct iovec iov[2] = {
		{
			.iov_base = &rtap_hdr,
			.iov_len = sizeof(rtap_hdr),
		},
		{
			.iov_base = (void *) u8aIeeeHeader,
			.iov_len = 24,
		}
	};
	*/
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};
	int res;
	u16 txflags = 0;

	if (rawSocket < 0) {
		CWLog("nl80211: No monitor socket available for %s", __func__);
		return -1;
	}

	//if (noack)
	//	txflags |= IEEE80211_RADIOTAP_F_TX_NOACK;
	//WPA_PUT_LE16(&rtap_hdr[12], txflags);

	/*
	int optval2;
 	int optlen2;
 	
	if (getsockopt(rawInjectSocket, SOL_SOCKET, IP_MTU, &optval2, &optlen2))
	{
		CWLog("nl80211: Failed to get socket MTU: %s", strerror(errno));
	}
	CWLog("****SOCKET MTU: %d", optval2);
	*/
	res = sendmsg(rawSocket, &msg, 0);
	if (res < 0) {
		CWLog("nl80211: sendmsg: %s (errno %d)", strerror(errno), errno);
		return -1;
	}
	//CWLog("Injection result code: %d", res);

	CW_FREE_OBJECT(bufToSend);
	return 0;
}
