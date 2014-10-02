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
	char headHomeMade[MAC80211_HEADER_FIXED_LEN+MAC80211_BEACON_BODY_MANDATORY_MIN_LEN+2+strlen(interfaceInfo->SSID)+10];
	int offset=0;
	
	//frame control: 2 byte
	short int val = IEEE80211_FC(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_BEACON);
	CWLog("VAL BEACON: %d WLAN_FC_TYPE_MGMT: %d, WLAN_FC_STYPE_BEACON: %d", val, WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_BEACON);
	CW_COPY_MEMORY(&(headHomeMade[offset]), &(val), 2);
	offset += 2;

	//duration: 2 byte
	val = htons(host_to_le16(0));
	CW_COPY_MEMORY(&(headHomeMade[offset]), &(val), 2);
	offset += 2;
	
	//da: 6 byte
	val = htons(0xff);
	CW_COPY_MEMORY(&(headHomeMade[offset]), &(val), ETH_ALEN);
	offset += ETH_ALEN;
	
	//sa: 6 byte. TODO      
	CW_COPY_MEMORY(&(headHomeMade[offset]), interfaceInfo->MACaddr, ETH_ALEN);
	offset += ETH_ALEN;
	
	//bssid: 6 byte
	//mac address phy + wlanId = bssid
	CW_CREATE_ARRAY_CALLOC_ERR(interfaceInfo->BSSID, ETH_ALEN+1, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	CW_COPY_MEMORY(interfaceInfo->MACaddr, interfaceInfo->BSSID, ETH_ALEN);
	interfaceInfo->BSSID[5] += interfaceInfo->realWlanID;
	
	CWLog("BSSID %02x:%02x:%02x:%02x:%02x:%02x\n", 
      (int) interfaceInfo->BSSID[0],
      (int) interfaceInfo->BSSID[1],
      (int) interfaceInfo->BSSID[2],
      (int) interfaceInfo->BSSID[3],
      (int) interfaceInfo->BSSID[4],
      (int) interfaceInfo->BSSID[5]);
      
	CW_COPY_MEMORY(&(headHomeMade[offset]), interfaceInfo->BSSID, ETH_ALEN);
	offset += ETH_ALEN;
	
	//2 (sequence ctl) + 8 (timestamp): vengono impostati in automatico
	offset += 10;
	
	
	//beacon interval: 2 byte
	val = htons(host_to_le16(100));
	CW_COPY_MEMORY(&(headHomeMade[offset]), &(val), 2);
	offset += 2;
	
	//capability: 2 byte
	val = interfaceInfo->capabilityBit;
	CW_COPY_MEMORY(&(headHomeMade[offset]), &(val), 2);
	offset += 2;
	
	//SSID: 6 byte
	val=0;
	CW_COPY_MEMORY(&(headHomeMade[offset]), &(val), 1);
	offset += 1;
	val=strlen(interfaceInfo->SSID);
	CW_COPY_MEMORY(&(headHomeMade[offset]), &(val), 1);
	offset += 1;
	CW_COPY_MEMORY(&(headHomeMade[offset]), interfaceInfo->SSID, strlen(interfaceInfo->SSID));
	offset += strlen(interfaceInfo->SSID);
	
/* *************************************************** */

	NLA_PUT(msg, NL80211_ATTR_BEACON_HEAD, offset, headHomeMade);
	//NLA_PUT(msg, NL80211_ATTR_BEACON_TAIL, NULL, params->tail);	
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifIndex);
	NLA_PUT_U32(msg, NL80211_ATTR_BEACON_INTERVAL, 1);
	NLA_PUT_U32(msg, NL80211_ATTR_DTIM_PERIOD, 1);
	
	NLA_PUT(msg, NL80211_ATTR_SSID, strlen(interfaceInfo->SSID), interfaceInfo->SSID);
	if(interfaceInfo->authType == NL80211_AUTHTYPE_OPEN_SYSTEM)
		NLA_PUT_U32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
	//TODO: else
			
				struct nlmsghdr * nm_nlhTMP = nlmsg_hdr(msg);
	CWLog("flags: %d", nm_nlhTMP->nlmsg_flags);
	CWLog("len: %d", nm_nlhTMP->nlmsg_len);
	CWLog("pid: %d", nm_nlhTMP->nlmsg_pid);
	CWLog("seq: %d", nm_nlhTMP->nlmsg_seq);
	CWLog("type: %d", nm_nlhTMP->nlmsg_type);
	
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

int nl80211_set_bss(WTPInterfaceInfo * interfaceInfo, int cts, int preamble)
/*
			   int slot, int ht_opmode, int ap_isolate,
			   int *basic_rates)
*/			   
{
	CWLog("Dentro nl80211_set_bss");
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

	//SET
	/*
	txq = nla_nest_start(msg, NL80211_ATTR_WIPHY_TXQ_PARAMS);
	if (!txq)
		goto nla_put_failure;

	// We are only sending parameters for a single TXQ at a time
	params = nla_nest_start(msg, 1);
	if (!params)
		goto nla_put_failure;

	switch (queue) {
	case 0:
		NLA_PUT_U8(msg, NL80211_TXQ_ATTR_QUEUE, NL80211_TXQ_Q_VO);
		break;
	case 1:
		NLA_PUT_U8(msg, NL80211_TXQ_ATTR_QUEUE, NL80211_TXQ_Q_VI);
		break;
	case 2:
		NLA_PUT_U8(msg, NL80211_TXQ_ATTR_QUEUE, NL80211_TXQ_Q_BE);
		break;
	case 3:
		NLA_PUT_U8(msg, NL80211_TXQ_ATTR_QUEUE, NL80211_TXQ_Q_BK);
		break;
	}
*/
	/* Burst time is configured in units of 0.1 msec and TXOP parameter in
	 * 32 usec, so need to convert the value here. */
/*	NLA_PUT_U16(msg, NL80211_TXQ_ATTR_TXOP, (burst_time * 100 + 16) / 32);
	NLA_PUT_U16(msg, NL80211_TXQ_ATTR_CWMIN);
	NLA_PUT_U16(msg, NL80211_TXQ_ATTR_CWMAX);
	NLA_PUT_U8(msg, NL80211_TXQ_ATTR_AIFS);

	nla_nest_end(msg, params);

	nla_nest_end(msg, txq);
*/


/************************************
 * AP: Registra ricezione mgmt frame
 ***********************************/
 
int nl80211_mgmt_ap(WTPInterfaceInfo * interfaceInfo, int radioID)
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
	if(interface_nl80211_init_nl(interfaceInfo) == -1)
		return -1;

	interfaceInfo->nl_mgmt = NULL;
	if (nl80211_alloc_mgmt_handle(interfaceInfo) != 0)
		return -1;
	
	CWLog("nl80211: Subscribe to mgmt frames with AP handle %p", interfaceInfo->nl_mgmt);

	for (i = 0; i < ARRAY_SIZE(stypes); i++) {
		CWLog("nl80211: Register %d (%d) type", stypes[i], i);
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
	nl80211_mgmt_handle_register_eloop(interfaceInfo);
	//Prova con select qui
	
	return 0;

out_err:
	nl_destroy_handles(&interfaceInfo->nl_mgmt);
	return -1;
}

/*
int nl80211_get_wiphy_data_ap(WTPInterfaceInfo * interfaceInfo, int radioID)
{	
	gRadiosInfo.radiosInfo[radioID].gWTPPhyInfo.nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!gRadiosInfo.radiosInfo[radioID].gWTPPhyInfo.nl_cb) {
		return -1;
	}
	nl_cb_set(gRadiosInfo.radiosInfo[radioID].gWTPPhyInfo.nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
	nl_cb_set(gRadiosInfo.radiosInfo[radioID].gWTPPhyInfo.nl_cb, NL_CB_VALID, NL_CB_CUSTOM, process_beacon_event, interfaceInfo);

	gRadiosInfo.radiosInfo[radioID].gWTPPhyInfo.nl_beacons = nl_create_handle(bss->drv->global->nl_cb, "wiphy beacons");
	if (gRadiosInfo.radiosInfo[radioID].gWTPPhyInfo.nl_beacons == NULL) {
		os_free(w);
		return NULL;
	}

	if (nl80211_register_beacons(bss->drv, w)) {
		nl_destroy_handles(&w->nl_beacons);
		os_free(w);
		return NULL;
	}

	nl80211_register_eloop_read(&w->nl_beacons, nl80211_recv_beacons, w);

	return 0;
}


int nl80211_register_beacons(int radioID, struct wpa_driver_nl80211_data *drv,
				    struct nl80211_wiphy_data *w)
{
	struct nl_msg *msg;
	int ret = -1;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	nl80211_cmd(drv, msg, 0, NL80211_CMD_REGISTER_BEACONS);

	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, radioID);

	ret = send_and_recv(drv->global, w->nl_beacons, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_DEBUG, "nl80211: Register beacons command "
			   "failed: ret=%d (%s)",
			   ret, strerror(-ret));
		goto nla_put_failure;
	}
	ret = 0;
nla_put_failure:
	nlmsg_free(msg);
	return ret;
}


int process_beacon_event(struct nl_msg *msg, void *arg)
{
	
	CWLog("DENTRO A process_beacon_event");

	struct nl80211_wiphy_data *w = arg;
	struct wpa_driver_nl80211_data *drv;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	union wpa_event_data event;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (gnlh->cmd != NL80211_CMD_FRAME) {
		wpa_printf(MSG_DEBUG, "nl80211: Unexpected beacon event? (%d)",
			   gnlh->cmd);
		return NL_SKIP;
	}

	if (!tb[NL80211_ATTR_FRAME])
		return NL_SKIP;

	dl_list_for_each(drv, &w->drvs, struct wpa_driver_nl80211_data,
			 wiphy_list) {
		os_memset(&event, 0, sizeof(event));
		event.rx_mgmt.frame = nla_data(tb[NL80211_ATTR_FRAME]);
		event.rx_mgmt.frame_len = nla_len(tb[NL80211_ATTR_FRAME]);
		wpa_supplicant_event(drv->ctx, EVENT_RX_MGMT, &event);
	}

	return NL_SKIP;
}
*/

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

void wpa_driver_nl80211_event_receive(int sock, void *eloop_ctx, void *handle)
{
	struct nl_cb *cb = eloop_ctx;
	int res;

	CWLog("nl80211: Event message available");

	res = nl_recvmsgs(handle, cb);
	if (res < 0) {
		CWLog("nl80211: %s->nl_recvmsgs failed: %d",  __func__, res);
	}
}

void do_process_drv_event(WTPInterfaceInfo * interfaceInfo, int cmd, struct nlattr **tb)
{
	CWLog("nl80211: Drv Event %d (%s) received for %s", cmd, nl80211_command_to_string(cmd), interfaceInfo->ifName);
	
	//union wpa_event_data data;
	int frameLen = nla_len(tb[NL80211_ATTR_FRAME]);
	unsigned char frameReceived[frameLen+1];
	
	CW_COPY_MEMORY(frameReceived, nla_data(tb[NL80211_ATTR_FRAME]), frameLen);
	
	const struct ieee80211_mgmt *mgmt;
	u16 fc;
	mgmt = (struct ieee80211_mgmt *) frameReceived;
	fc = le_to_host16(mgmt->frame_control);
	
	
	if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT &&
	    WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_PROBE_REQ)
	CWLog("PROBE!!");
	
	u8 *resp;
	struct ieee802_11_elems elems;
	const u8 *ie;
	size_t ie_len;
	struct sta_info *sta = NULL;
	size_t i, resp_len;
	int noack;

	ie = mgmt->u.probe_req.variable;
	if (frameLen < IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req))
		return;
	ie_len = frameLen - (IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req));
	
	
	if (ieee802_11_parse_elems(ie, ie_len, &elems, 0) == ParseFailed) {
		CWLog("Could not parse ProbeReq from " MACSTR,  MAC2STR(mgmt->sa));
		return;
	}

	if ((!elems.ssid || !elems.supp_rates)) {
		CWLog("STA " MACSTR " sent probe request "
			   "without SSID or supported rates element",
			   MAC2STR(mgmt->sa));
		return;
	}
	
	 CWLog("Ethernet fuori %02x:%02x:%02x:%02x:%02x:%02x\n", 
      (int) interfaceInfo->MACaddr[0],
      (int) interfaceInfo->MACaddr[1],
      (int) interfaceInfo->MACaddr[2],
      (int) interfaceInfo->MACaddr[3],
      (int) interfaceInfo->MACaddr[4],
      (int) interfaceInfo->MACaddr[5]);
      
	/* +++ PROBE RESPONSE +++ */
	char * probeResponse = NULL;
	u64 cookie_out;
	int frameRespLen=0;
	probeResponse = nl80211ProbeResponseCreate(interfaceInfo, mgmt, &frameRespLen);
	
	CWLog("frameRespLen: %d interfaceInfo->realWlanID: %d", frameRespLen, interfaceInfo->realWlanID);
	int j;
	for(j=0; j<frameRespLen; j++)
	{
		if(probeResponse[j] == '\0')
			CWLog("j[%d]: 000000", j);
		else
			CWLog("j[%d]: %c, %d", j, probeResponse[j], probeResponse[j]);
	}
	
	if(probeResponse)
		if(!nl80211_send_frame_cmd(interfaceInfo, 0,CW_FALSE, probeResponse, frameRespLen, &(cookie_out), 1,1))
			CWLog("NL80211: Errore nl80211_send_frame_cmd");
}

int nl80211_send_frame_cmd(WTPInterfaceInfo * interfaceInfo,
			unsigned int freq, 
			unsigned int wait,
			char * buf, size_t buf_len,
			u64 *cookie_out,
			int no_cck, int no_ack)
{
	struct nl_msg *msg;
	u64 cookie;
	int ret = -1;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;
	
	CWLog("nl80211: CMD_FRAME freq=%u wait=%u no_cck=%d no_ack=%d", freq, wait, no_cck, no_ack);

	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_FRAME, 0);
//	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, interfaceInfo->realWlanID);
	
	CWLog("Frame len: %d wlanid: %d", buf_len, interfaceInfo->realWlanID);
	//Frame da inviare
	NLA_PUT(msg, NL80211_ATTR_FRAME, buf_len+1, buf);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, gRadiosInfo.radiosInfo[0].gWTPPhyInfo.phyFrequencyInfo.frequencyList[CW_WTP_DEFAULT_RADIO_CHANNEL].frequency);
	
	/*
	NLA_PUT_FLAG(msg, NL80211_ATTR_TX_NO_CCK_RATE);
	//int channel = 2417;
	//NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, channel);
	
	NLA_PUT_FLAG(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK);
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
	
	struct nlmsghdr * nm_nlhTMP = nlmsg_hdr(msg);
	CWLog("flags: %d", nm_nlhTMP->nlmsg_flags);
	CWLog("len: %d", nm_nlhTMP->nlmsg_len);
	CWLog("pid: %d", nm_nlhTMP->nlmsg_pid);
	CWLog("seq: %d", nm_nlhTMP->nlmsg_seq);
	CWLog("type: %d", nm_nlhTMP->nlmsg_type);
	
	ret = nl80211_send_recv_cb_input(&(globalNLSock), msg, CB_cookieHandler, &cookie);
//	ret = send_and_recv(drv, msg, CB_cookieHandler, &cookie);
	
	msg = NULL;
	if (ret) {
		
		CWLog("nl80211: Frame command failed: ret=%d (%s) (freq=%u wait=%u) nl_geterror: %s", ret, strerror(-ret), freq, wait, nl_geterror(ret));
		goto nla_put_failure;
	}
	CWLog("nl80211: Frame TX command accepted%s; cookie 0x%llx", no_ack ? " (no ACK)" : "", (long long unsigned int) cookie);

	if (cookie_out)
		*cookie_out = no_ack ? (u64) -1 : cookie;

nla_put_failure:
	nlmsg_free(msg);
	return ret;
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
		/*case WLAN_EID_VENDOR_SPECIFIC:
			if (ieee802_11_parse_vendor_specific(pos, elen,
							     elems,
							     show_errors))
				unknown++;
			break;
		*/
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

//Genera probe response
char * nl80211ProbeResponseCreate(WTPInterfaceInfo * interfaceInfo, struct ieee80211_mgmt *probeRequest, int *offset)
{
	CWLog("Probe response per ifname: %s", interfaceInfo->ifName);
	(*offset)=0;
	/* ***************** PROBE RESPONSE FRAME: DO IT BETTER ******************** */
	char * frameProbeResponse;
	CW_CREATE_ARRAY_CALLOC_ERR(frameProbeResponse, 22+strlen(interfaceInfo->SSID)+3+2+1+2+3, char, {CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL); return NULL;});
	
	//frame control: 2 byte
	short int val = IEEE80211_FC(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_PROBE_RESP);
	CWLog("VAL PROBE REPONSE: %d WLAN_FC_TYPE_MGMT: %d, WLAN_FC_STYPE_PROBE_RESP: %d", val, WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_PROBE_RESP);
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), &(val), 2);
	(*offset) += 2;
	
	
	//duration: 2 byte
	val = htons(host_to_le16(0));
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), &(val), 2);
	(*offset) += 2;
	
	//da: 6 byte
	//val = htons(probeRequest->da);
	val = htons(0xff);
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), &(val), ETH_ALEN);
	(*offset) += ETH_ALEN;
	
	//sa: 6 byte.
	 CWLog("Ethernet %02x:%02x:%02x:%02x:%02x:%02x\n", 
      (int) interfaceInfo->MACaddr[0],
      (int) interfaceInfo->MACaddr[1],
      (int) interfaceInfo->MACaddr[2],
      (int) interfaceInfo->MACaddr[3],
      (int) interfaceInfo->MACaddr[4],
      (int) interfaceInfo->MACaddr[5]);
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), interfaceInfo->MACaddr, ETH_ALEN);
	(*offset) += ETH_ALEN;
	
	//bssid: 6 byte
	CWLog("BSSID %02x:%02x:%02x:%02x:%02x:%02x\n", 
      (int) interfaceInfo->BSSID[0],
      (int) interfaceInfo->BSSID[1],
      (int) interfaceInfo->BSSID[2],
      (int) interfaceInfo->BSSID[3],
      (int) interfaceInfo->BSSID[4],
      (int) interfaceInfo->BSSID[5]);
      
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), interfaceInfo->BSSID, ETH_ALEN);
	(*offset) += ETH_ALEN;
	
	(*offset) += 2;
	//2 (sequence ctl) + 8 (timestamp): vengono impostati in automatico
//	(*offset) += 10;
	
	
	//beacon interval: 2 byte
	/*val = 2; // htons(host_to_le16(1));
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), &(val), 2);
	(*offset) += 2;
	
	
	//capability: 2 byte
	val = interfaceInfo->capabilityBit;
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), &(val), 2);
	(*offset) += 2;
	*/
	
	//SSID: 6 byte
	val=0;
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), &(val), 1);
	(*offset) += 1;
	val=strlen(interfaceInfo->SSID);
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), &(val), 1);
	(*offset) += 1;
	CWLog("SSID: %s, %d", interfaceInfo->SSID, strlen(interfaceInfo->SSID));
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), interfaceInfo->SSID, strlen(interfaceInfo->SSID));
	(*offset) += strlen(interfaceInfo->SSID);
	
	/* *************************************************** */

	//Supported Rates: 2 byte hdr + 1 rate (numero variabile, dopo modifichi)
	val=1;
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), &(val), 1);
	(*offset) += 1;
	val=4;
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), &(val), 1);
	(*offset) += 1;
	char suppRate = 64; //2 << 6;
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), &(suppRate), 1);
	(*offset) += 1;
	
	val=3;
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), &(val), 1);
	(*offset) += 1;
	val=1;
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), &(val), 1);
	(*offset) += 1;
	unsigned char channel = CW_WTP_DEFAULT_RADIO_CHANNEL+1;
	CW_COPY_MEMORY(&(frameProbeResponse[(*offset)]), &(channel), 1);
	(*offset) += 1;
	
	/* Supported rates */
	//pos = hostapd_eid_supp_rates(hapd, pos);

	/* DS Params */
	//pos = hostapd_eid_ds_params(hapd, pos);

	//pos = hostapd_eid_country(hapd, pos, epos - pos);

	/* Power Constraint element */
	//pos = hostapd_eid_pwr_constraint(hapd, pos);

	/* ERP Information element */
	//pos = hostapd_eid_erp_info(hapd, pos);

	/* Extended supported rates */
	//pos = hostapd_eid_ext_supp_rates(hapd, pos);

	/* RSN, MDIE, WPA */
	/*pos = hostapd_eid_wpa(hapd, pos, epos - pos);

	pos = hostapd_eid_bss_load(hapd, pos, epos - pos);

//CONFIG_IEEE80211N

#ifdef CONFIG_IEEE80211N
	pos = hostapd_eid_ht_capabilities(hapd, pos);
	pos = hostapd_eid_ht_operation(hapd, pos);
#endif 

	pos = hostapd_eid_ext_capab(hapd, pos);

	pos = hostapd_eid_time_adv(hapd, pos);
	pos = hostapd_eid_time_zone(hapd, pos);

	pos = hostapd_eid_interworking(hapd, pos);
	pos = hostapd_eid_adv_proto(hapd, pos);
	pos = hostapd_eid_roaming_consortium(hapd, pos);

	pos = hostapd_add_csa_elems(hapd, pos, (u8 *)resp,
				    &hapd->iface->cs_c_off_proberesp);
//CONFIG_IEEE80211AC
#ifdef CONFIG_IEEE80211AC
	pos = hostapd_eid_vht_capabilities(hapd, pos);
	pos = hostapd_eid_vht_operation(hapd, pos);
#endif
	//Wi-Fi Alliance WMM
	pos = hostapd_eid_wmm(hapd, pos);

	if (hapd->conf->vendor_elements) {
		os_memcpy(pos, wpabuf_head(hapd->conf->vendor_elements),
			  wpabuf_len(hapd->conf->vendor_elements));
		pos += wpabuf_len(hapd->conf->vendor_elements);
	}
*/
	return frameProbeResponse;
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
