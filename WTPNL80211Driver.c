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
	val = 2; // htons(host_to_le16(1));
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
 
int nl80211_mgmt_ap(WTPInterfaceInfo * interfaceInfo)
{
	static const int stypes[] = {
		WLAN_FC_STYPE_AUTH,
		WLAN_FC_STYPE_ASSOC_REQ,
		WLAN_FC_STYPE_REASSOC_REQ,
		WLAN_FC_STYPE_DISASSOC,
		WLAN_FC_STYPE_DEAUTH,
		//WLAN_FC_STYPE_ACTION,
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
	interface_nl80211_init_nl(interfaceInfo);

	if (nl80211_alloc_mgmt_handle(interfaceInfo))
		return -1;
	CWLog("nl80211: Subscribe to mgmt frames with AP handle %p", interfaceInfo->nl_mgmt);

	for (i = 0; i < ARRAY_SIZE(stypes); i++) {
		CWLog("nl80211: Register %d (%d) type", stypes[i], i);
		
			CWLog("WLAN_FC_TYPE_MGMT: %d, type: %d", WLAN_FC_TYPE_MGMT, stypes[i]);


		if (nl80211_register_frame(interfaceInfo, interfaceInfo->nl_mgmt,
					IEEE80211_FC(WLAN_FC_TYPE_MGMT, stypes[i]),
//					   (WLAN_FC_TYPE_MGMT << 2) |
	//				   (stypes[i] << 4),
					   NULL, 0) < 0) {
			goto out_err;
		}
		
	}

	if (nl80211_register_spurious_class3(interfaceInfo))
		goto out_err;
/*
	if (nl80211_get_wiphy_data_ap(interfaceInfo) == NULL)
		goto out_err;
*/
	nl80211_mgmt_handle_register_eloop(interfaceInfo);
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
		return -1;

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

	/*buf[0] = '\0';
	wpa_snprintf_hex(buf, sizeof(buf), match, match_len);
	CWLog("nl80211: Register frame type=0x%x nl_handle=%p match=%s", type, nl_handle, buf);
	*/
	
	CWLog("nl80211: Register frame type=0x%x (%d) nl_handle=%p interface: %d", type, type, nl_handle, interfaceInfo->realWlanID);
	
	genlmsg_put(msg, 0, 0, globalNLSock.nl80211_id, 0, 0, NL80211_CMD_REGISTER_ACTION, 0);
	//Associo la ricezione dei frame management all'interfaccia in questione
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, interfaceInfo->realWlanID);
	NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, type);
	NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, match_len, match);
	
	//Prepara handler del netlink
	globalNLSock.nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!globalNLSock.nl_cb) {
		fprintf(stderr, "failed to allocate netlink callbacks\n");
		int err = 2;
		return err;
	}

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
	eloop_register_read_sock(nl_socket_get_fd(*handle), handler,
				 eloop_data, *handle);
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
	
	union wpa_event_data data;

	exit(1);
/*
	if (drv->ap_scan_as_station != NL80211_IFTYPE_UNSPECIFIED &&
	    (cmd == NL80211_CMD_NEW_SCAN_RESULTS ||
	     cmd == NL80211_CMD_SCAN_ABORTED)) {
		wpa_driver_nl80211_set_mode(drv->first_bss,
					    drv->ap_scan_as_station);
		drv->ap_scan_as_station = NL80211_IFTYPE_UNSPECIFIED;
	}

	switch (cmd) {
	case NL80211_CMD_TRIGGER_SCAN:
		wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: Scan trigger");
		drv->scan_state = SCAN_STARTED;
		if (drv->scan_for_auth) {
			*/
			/*
			 * Cannot indicate EVENT_SCAN_STARTED here since we skip
			 * EVENT_SCAN_RESULTS in scan_for_auth case and the
			 * upper layer implementation could get confused about
			 * scanning state.
			 */
	/*		wpa_printf(MSG_DEBUG, "nl80211: Do not indicate scan-start event due to internal scan_for_auth");
			break;
		}
		wpa_supplicant_event(drv->ctx, EVENT_SCAN_STARTED, NULL);
		break;
	case NL80211_CMD_START_SCHED_SCAN:
		wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: Sched scan started");
		drv->scan_state = SCHED_SCAN_STARTED;
		break;
	case NL80211_CMD_SCHED_SCAN_STOPPED:
		wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: Sched scan stopped");
		drv->scan_state = SCHED_SCAN_STOPPED;
		wpa_supplicant_event(drv->ctx, EVENT_SCHED_SCAN_STOPPED, NULL);
		break;
	case NL80211_CMD_NEW_SCAN_RESULTS:
		wpa_dbg(drv->ctx, MSG_DEBUG,
			"nl80211: New scan results available");
		drv->scan_state = SCAN_COMPLETED;
		drv->scan_complete_events = 1;
		eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv,
				     drv->ctx);
		send_scan_event(drv, 0, tb);
		break;
	case NL80211_CMD_SCHED_SCAN_RESULTS:
		wpa_dbg(drv->ctx, MSG_DEBUG,
			"nl80211: New sched scan results available");
		drv->scan_state = SCHED_SCAN_RESULTS;
		send_scan_event(drv, 0, tb);
		break;
	case NL80211_CMD_SCAN_ABORTED:
		wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: Scan aborted");
		drv->scan_state = SCAN_ABORTED;
		*/
		/*
		 * Need to indicate that scan results are available in order
		 * not to make wpa_supplicant stop its scanning.
		 */
	/*	eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv,
				     drv->ctx);
		send_scan_event(drv, 1, tb);
		break;
	case NL80211_CMD_AUTHENTICATE:
	case NL80211_CMD_ASSOCIATE:
	case NL80211_CMD_DEAUTHENTICATE:
	case NL80211_CMD_DISASSOCIATE:
	case NL80211_CMD_FRAME_TX_STATUS:
	case NL80211_CMD_UNPROT_DEAUTHENTICATE:
	case NL80211_CMD_UNPROT_DISASSOCIATE:
		mlme_event(bss, cmd, tb[NL80211_ATTR_FRAME],
			   tb[NL80211_ATTR_MAC], tb[NL80211_ATTR_TIMED_OUT],
			   tb[NL80211_ATTR_WIPHY_FREQ], tb[NL80211_ATTR_ACK],
			   tb[NL80211_ATTR_COOKIE],
			   tb[NL80211_ATTR_RX_SIGNAL_DBM]);
		break;
	case NL80211_CMD_CONNECT:
	case NL80211_CMD_ROAM:
		mlme_event_connect(drv, cmd,
				   tb[NL80211_ATTR_STATUS_CODE],
				   tb[NL80211_ATTR_MAC],
				   tb[NL80211_ATTR_REQ_IE],
				   tb[NL80211_ATTR_RESP_IE]);
		break;
	case NL80211_CMD_CH_SWITCH_NOTIFY:
		mlme_event_ch_switch(drv,
				     tb[NL80211_ATTR_IFINDEX],
				     tb[NL80211_ATTR_WIPHY_FREQ],
				     tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE],
				     tb[NL80211_ATTR_CHANNEL_WIDTH],
				     tb[NL80211_ATTR_CENTER_FREQ1],
				     tb[NL80211_ATTR_CENTER_FREQ2]);
		break;
	case NL80211_CMD_DISCONNECT:
		mlme_event_disconnect(drv, tb[NL80211_ATTR_REASON_CODE],
				      tb[NL80211_ATTR_MAC],
				      tb[NL80211_ATTR_DISCONNECTED_BY_AP]);
		break;
	case NL80211_CMD_MICHAEL_MIC_FAILURE:
		mlme_event_michael_mic_failure(bss, tb);
		break;
	case NL80211_CMD_JOIN_IBSS:
		mlme_event_join_ibss(drv, tb);
		break;
	case NL80211_CMD_REMAIN_ON_CHANNEL:
		mlme_event_remain_on_channel(drv, 0, tb);
		break;
	case NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL:
		mlme_event_remain_on_channel(drv, 1, tb);
		break;
	case NL80211_CMD_NOTIFY_CQM:
		nl80211_cqm_event(drv, tb);
		break;
	case NL80211_CMD_REG_CHANGE:
		nl80211_reg_change_event(drv, tb);
		break;
	case NL80211_CMD_REG_BEACON_HINT:
		wpa_printf(MSG_DEBUG, "nl80211: Regulatory beacon hint");
		os_memset(&data, 0, sizeof(data));
		data.channel_list_changed.initiator = REGDOM_BEACON_HINT;
		wpa_supplicant_event(drv->ctx, EVENT_CHANNEL_LIST_CHANGED,
				     &data);
		break;
	case NL80211_CMD_NEW_STATION:
		nl80211_new_station_event(drv, tb);
		break;
	case NL80211_CMD_DEL_STATION:
		nl80211_del_station_event(drv, tb);
		break;
	case NL80211_CMD_SET_REKEY_OFFLOAD:
		nl80211_rekey_offload_event(drv, tb);
		break;
	case NL80211_CMD_PMKSA_CANDIDATE:
		nl80211_pmksa_candidate_event(drv, tb);
		break;
	case NL80211_CMD_PROBE_CLIENT:
		nl80211_client_probe_event(drv, tb);
		break;
	case NL80211_CMD_TDLS_OPER:
		nl80211_tdls_oper_event(drv, tb);
		break;
	case NL80211_CMD_CONN_FAILED:
		nl80211_connect_failed_event(drv, tb);
		break;
	case NL80211_CMD_FT_EVENT:
		mlme_event_ft_event(drv, tb);
		break;
	case NL80211_CMD_RADAR_DETECT:
		nl80211_radar_event(drv, tb);
		break;
	case NL80211_CMD_STOP_AP:
		nl80211_stop_ap(drv, tb);
		break;
	case NL80211_CMD_VENDOR:
		nl80211_vendor_event(drv, tb);
		break;
	default:
		wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: Ignored unknown event "
			"(cmd=%d)", cmd);
		break;
	}
	*/
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
