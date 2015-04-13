/*
 * Elena Agostini - elena.ago@gmail.com
 * 
 * Netlink functions with libnl
 */

#include "CWWTP.h"

static uint32_t port_bitmap[32] = { 0 };

/* ************* NETLINK LIBNL *************** */
int nl80211_init_socket(struct nl80211SocketUnit *nlSockUnit)
{
	int err;

	nlSockUnit->nl_sock = nl_socket_alloc();
	if (!nlSockUnit->nl_sock) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	nl_socket_set_buffer_size(nlSockUnit->nl_sock, 8192, 8192);

	if (genl_connect(nlSockUnit->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	nlSockUnit->nl80211_id = genl_ctrl_resolve(nlSockUnit->nl_sock, "nl80211");
	if (nlSockUnit->nl80211_id < 0) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_handle_destroy;
	}
	
	nlSockUnit->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!nlSockUnit->nl_cb)
		return -1;
/*
	nl_cb_set(nlSockUnit->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
	nl_cb_set(nlSockUnit->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, process_bss_event, bss);
	*/	  
	return 0;

 out_handle_destroy:
	nl_socket_free(nlSockUnit->nl_sock);
	return err;
}

//Chiude netlink libnl
void nl80211_cleanup_socket(struct nl80211SocketUnit *nlSockUnit)
{
	nl_socket_free(nlSockUnit->nl_sock);
}

//Crea handler
struct nl_handle * nl_create_handle(struct nl_cb *cb, const char *dbg)
{
	struct nl_handle *handle;

	handle = nl80211_handle_alloc(cb);
	if (handle == NULL) {
		CWLog("nl80211: Failed to allocate netlink callbacks (%s)", dbg);
		return NULL;
	}

	if (genl_connect(handle)) {
		CWLog("nl80211: Failed to connect to generic netlink (%s)", dbg);
		nl80211_handle_destroy(handle);
		return NULL;
	}

	return handle;
}

/*
struct nl_handle *nl80211_handle_alloc(void *cb)
{
	struct nl_handle *handle;
	uint32_t pid = getpid() & 0x3FFFFF;
	int i;

	handle = nl_handle_alloc_cb(cb);

	for (i = 0; i < 1024; i++) {
		if (port_bitmap[i / 32] & (1 << (i % 32)))
			continue;
		port_bitmap[i / 32] |= 1 << (i % 32);
		pid += i << 22;
		break;
	}

	nl_socket_set_local_port(handle, pid);

	return handle;
}

void nl80211_handle_destroy(struct nl_handle *handle)
{
	uint32_t port = nl_socket_get_local_port(handle);

	port >>= 22;
	port_bitmap[port / 32] &= ~(1 << (port % 32));

	nl_handle_destroy(handle);
}
* */

void nl_destroy_handles(struct nl_handle **handle)
{
	if (*handle == NULL)
		return;
	nl80211_handle_destroy(*handle);
	*handle = NULL;
}


int no_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}


//Alloca nuova callback
int CW80211InitNlCb(WTPBSSInfo * WTPBSSInfoPtr) //WTPInterfaceInfo * interfaceInfo)
{
	WTPBSSInfoPtr->interfaceInfo->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!WTPBSSInfoPtr->interfaceInfo->nl_cb) {
		CWLog("nl80211: Failed to alloc cb struct");
		return -1;
	}

	if(nl_cb_set(WTPBSSInfoPtr->interfaceInfo->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL) != 0)
	{
		CWLog("nl80211: Errore nl_cb_set no_seq_check");
		return -1;
	}
	
	if(nl_cb_set(WTPBSSInfoPtr->interfaceInfo->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, CW80211CheckTypeEvent, WTPBSSInfoPtr) != 0)
	{
		CWLog("nl80211: Errore nl_cb_set CW80211CheckTypeEvent");
		return -1;
	}

	return 0;
}

int CW80211CheckTypeEvent(struct nl_msg *msg, void *arg)
{
	WTPBSSInfo * WTPBSSInfoPtr = arg;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	char * frameBuffer = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	int ifidx = -1;
	
	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_IFINDEX]) {
		ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);

		if (ifidx == -1 || ifidx == WTPBSSInfoPtr->interfaceInfo->realWlanID) {
				CW80211EventProcess(WTPBSSInfoPtr, gnlh->cmd, tb, frameBuffer);
				return NL_SKIP;
		}
		CWLog("nl80211: Ignored event (cmd=%d) for foreign interface (ifindex %d)", gnlh->cmd, ifidx);
		
	} else if (tb[NL80211_ATTR_WDEV]) {
		u64 wdev_id = nla_get_u64(tb[NL80211_ATTR_WDEV]);
		CWLog("nl80211: Process event on P2P device");
		/*for (bss = drv->first_bss; bss; bss = bss->next) {
			if (bss->wdev_id_set && wdev_id == bss->wdev_id) {
				CW80211EventProcess(bss, gnlh->cmd, tb);
				return NL_SKIP;
			}
		}
		*/
		CWLog("nl80211: Ignored event (cmd=%d) for foreign interface (wdev 0x%llx)", gnlh->cmd, (long long unsigned int) wdev_id);
		
	}

	return NL_SKIP;
}


//Alloca nuovo messaggio
struct nl_msg * nl80211_message_alloc()
{
	struct nl_msg *msg;
	
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return NULL;
	}
	
	return msg;
}

int nl80211_send_recv_cb_input(struct nl80211SocketUnit *nlSockUnit,
				struct nl_msg *msg,
				int (*valid_handler)(struct nl_msg *, void *),
				void *valid_data)
{
	struct nl_cb *cb;
	int err = -ENOMEM;
	
	//Prepara handler del netlink
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		fprintf(stderr, "failed to allocate netlink callbacks\n");
		err = 2;
		return err;
	}
	
	err = nl_send_auto(nlSockUnit->nl_sock, msg);
	if (err < 0)
		goto out;

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	if (valid_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, valid_data);

	while (err > 0) {
		int res = nl_recvmsgs(nlSockUnit->nl_sock, cb);
		if (res < 0) {
			CWLog("nl80211: %s->nl_recvmsgs failed: %d", __func__, res);
		}
	}
	
 out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	return err;
}

int send_and_recv(struct nl80211SocketUnit *global,
			 struct nl_handle *nl_handle, struct nl_msg *msg,
			 int (*valid_handler)(struct nl_msg *, void *),
			 void *valid_data)
{
	struct nl_cb *cb;
	int err = -ENOMEM;

	cb = nl_cb_clone(global->nl_cb);
	if (!cb)
		goto out;
	
	err = nl_send_auto(nl_handle, msg);
	//err = nl_send_auto_complete(nl_handle, msg);
	if (err < 0)
		goto out;

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	if (valid_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
			  valid_handler, valid_data);

	while (err > 0) {
		int res = nl_recvmsgs(nl_handle, cb);
		if (res < 0) {
			CWLog("nl80211: %s->nl_recvmsgs failed: %d",  __func__, res);
		}
	}
 out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	return err;
}



/* ************* NETLINK SOCKET *************** */
int netlink_create_socket(struct nl80211SocketUnit *nlSockUnit)
{
	struct sockaddr_nl local;
	nlSockUnit->sockNetlink = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nlSockUnit->sockNetlink < 0) {
		CWLog("netlink: Failed to open netlink socket: %s", strerror(errno));
	//	netlink_deinit(netlink);
		return -1;
	}

	os_memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;
	if (bind(nlSockUnit->sockNetlink, (struct sockaddr *) &local, sizeof(local)) < 0)
	{
		CWLog("netlink: Failed to bind netlink socket: %s", strerror(errno));
		//	netlink_deinit(netlink);
		return -1;
	}
	
	return 0;
}

CWBool netlink_send_oper_ifla(int sock, int ifindex, int linkmode, int operstate)
{
	struct {
		struct nlmsghdr hdr;
		struct ifinfomsg ifinfo;
		char opts[16];
	} req;
	struct rtattr *rta;
	static int nl_seq;
	ssize_t ret;

	os_memset(&req, 0, sizeof(req));

	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.hdr.nlmsg_type = RTM_SETLINK;
	req.hdr.nlmsg_flags = NLM_F_REQUEST;
	req.hdr.nlmsg_seq = ++nl_seq;
	req.hdr.nlmsg_pid = 0;

	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_type = 0;
	req.ifinfo.ifi_index = ifindex;
	req.ifinfo.ifi_flags = 0;
	req.ifinfo.ifi_change = 0;

	if (linkmode != -1) {
		rta = aliasing_hide_typecast(
			((char *) &req + NLMSG_ALIGN(req.hdr.nlmsg_len)),
			struct rtattr);
		rta->rta_type = IFLA_LINKMODE;
		rta->rta_len = RTA_LENGTH(sizeof(char));
		*((char *) RTA_DATA(rta)) = linkmode;
		req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) +
			RTA_LENGTH(sizeof(char));
	}
	if (operstate != -1) {
		rta = aliasing_hide_typecast(
			((char *) &req + NLMSG_ALIGN(req.hdr.nlmsg_len)),
			struct rtattr);
		rta->rta_type = IFLA_OPERSTATE;
		rta->rta_len = RTA_LENGTH(sizeof(char));
		*((char *) RTA_DATA(rta)) = operstate;
		req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) +
			RTA_LENGTH(sizeof(char));
	}

	ret = send(sock, &req, req.hdr.nlmsg_len, 0);
	if (ret < 0) {
		CWLog("netlink: Sending operstate IFLA failed: %s (assume operstate is not supported)", strerror(errno));
	}
	
	CWLog("netlink: Operstate: ifindex=%d linkmode=%d, operstate=%d", ifindex, linkmode, operstate);
		   
	return ret < 0 ? CW_FALSE : CW_TRUE;
}

#ifndef SIOCBRADDBR
#define SIOCBRADDBR 0x89a0
#endif
#ifndef SIOCBRDELBR
#define SIOCBRDELBR 0x89a1
#endif
#ifndef SIOCBRADDIF
#define SIOCBRADDIF 0x89a2
#endif
#ifndef SIOCBRDELIF
#define SIOCBRDELIF 0x89a3
#endif

CWBool CWSetNewBridge(int sock, char * bridgeName) {
	//Set up bridge
	if (ioctl(sock, SIOCBRADDBR, bridgeName) < 0) {
		CWLog("Could not add bridge %s: %s", bridgeName, strerror(errno));
		//return CW_FALSE;
	}
	return CW_TRUE;
}

CWBool CWAddNewBridgeInterface(int sock, char * bridgeName, int wlanID) {
	struct ifreq ifr;
	
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, bridgeName, IFNAMSIZ);
	ifr.ifr_ifindex = wlanID;
	CWLog("Aggiungo a %s ifface %d", bridgeName, wlanID);
	if (ioctl(sock, SIOCBRADDIF, &ifr) < 0) {
		CWLog("Could not add interface %d into bridge %s: %s", wlanID, bridgeName, strerror(errno));
		return CW_FALSE;
	}
	
	return CW_TRUE;
}

CWBool CWDelBridge(int sock, char * bridgeName) {
	
	if (ioctl(sock, SIOCBRDELBR, bridgeName) < 0) {
		CWLog("Could not remove bridge %s: %s", bridgeName, strerror(errno));
		return CW_FALSE;
	}

	return CW_TRUE;
}

CWBool CWDelBridgeInterface(int sock, char * bridgeName, int wlanID) {
	struct ifreq ifr;

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, bridgeName, IFNAMSIZ);
	ifr.ifr_ifindex = wlanID;
	if (ioctl(sock, SIOCBRDELIF, &ifr) < 0) {
		CWLog("Could not remove interface %d from bridge %s: %s", wlanID, bridgeName, strerror(errno));
		return CW_FALSE;
	}

	return CW_TRUE;
}


int CWGetBridge(char *brname, const char *ifname)
{
	char path[128], brlink[128], *pos;
	ssize_t res;

	os_snprintf(path, sizeof(path), "/sys/class/net/%s/brport/bridge", ifname);
	res = readlink(path, brlink, sizeof(brlink));
	if (res < 0 || (size_t) res >= sizeof(brlink))
		return CW_FALSE;
	brlink[res] = '\0';
	pos = os_strrchr(brlink, '/');
	if (pos == NULL)
		return CW_FALSE;
	pos++;
	os_strlcpy(brname, pos, IFNAMSIZ);
	return CW_TRUE;
}
