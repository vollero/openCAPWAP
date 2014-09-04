/*
 * Elena Agostini - elena.ago@gmail.com
 * 
 * Netlink functions with libnl
 */

#include "CWWTP.h"

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

	err = nl_send_auto_complete(nlSockUnit->nl_sock, msg);
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
