/*
 * Elena Agostini - elena.ago@gmail.com
 * 
 * Netlink functions with libnl
 */

#include "CWWTP.h"

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
