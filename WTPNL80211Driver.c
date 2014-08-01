/*
 * Elena Agostini - elena.ago@gmail.com
 * 
 * libnl interaction with nl80211 API
 */
 
#include "CWWTP.h"

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
/*

int nl80211CmdGetWiphyInfo()
{
	enum nl80211_commands cmd = NL80211_CMD_SET_WIPHY;
	
	//Inizializza netlink
	err = nl80211_init(&nlstate);
	if (err)
		return 1;
	
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 2;
	}


	//Prepara handler del netlink
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		fprintf(stderr, "failed to allocate netlink callbacks\n");
		err = 2;
		return err;
	}
	
	expectedId = nlstate.nl80211_id;
	
	//Setta callback
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, print_iface_handler, NULL);

	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, cmd, 0);

	//Attributo
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifIndex);	
	
	nl_socket_set_cb(nlstate.nl_sock, cb);

	err = nl_send_auto_complete(nlstate.nl_sock, msg);
	if (err < 0)
		return err;
	
	nl_recvmsgs_default(nlstate.nl_sock);
}
*/

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
