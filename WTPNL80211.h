/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	NL80211 Integration
 * 
 ***************************************/
 
/*#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <endian.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "nl80211.h"
#include "ieee80211.h"
*/
/* ********* DEFINE ********* */
#define ETH_ALEN 6
/*
* 80211.a = 2
* 80211.b = 1
* 80211.g = 4
* 80211.n = 8
*/
		 
#define PHY_NO_STANDARD 0
#define PHY_STANDARD_A 2
#define PHY_STANDARD_B 1
#define PHY_STANDARD_G 4
#define PHY_STANDARD_N 8
#define PHY_ALL_STANDARD 15

//Netlink socket
struct nl80211SocketUnit {
	struct nl_sock *nl_sock;
	int nl80211_id;
};
extern struct nl80211SocketUnit globalNLSock;

typedef struct PhyFrequencyInfoList {
	int frequency;
	int channel;
	int maxTxPower;
} PhyFrequencyInfoList;

typedef struct PhyFrequencyInfo {
	int totChannels;
	PhyFrequencyInfoList * frequencyList;
} PhyFrequencyInfo;

typedef struct WTPSinglePhyInfo {	
	int radioID;
	char * phyName;
	CWBool phyStandard2400MH; //802.11b/g
	CWBool phyStandard5000MH; //802.11a/n
	float * phyMbpsSet;
	CWBool phyHT20;
	CWBool phyHT40;
	//802.11a/b/g/n
	CWBool phyStandardA;
	CWBool phyStandardB;
	CWBool phyStandardG;
	CWBool phyStandardN;
	char phyStandardValue;
	
	//frequencies
	PhyFrequencyInfo phyFrequencyInfo;
	
	int numInterfaces;
} WTPSinglePhyInfo;

typedef struct WTPglobalPhyInfo {
	int numPhyActive;
	WTPSinglePhyInfo * singlePhyInfo;
} WTPglobalPhyInfo;

//Only for configure ac message
typedef struct PhyFrequencyInfoConfigureMessage {
	int radioID;
	int firstChannel;
	int totChannels;
	int maxTxPower;
} PhyFrequencyInfoConfigureMessage;



CWBool nl80211CmdGetPhyInfo(int indexPhy, struct WTPSinglePhyInfo * singlePhyInfo);
CWBool CWWTPGetRadioGlobalInfo(void);

//Define create per allocazione array in CB_getPhyInfo
//la dove dovrei fare due cicli per sapere la quantita di bitrate e di canali
//che dovranno essere salvati
#define WTP_NL80211_BITRATE_NUM 20
#define WTP_NL80211_CHANNELS_NUM 20

int nl80211_init_socket(struct nl80211SocketUnit *nlSockUnit);

/* NL80211DriverCallback.c */
int ack_handler(struct nl_msg *msg, void *arg);
int finish_handler(struct nl_msg *msg, void *arg);
int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);
int CB_getQoSValues(struct nl_msg *msg, void *arg);
int CB_getPhyInfo(struct nl_msg *msg, void * arg);

/* NL80211Driver.c */
int ieee80211_frequency_to_channel(int freq);
int nl80211_send_recv_cb_input(struct nl80211SocketUnit *nlSockUnit,
				struct nl_msg *msg,
				int (*valid_handler)(struct nl_msg *, void *),
				void *valid_data);
