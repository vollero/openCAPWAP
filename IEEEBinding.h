/*******************************************************************************************
 * Copyright (c) 2006-7 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
 *                      Universita' Campus BioMedico - Italy                               *
 *                                                                                         *
 * This program is free software; you can redistribute it and/or modify it under the terms *
 * of the GNU General Public License as published by the Free Software Foundation; either  *
 * version 2 of the License, or (at your option) any later version.                        *
 *                                                                                         *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY         *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 	       *
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.                *
 *                                                                                         *
 * You should have received a copy of the GNU General Public License along with this       *
 * program; if not, write to the:                                                          *
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,                    *
 * MA  02111-1307, USA.                                                                    *
 *                                                                                         *
 * --------------------------------------------------------------------------------------- *
 * Project:  OpenCapwap - NL80211 Integration                                              *
 *                                                                                         *
 * Author :  Elena Agostini elena.ago@gmail.com		                                       *  
 *                                                                                         *
 *******************************************************************************************/
 
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

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP   0x10000         /* driver signals L1 up         */
#endif
#ifndef IFF_DORMANT
#define IFF_DORMANT    0x20000         /* driver signals dormant       */
#endif

#ifndef IF_OPER_DORMANT
#define IF_OPER_DORMANT 5
#endif
#ifndef IF_OPER_UP
#define IF_OPER_UP 6
#endif

//Netlink socket
struct nl80211SocketUnit {
	struct nl_sock *nl_sock;
	int nl80211_id;
	
	int sockNetlink;
};
extern struct nl80211SocketUnit globalNLSock;

//Max num WTP radio interface
#define WTP_RADIO_MAX 5
//Max num WTP interface for each radio
#define WTP_MAX_INTERFACES 3

#define WLAN_CAPABILITY_NUM_FIELDS 16
#define WLAN_KEY_LEN 4
#define WLAN_GROUP_TSC_LEN 6
#define CW_MSG_IEEE_ADD_WLAN_MIN_LEN 23
#define CW_MSG_IEEE_UPDATE_WLAN_MIN_LEN 23

#define MAC80211_HEADER_FIXED_LEN 24
#define MAC80211_BEACON_BODY_MANDATORY_MIN_LEN 12

#define WTP_NAME_WLAN_PREFIX "WTPWLan"
#define WTP_NAME_WLAN_PREFIX_LEN 7
#define WTP_NAME_WLAN_SUFFIX_LEN 2

enum {
	CW_OP_ADD_WLAN,
	CW_OP_DEL_WLAN,
	CW_OP_UPDATE_WLAN
} wlanOperationType;

enum {
	CW_STA_MODE,
	CW_AP_MODE
} wlanModeType;

typedef struct ACInterfaceRequestInfo {
	int radioID;
	//ID assigned by AC
	int wlanID;
		
	int operation;
	
	char * ifName;
	
	//Info Interface
	char capability[WLAN_CAPABILITY_NUM_FIELDS];
	unsigned short int capabilityBit;
	
	//key info not used
	char keyIndex;
	char keyStatus;
	short unsigned int keyLength;
	char key[WLAN_KEY_LEN];
	char groupTSC[WLAN_GROUP_TSC_LEN];
	
	char qos;
	char authType;
	char MACmode;
	char tunnelMode;
	char suppressSSID;
	char * SSID;

} ACInterfaceRequestInfo;

typedef struct WTPInterfaceInfo {
	//ID assigned by AC
	int wlanID;
	//Real ID assigned by mac80211
	int realWlanID;
	
	//AC or STA
	int typeInterface;
	
	char * ifName;
	
	//Info Interface
	char capability[WLAN_CAPABILITY_NUM_FIELDS];
	unsigned short int capabilityBit;
	
	//key info not used
	char keyIndex;
	char keyStatus;
	short unsigned int keyLength;
	char key[WLAN_KEY_LEN];
	char groupTSC[WLAN_GROUP_TSC_LEN];
	
	char qos;
	char authType;
	char MACmode;
	char tunnelMode;
	char suppressSSID;
	char * SSID;
	char * MACaddr;
	char * BSSID;

} WTPInterfaceInfo;

#define CW_WTP_DEFAULT_RADIO_CHANNEL 1

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
	
	int fragmentationTreshold;
	int rtsThreshold;
	char shortRetry;
	char longRetry;
	int txMSDU;
	int rxMSDU;
	
	int numInterfaces;
	WTPInterfaceInfo interfaces[WTP_MAX_INTERFACES];
	
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

typedef struct ACWTPSinglePhyInfo {	
	int radioID;
	char * phyName;
	CWBool phyStandard2400MH; //802.11b/g
	CWBool phyStandard5000MH; //802.11a/n
	float * phyMbpsSet;
	CWBool phyHT20;
	CWBool phyHT40;
	CWBool phyStandardA;
	CWBool phyStandardB;
	CWBool phyStandardG;
	CWBool phyStandardN;
	char phyStandardValue;
	
	int numInterfaces;
} ACWTPSinglePhyInfo;

typedef struct ACWTPglobalPhyInfo {
	int numPhyActive;
	ACWTPSinglePhyInfo * singlePhyInfo;
} ACWTPglobalPhyInfo;

typedef struct wpa_driver_ap_params {
	/**
	 * head - Beacon head from IEEE 802.11 header to IEs before TIM IE
	 */
	u8 *head;

	/**
	 * head_len - Length of the head buffer in octets
	 */
	size_t head_len;

	/**
	 * tail - Beacon tail following TIM IE
	 */
	u8 *tail;

	/**
	 * tail_len - Length of the tail buffer in octets
	 */
	size_t tail_len;

	/**
	 * dtim_period - DTIM period
	 */
	int dtim_period;

	/**
	 * beacon_int - Beacon interval
	 */
	int beacon_int;

	/**
	 * basic_rates: -1 terminated array of basic rates in 100 kbps
	 *
	 * This parameter can be used to set a specific basic rate set for the
	 * BSS. If %NULL, default basic rate set is used.
	 */
	int *basic_rates;

	/**
	 * proberesp - Probe Response template
	 *
	 * This is used by drivers that reply to Probe Requests internally in
	 * AP mode and require the full Probe Response template.
	 */
	u8 *proberesp;

	/**
	 * proberesp_len - Length of the proberesp buffer in octets
	 */
	size_t proberesp_len;

	/**
	 * ssid - The SSID to use in Beacon/Probe Response frames
	 */
	const u8 *ssid;

	/**
	 * ssid_len - Length of the SSID (1..32)
	 */
	size_t ssid_len;

	/**
	 * hide_ssid - Whether to hide the SSID
	 */
	//enum hide_ssid hide_ssid;

	/**
	 * pairwise_ciphers - WPA_CIPHER_* bitfield
	 */
	unsigned int pairwise_ciphers;

	/**
	 * group_cipher - WPA_CIPHER_*
	 */
	unsigned int group_cipher;

	/**
	 * key_mgmt_suites - WPA_KEY_MGMT_* bitfield
	 */
	unsigned int key_mgmt_suites;

	/**
	 * auth_algs - WPA_AUTH_ALG_* bitfield
	 */
	unsigned int auth_algs;

	/**
	 * wpa_version - WPA_PROTO_* bitfield
	 */
	unsigned int wpa_version;

	/**
	 * privacy - Whether privacy is used in the BSS
	 */
	int privacy;

	/**
	 * beacon_ies - WPS/P2P IE(s) for Beacon frames
	 *
	 * This is used to add IEs like WPS IE and P2P IE by drivers that do
	 * not use the full Beacon template.
	 */
	const struct wpabuf *beacon_ies;

	/**
	 * proberesp_ies - P2P/WPS IE(s) for Probe Response frames
	 *
	 * This is used to add IEs like WPS IE and P2P IE by drivers that
	 * reply to Probe Request frames internally.
	 */
	const struct wpabuf *proberesp_ies;

	/**
	 * assocresp_ies - WPS IE(s) for (Re)Association Response frames
	 *
	 * This is used to add IEs like WPS IE by drivers that reply to
	 * (Re)Association Request frames internally.
	 */
	const struct wpabuf *assocresp_ies;

	/**
	 * isolate - Whether to isolate frames between associated stations
	 *
	 * If this is non-zero, the AP is requested to disable forwarding of
	 * frames between associated stations.
	 */
	int isolate;

	/**
	 * cts_protect - Whether CTS protection is enabled
	 */
	int cts_protect;

	/**
	 * preamble - Whether short preamble is enabled
	 */
	int preamble;

	/**
	 * short_slot_time - Whether short slot time is enabled
	 *
	 * 0 = short slot time disable, 1 = short slot time enabled, -1 = do
	 * not set (e.g., when 802.11g mode is not in use)
	 */
	int short_slot_time;

	/**
	 * ht_opmode - HT operation mode or -1 if HT not in use
	 */
	int ht_opmode;

	/**
	 * interworking - Whether Interworking is enabled
	 */
	int interworking;

	/**
	 * hessid - Homogeneous ESS identifier or %NULL if not set
	 */
	const u8 *hessid;

	/**
	 * access_network_type - Access Network Type (0..15)
	 *
	 * This is used for filtering Probe Request frames when Interworking is
	 * enabled.
	 */
	u8 access_network_type;

	/**
	 * ap_max_inactivity - Timeout in seconds to detect STA's inactivity
	 *
	 * This is used by driver which advertises this capability.
	 */
	int ap_max_inactivity;

	/**
	 * disable_dgaf - Whether group-addressed frames are disabled
	 */
	int disable_dgaf;

	/**
	 * osen - Whether OSEN security is enabled
	 */
	int osen;

	/**
	 * freq - Channel parameters for dynamic bandwidth changes
	 */
//	struct hostapd_freq_params *freq;
}wpa_driver_ap_params;

/* WUM IEEE 802.11 */
typedef struct WUMWLANCmdParameters {
	int typeCmd;
	int radioID;
	int wlanID;
	char * ssid;
} WUMWLANCmdParameters;

CWBool nl80211CmdGetPhyInfo(int indexPhy, struct WTPSinglePhyInfo * singlePhyInfo);
CWBool nl80211CmdSetNewInterface(int indexPhy, WTPInterfaceInfo * interfaceInfo);
CWBool nl80211CmdDelInterface(int indexPhy, char * ifName);
CWBool nl80211CmdSetInterfaceAPType(char * interface);
CWBool nl80211CmdSetInterfaceSTAType(char * interface);
CWBool nl80211CmdSetChannelInterface(char * interface, int channel);
CWBool nl80211CmdStartAP(WTPInterfaceInfo * interfaceInfo);
CWBool nl80211CmdStopAP(char * ifName);

CWBool ioctlActivateInterface(char * interface);

//WTPRadio.c
CWBool CWWTPGetRadioGlobalInfo(void);
CWBool CWWTPCreateNewWlanInterface(int radioID, int wlanID);
CWBool CWWTPSetAPInterface(int radioID, WTPInterfaceInfo * interfaceInfo);
CWBool CWWTPDeleteWLANAPInterface(int radioID, int wlanID);

//Define create per allocazione array in CB_getPhyInfo
//la dove dovrei fare due cicli per sapere la quantita di bitrate e di canali
//che dovranno essere salvati
#define WTP_NL80211_BITRATE_NUM 50
#define WTP_NL80211_CHANNELS_NUM 50
#define WTP_NL80211_DEFAULT_MSDU 512

int nl80211_init_socket(struct nl80211SocketUnit *nlSockUnit);
int netlink_create_socket(struct nl80211SocketUnit *nlSockUnit);
CWBool netlink_send_oper_ifla(int sock, int ifindex, int linkmode, int operstate);

/* NL80211DriverCallback.c */
int ack_handler(struct nl_msg *msg, void *arg);
int finish_handler(struct nl_msg *msg, void *arg);
int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);
int CB_getQoSValues(struct nl_msg *msg, void *arg);
int CB_getPhyInfo(struct nl_msg *msg, void * arg);
int CB_setNewInterface(struct nl_msg *msg, void * arg);
int CB_startAP(struct nl_msg *msg, void * arg);

/* NL80211Driver.c */
int ieee80211_frequency_to_channel(int freq);
int nl80211_send_recv_cb_input(struct nl80211SocketUnit *nlSockUnit,
				struct nl_msg *msg,
				int (*valid_handler)(struct nl_msg *, void *),
				void *valid_data);

