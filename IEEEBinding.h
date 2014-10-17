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

#include "eloop.h"
/* ********* DEFINE ********* */
#define ETH_ALEN 6
/*
* 80211.a = 2
* 80211.b = 1
* 80211.g = 4
* 80211.n = 8
*/
		
#define nl_handle nl_sock
#define nl80211_handle_alloc nl_socket_alloc_cb
#define nl80211_handle_destroy nl_socket_free
		 
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

#ifndef BIT0
#define BIT0(x) (0 << (x))
#endif

//Netlink socket
typedef struct nl80211SocketUnit {
	struct nl_sock *nl_sock;
	int nl80211_id;
	
	struct nl_cb *nl_cb;
	struct nl_handle * nl;
	
	int sockNetlink;
}nl80211SocketUnit;
extern struct nl80211SocketUnit globalNLSock;

//Max num WTP radio interface
#define WTP_RADIO_MAX 5
//Max num WTP interface for each radio
#define WTP_MAX_INTERFACES 3
//Max num STA for each interface
#define WTP_MAX_STA 3

#define WLAN_CAPABILITY_NUM_FIELDS 16
#define WLAN_KEY_LEN 4
#define WLAN_GROUP_TSC_LEN 6
#define CW_MSG_IEEE_ADD_WLAN_MIN_LEN 23
#define CW_MSG_IEEE_UPDATE_WLAN_MIN_LEN 23
#define CW_MSG_IEEE_STATION_LEN 13

#define MAC80211_BEACON_BODY_MANDATORY_MIN_LEN 12
#define MAC80211_MAX_PROBERESP_LEN 768

#define WTP_NAME_WLAN_PREFIX "WTPWLan"
#define WTP_NAME_WLAN_PREFIX_LEN 7
#define WTP_NAME_WLAN_SUFFIX_LEN 2

/* ++++++++ IE Frame Management ++++++++++ */
#define MGMT_FRAME_FIXED_LEN_BEACON 36
#define MGMT_FRAME_FIXED_LEN_PROBE_RESP 36
#define MGMT_FRAME_FIXED_LEN_AUTH 30
#define MGMT_FRAME_FIXED_LEN_ASSOCIATION 30
#define MGMT_FRAME_IE_FIXED_LEN 2

#define LEN_IE_FRAME_CONTROL 2
#define LEN_IE_DURATION 2
#define LEN_IE_BEACON_INT 2
#define LEN_IE_CAPABILITY 2
#define LEN_IE_LISTEN_INTERVAL 2
#define LEN_IE_SEQ_CTRL 2
#define LEN_IE_TIMESTAMP 8
#define LEN_IE_AUTH_ALG 2
#define LEN_IE_AUTH_TRANS 2
#define LEN_IE_STATUS_CODE 2
#define LEN_IE_REASON_CODE 2
#define LEN_IE_ASSOCIATION_ID 2

#define IE_TYPE_LEN 1
#define IE_SIZE_LEN 1
#define IE_TYPE_SSID 0
#define IE_TYPE_SUPP_RATES 1
#define IE_TYPE_DSSS 3

#define IE_AUTH_OPEN_SYSTEM 0

#define IE_STATUS_CODE_SUCCESS 0
#define IE_STATUS_CODE_FAILURE 1

#define CW_80211_MAX_SUPP_RATES 8

/* ++++++++ IE Frame Data ++++++++++ */
#define DATA_FRAME_FIXED_LEN_ACK 10

enum {
	CW_80211_SUPP_RATES_CONVERT_VALUE_TO_FRAME,
	CW_80211_SUPP_RATES_CONVERT_FRAME_TO_VALUE
}CW80211ConversionRateType;

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
	int realRadioID;
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
	
	//Netlink: Receive frames on each interface
	struct nl_handle *nl_preq, *nl_mgmt;
	struct nl_cb *nl_cb;

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
	int realRadioID;

	char * phyName;
	CWBool phyStandard2400MH; //802.11b/g
	CWBool phyStandard5000MH; //802.11a/n
	float * phyMbpsSet;
	char * supportedRates;
	int lenSupportedRates;
	
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
	
	//Netlink: Receive frames on each interface
	struct nl_handle *nl_beacons;
	struct nl_cb *nl_cb;
	
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
	char * supportedRates;
	int lenSupportedRates;
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

typedef enum {
	CW_80211_STA_OFF,
	CW_80211_STA_PROBE,
	CW_80211_STA_AUTH,
	CW_80211_STA_ASSOCIATION,
	CW_80211_STA_DATA
} CW80211StateSTA;

typedef struct WTPSTAInfo {
	CW80211StateSTA state;
	unsigned char * address;
	short int staAID;
	short int capabilityBit;
	short int listenInterval;
	short int flags;
	
	CWBool radioAdd;
	
	//Phy Attr
	CWBool phyStandard2400MH; //802.11b/g
	CWBool phyStandard5000MH; //802.11a/n
	float * phyMbpsSet;
	char * supportedRates;
	int lenSupportedRates;
	
	CWBool phyHT20;
	CWBool phyHT40;
	//802.11a/b/g/n
	CWBool phyStandardA;
	CWBool phyStandardB;
	CWBool phyStandardG;
	CWBool phyStandardN;
	PhyFrequencyInfo phyFrequencyInfo;

} WTPSTAInfo;


typedef struct WTPBSSInfo {
	CWBool active;
	
	CWThread threadBSS;
	
	nl80211SocketUnit BSSNLSock;
	
	WTPSinglePhyInfo * phyInfo;
	WTPInterfaceInfo * interfaceInfo;
	
	int numSTAActive;
	WTPSTAInfo * staList;
	
} WTPBSSInfo;
extern struct WTPBSSInfo ** WTPGlobalBSSList;

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

/**
 * union wpa_event_data - Additional data for wpa_supplicant_event() calls
 */
union wpa_event_data {
	/**
	 * struct assoc_info - Data for EVENT_ASSOC and EVENT_ASSOCINFO events
	 *
	 * This structure is optional for EVENT_ASSOC calls and required for
	 * EVENT_ASSOCINFO calls. By using EVENT_ASSOC with this data, the
	 * driver interface does not need to generate separate EVENT_ASSOCINFO
	 * calls.
	 */
	struct assoc_info {
		/**
		 * reassoc - Flag to indicate association or reassociation
		 */
		int reassoc;

		/**
		 * req_ies - (Re)Association Request IEs
		 *
		 * If the driver generates WPA/RSN IE, this event data must be
		 * returned for WPA handshake to have needed information. If
		 * wpa_supplicant-generated WPA/RSN IE is used, this
		 * information event is optional.
		 *
		 * This should start with the first IE (fixed fields before IEs
		 * are not included).
		 */
		const u8 *req_ies;

		/**
		 * req_ies_len - Length of req_ies in bytes
		 */
		size_t req_ies_len;

		/**
		 * resp_ies - (Re)Association Response IEs
		 *
		 * Optional association data from the driver. This data is not
		 * required WPA, but may be useful for some protocols and as
		 * such, should be reported if this is available to the driver
		 * interface.
		 *
		 * This should start with the first IE (fixed fields before IEs
		 * are not included).
		 */
		const u8 *resp_ies;

		/**
		 * resp_ies_len - Length of resp_ies in bytes
		 */
		size_t resp_ies_len;

		/**
		 * beacon_ies - Beacon or Probe Response IEs
		 *
		 * Optional Beacon/ProbeResp data: IEs included in Beacon or
		 * Probe Response frames from the current AP (i.e., the one
		 * that the client just associated with). This information is
		 * used to update WPA/RSN IE for the AP. If this field is not
		 * set, the results from previous scan will be used. If no
		 * data for the new AP is found, scan results will be requested
		 * again (without scan request). At this point, the driver is
		 * expected to provide WPA/RSN IE for the AP (if WPA/WPA2 is
		 * used).
		 *
		 * This should start with the first IE (fixed fields before IEs
		 * are not included).
		 */
		const u8 *beacon_ies;

		/**
		 * beacon_ies_len - Length of beacon_ies */
		size_t beacon_ies_len;

		/**
		 * freq - Frequency of the operational channel in MHz
		 */
		unsigned int freq;

		/**
		 * addr - Station address (for AP mode)
		 */
		const u8 *addr;
	} assoc_info;

	/**
	 * struct disassoc_info - Data for EVENT_DISASSOC events
	 */
	struct disassoc_info {
		/**
		 * addr - Station address (for AP mode)
		 */
		const u8 *addr;

		/**
		 * reason_code - Reason Code (host byte order) used in
		 *	Deauthentication frame
		 */
		u16 reason_code;

		/**
		 * ie - Optional IE(s) in Disassociation frame
		 */
		const u8 *ie;

		/**
		 * ie_len - Length of ie buffer in octets
		 */
		size_t ie_len;

		/**
		 * locally_generated - Whether the frame was locally generated
		 */
		int locally_generated;
	} disassoc_info;

	/**
	 * struct deauth_info - Data for EVENT_DEAUTH events
	 */
	struct deauth_info {
		/**
		 * addr - Station address (for AP mode)
		 */
		const u8 *addr;

		/**
		 * reason_code - Reason Code (host byte order) used in
		 *	Deauthentication frame
		 */
		u16 reason_code;

		/**
		 * ie - Optional IE(s) in Deauthentication frame
		 */
		const u8 *ie;

		/**
		 * ie_len - Length of ie buffer in octets
		 */
		size_t ie_len;

		/**
		 * locally_generated - Whether the frame was locally generated
		 */
		int locally_generated;
	} deauth_info;

	/**
	 * struct michael_mic_failure - Data for EVENT_MICHAEL_MIC_FAILURE
	 */
	struct michael_mic_failure {
		int unicast;
		const u8 *src;
	} michael_mic_failure;

	/**
	 * struct interface_status - Data for EVENT_INTERFACE_STATUS
	 */
	struct interface_status {
		char ifname[100];
		enum {
			EVENT_INTERFACE_ADDED, EVENT_INTERFACE_REMOVED
		} ievent;
	} interface_status;

	/**
	 * struct pmkid_candidate - Data for EVENT_PMKID_CANDIDATE
	 */
	struct pmkid_candidate {
		/** BSSID of the PMKID candidate */
		u8 bssid[ETH_ALEN];
		/** Smaller the index, higher the priority */
		int index;
		/** Whether RSN IE includes pre-authenticate flag */
		int preauth;
	} pmkid_candidate;

	/**
	 * struct stkstart - Data for EVENT_STKSTART
	 */
	struct stkstart {
		u8 peer[ETH_ALEN];
	} stkstart;

	/**
	 * struct tdls - Data for EVENT_TDLS
	 */
	struct tdls {
		u8 peer[ETH_ALEN];
		enum {
			TDLS_REQUEST_SETUP,
			TDLS_REQUEST_TEARDOWN
		} oper;
		u16 reason_code; /* for teardown */
	} tdls;

	/**
	 * struct wnm - Data for EVENT_WNM
	 */
	struct wnm {
		u8 addr[ETH_ALEN];
		enum {
			WNM_OPER_SLEEP,
		} oper;
		enum {
			WNM_SLEEP_ENTER,
			WNM_SLEEP_EXIT
		} sleep_action;
		int sleep_intval;
		u16 reason_code;
		u8 *buf;
		u16 buf_len;
	} wnm;

	/**
	 * struct ft_ies - FT information elements (EVENT_FT_RESPONSE)
	 *
	 * During FT (IEEE 802.11r) authentication sequence, the driver is
	 * expected to use this event to report received FT IEs (MDIE, FTIE,
	 * RSN IE, TIE, possible resource request) to the supplicant. The FT
	 * IEs for the next message will be delivered through the
	 * struct wpa_driver_ops::update_ft_ies() callback.
	 */
	struct ft_ies {
		const u8 *ies;
		size_t ies_len;
		int ft_action;
		u8 target_ap[ETH_ALEN];
		/** Optional IE(s), e.g., WMM TSPEC(s), for RIC-Request */
		const u8 *ric_ies;
		/** Length of ric_ies buffer in octets */
		size_t ric_ies_len;
	} ft_ies;

	/**
	 * struct ibss_rsn_start - Data for EVENT_IBSS_RSN_START
	 */
	struct ibss_rsn_start {
		u8 peer[ETH_ALEN];
	} ibss_rsn_start;

	/**
	 * struct auth_info - Data for EVENT_AUTH events
	 */
	struct auth_info {
		u8 peer[ETH_ALEN];
		u8 bssid[ETH_ALEN];
		u16 auth_type;
		u16 auth_transaction;
		u16 status_code;
		const u8 *ies;
		size_t ies_len;
	} auth;

	/**
	 * struct assoc_reject - Data for EVENT_ASSOC_REJECT events
	 */
	struct assoc_reject {
		/**
		 * bssid - BSSID of the AP that rejected association
		 */
		const u8 *bssid;

		/**
		 * resp_ies - (Re)Association Response IEs
		 *
		 * Optional association data from the driver. This data is not
		 * required WPA, but may be useful for some protocols and as
		 * such, should be reported if this is available to the driver
		 * interface.
		 *
		 * This should start with the first IE (fixed fields before IEs
		 * are not included).
		 */
		const u8 *resp_ies;

		/**
		 * resp_ies_len - Length of resp_ies in bytes
		 */
		size_t resp_ies_len;

		/**
		 * status_code - Status Code from (Re)association Response
		 */
		u16 status_code;
	} assoc_reject;

	struct timeout_event {
		u8 addr[ETH_ALEN];
	} timeout_event;

	/**
	 * struct ft_rrb_rx - Data for EVENT_FT_RRB_RX events
	 */
	struct ft_rrb_rx {
		const u8 *src;
		const u8 *data;
		size_t data_len;
	} ft_rrb_rx;

	/**
	 * struct tx_status - Data for EVENT_TX_STATUS events
	 */
	struct tx_status {
		u16 type;
		u16 stype;
		const u8 *dst;
		const u8 *data;
		size_t data_len;
		int ack;
	} tx_status;

	/**
	 * struct rx_from_unknown - Data for EVENT_RX_FROM_UNKNOWN events
	 */
	struct rx_from_unknown {
		const u8 *bssid;
		const u8 *addr;
		int wds;
	} rx_from_unknown;

	/**
	 * struct rx_mgmt - Data for EVENT_RX_MGMT events
	 */
	struct rx_mgmt {
		const u8 *frame;
		size_t frame_len;
		u32 datarate;

		/**
		 * drv_priv - Pointer to store driver private BSS information
		 *
		 * If not set to NULL, this is used for comparison with
		 * hostapd_data->drv_priv to determine which BSS should process
		 * the frame.
		 */
		void *drv_priv;

		/**
		 * freq - Frequency (in MHz) on which the frame was received
		 */
		int freq;

		/**
		 * ssi_signal - Signal strength in dBm (or 0 if not available)
		 */
		int ssi_signal;
	} rx_mgmt;

	/**
	 * struct remain_on_channel - Data for EVENT_REMAIN_ON_CHANNEL events
	 *
	 * This is also used with EVENT_CANCEL_REMAIN_ON_CHANNEL events.
	 */
	struct remain_on_channel {
		/**
		 * freq - Channel frequency in MHz
		 */
		unsigned int freq;

		/**
		 * duration - Duration to remain on the channel in milliseconds
		 */
		unsigned int duration;
	} remain_on_channel;

	/**
	 * struct scan_info - Optional data for EVENT_SCAN_RESULTS events
	 * @aborted: Whether the scan was aborted
	 * @freqs: Scanned frequencies in MHz (%NULL = all channels scanned)
	 * @num_freqs: Number of entries in freqs array
	 * @ssids: Scanned SSIDs (%NULL or zero-length SSID indicates wildcard
	 *	SSID)
	 * @num_ssids: Number of entries in ssids array
	 */
	/*struct scan_info {
		int aborted;
		const int *freqs;
		size_t num_freqs;
		struct wpa_driver_scan_ssid ssids[WPAS_MAX_SCAN_SSIDS];
		size_t num_ssids;
	} scan_info;
*/
	/**
	 * struct mlme_rx - Data for EVENT_MLME_RX events
	 */
	struct mlme_rx {
		const u8 *buf;
		size_t len;
		int freq;
		int channel;
		int ssi;
	} mlme_rx;

	/**
	 * struct rx_probe_req - Data for EVENT_RX_PROBE_REQ events
	 */
	struct rx_probe_req {
		/**
		 * sa - Source address of the received Probe Request frame
		 */
		const u8 *sa;

		/**
		 * da - Destination address of the received Probe Request frame
		 *	or %NULL if not available
		 */
		const u8 *da;

		/**
		 * bssid - BSSID of the received Probe Request frame or %NULL
		 *	if not available
		 */
		const u8 *bssid;

		/**
		 * ie - IEs from the Probe Request body
		 */
		const u8 *ie;

		/**
		 * ie_len - Length of ie buffer in octets
		 */
		size_t ie_len;

		/**
		 * signal - signal strength in dBm (or 0 if not available)
		 */
		int ssi_signal;
	} rx_probe_req;

	/**
	 * struct new_sta - Data for EVENT_NEW_STA events
	 */
	struct new_sta {
		const u8 *addr;
	} new_sta;

	/**
	 * struct eapol_rx - Data for EVENT_EAPOL_RX events
	 */
	struct eapol_rx {
		const u8 *src;
		const u8 *data;
		size_t data_len;
	} eapol_rx;

	/**
	 * signal_change - Data for EVENT_SIGNAL_CHANGE events
	 */
	//struct wpa_signal_info signal_change;

	/**
	 * struct best_channel - Data for EVENT_BEST_CHANNEL events
	 * @freq_24: Best 2.4 GHz band channel frequency in MHz
	 * @freq_5: Best 5 GHz band channel frequency in MHz
	 * @freq_overall: Best channel frequency in MHz
	 *
	 * 0 can be used to indicate no preference in either band.
	 */
	 /*
	struct best_channel {
		int freq_24;
		int freq_5;
		int freq_overall;
	} best_chan;

	struct unprot_deauth {
		const u8 *sa;
		const u8 *da;
		u16 reason_code;
	} unprot_deauth;

	struct unprot_disassoc {
		const u8 *sa;
		const u8 *da;
		u16 reason_code;
	} unprot_disassoc;
*/
	/**
	 * struct low_ack - Data for EVENT_STATION_LOW_ACK events
	 * @addr: station address
	 */
	struct low_ack {
		u8 addr[ETH_ALEN];
	} low_ack;

	/**
	 * struct ibss_peer_lost - Data for EVENT_IBSS_PEER_LOST
	 */
	struct ibss_peer_lost {
		u8 peer[ETH_ALEN];
	} ibss_peer_lost;

	/**
	 * struct driver_gtk_rekey - Data for EVENT_DRIVER_GTK_REKEY
	 */
	struct driver_gtk_rekey {
		const u8 *bssid;
		const u8 *replay_ctr;
	} driver_gtk_rekey;

	/**
	 * struct client_poll - Data for EVENT_DRIVER_CLIENT_POLL_OK events
	 * @addr: station address
	 */
	struct client_poll {
		u8 addr[ETH_ALEN];
	} client_poll;

	/**
	 * struct eapol_tx_status
	 * @dst: Original destination
	 * @data: Data starting with IEEE 802.1X header (!)
	 * @data_len: Length of data
	 * @ack: Indicates ack or lost frame
	 *
	 * This corresponds to hapd_send_eapol if the frame sent
	 * there isn't just reported as EVENT_TX_STATUS.
	 */
	struct eapol_tx_status {
		const u8 *dst;
		const u8 *data;
		int data_len;
		int ack;
	} eapol_tx_status;

	/**
	 * struct ch_switch
	 * @freq: Frequency of new channel in MHz
	 * @ht_enabled: Whether this is an HT channel
	 * @ch_offset: Secondary channel offset
	 * @ch_width: Channel width
	 * @cf1: Center frequency 1
	 * @cf2: Center frequency 2
	 */
/*	struct ch_switch {
		int freq;
		int ht_enabled;
		int ch_offset;
		enum chan_width ch_width;
		int cf1;
		int cf2;
	} ch_switch;
*/
	/**
	 * struct connect_failed - Data for EVENT_CONNECT_FAILED_REASON
	 * @addr: Remote client address
	 * @code: Reason code for connection failure
	 */
	struct connect_failed_reason {
		u8 addr[ETH_ALEN];
		enum {
			MAX_CLIENT_REACHED,
			BLOCKED_CLIENT
		} code;
	} connect_failed_reason;

	/**
	 * struct dfs_event - Data for radar detected events
	 * @freq: Frequency of the channel in MHz
	 */
/*
	struct dfs_event {
		int freq;
		int ht_enabled;
		int chan_offset;
		enum chan_width chan_width;
		int cf1;
		int cf2;
	} dfs_event;
*/
	/**
	 * survey_results - Survey result data for EVENT_SURVEY
	 * @freq_filter: Requested frequency survey filter, 0 if request
	 *	was for all survey data
	 * @survey_list: Linked list of survey data
	 */
/*
	struct survey_results {
		unsigned int freq_filter;
		struct dl_list survey_list; // struct freq_survey
	} survey_results;
*/
	/**
	 * channel_list_changed - Data for EVENT_CHANNEL_LIST_CHANGED
	 * @initiator: Initiator of the regulatory change
	 * @type: Regulatory change type
	 * @alpha2: Country code (or "" if not available)
	 */
/*
	struct channel_list_changed {
		enum reg_change_initiator initiator;
		enum reg_type type;
		char alpha2[3];
	} channel_list_changed;
*/
	/**
	 * freq_range - List of frequency ranges
	 *
	 * This is used as the data with EVENT_AVOID_FREQUENCIES.
	 */
	struct wpa_freq_range_list freq_range;
};

#if __WORDSIZE == 64
#define ELOOP_SOCKET_INVALID	(intptr_t) 0x8888888888888889ULL
#else
#define ELOOP_SOCKET_INVALID	(intptr_t) 0x88888889ULL
#endif

/* WUM IEEE 802.11 */
typedef struct WUMWLANCmdParameters {
	int typeCmd;
	int radioID;
	int wlanID;
	char * ssid;
} WUMWLANCmdParameters;

typedef struct CWFrameProbeRequest {
	short int frameControl;
	short int duration;
	unsigned char DA[ETH_ALEN];
	unsigned char SA[ETH_ALEN];
	unsigned char BSSID[ETH_ALEN];
	short int seqCtrl;
	
	char * SSID;
	
} CWFrameProbeRequest;

typedef struct CWFrameAuthRequest {
	short int frameControl;
	short int duration;
	unsigned char DA[ETH_ALEN];
	unsigned char SA[ETH_ALEN];
	unsigned char BSSID[ETH_ALEN];
	short int seqCtrl;
	char * SSID;
	
	short int authAlg;
	short int authTransaction;
	short int statusCode;
} CWFrameAuthRequest;

typedef struct CWFrameAuthResponse {
	short int frameControl;
	short int duration;
	unsigned char DA[ETH_ALEN];
	unsigned char SA[ETH_ALEN];
	unsigned char BSSID[ETH_ALEN];
	short int seqCtrl;
	char * SSID;
	
	short int authAlg;
	short int authTransaction;
	short int statusCode;
} CWFrameAuthResponse;

typedef struct CWFrameAssociationRequest {
	short int frameControl;
	short int duration;
	unsigned char DA[ETH_ALEN];
	unsigned char SA[ETH_ALEN];
	unsigned char BSSID[ETH_ALEN];
	short int seqCtrl;
	
	short int capabilityBit;
	short int listenInterval;
	char * SSID;
	short int supportedRatesLen;
	char * supportedRates;

} CWFrameAssociationRequest;

typedef struct CWFrameAssociationResponse {
	short int frameControl;
	short int duration;
	unsigned char DA[ETH_ALEN];
	unsigned char SA[ETH_ALEN];
	unsigned char BSSID[ETH_ALEN];
	short int seqCtrl;
	
	short int capabilityBit;
	short int statusCode;
	short int assID;
	
	short int supportedRatesLen;
	char * supportedRates;

} CWFrameAssociationResponse;

typedef struct CWFrameDeauthDisassociationRequest {
	short int frameControl;
	short int duration;
	unsigned char DA[ETH_ALEN];
	unsigned char SA[ETH_ALEN];
	unsigned char BSSID[ETH_ALEN];
	short int seqCtrl;
	
	short int reasonCode;
	
} CWFrameDeauthDisassociationRequest;


//WTPRadio.c
CWBool CWWTPGetRadioGlobalInfo(void);
CWBool CWWTPCreateNewWlanInterface(int radioID, int wlanID);
CWBool CWWTPSetAPInterface(int radioIndex, int wlanIndex, WTPInterfaceInfo * interfaceInfo);
CWBool CWWTPDeleteWLANAPInterface(int radioID, int wlanID);
CWBool CWWTPCreateNewBSS(int radioID, int wlanID);
CWBool CWWTPAddNewStation(int BSSIndex, int STAIndex);

//Define create per allocazione array in CB_getPhyInfo
//la dove dovrei fare due cicli per sapere la quantita di bitrate e di canali
//che dovranno essere salvati
#define WTP_NL80211_BITRATE_NUM 50
#define WTP_NL80211_CHANNELS_NUM 50
#define WTP_NL80211_DEFAULT_MSDU 512

//WTP80211Netlink.c
int nl80211_init_socket(struct nl80211SocketUnit *nlSockUnit);
int netlink_create_socket(struct nl80211SocketUnit *nlSockUnit);
CWBool netlink_send_oper_ifla(int sock, int ifindex, int linkmode, int operstate);
struct nl_handle * nl_create_handle(struct nl_cb *cb, const char *dbg);
			 
//struct nl_handle *nl80211_handle_alloc(void *cb);
//void nl80211_handle_destroy(struct nl_handle *handle);

int no_seq_check(struct nl_msg *msg, void *arg);
int CW80211InitNlCb(WTPBSSInfo * WTPBSSInfoPtr);
int CW80211CheckTypeEvent(struct nl_msg *msg, void *arg);
int send_and_recv(struct nl80211SocketUnit *global,
			 struct nl_handle *nl_handle, struct nl_msg *msg,
			 int (*valid_handler)(struct nl_msg *, void *),
			 void *valid_data);
int nl80211_send_recv_cb_input(struct nl80211SocketUnit *nlSockUnit,
				struct nl_msg *msg,
				int (*valid_handler)(struct nl_msg *, void *),
				void *valid_data);
void nl_destroy_handles(struct nl_handle **handle);

/* NL80211DriverCallback.c */
int ack_handler(struct nl_msg *msg, void *arg);
int finish_handler(struct nl_msg *msg, void *arg);
int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);
int CB_getQoSValues(struct nl_msg *msg, void *arg);
int CB_getPhyInfo(struct nl_msg *msg, void * arg);
int CB_setNewInterface(struct nl_msg *msg, void * arg);
int CB_startAP(struct nl_msg *msg, void * arg);
int CB_cookieHandler(struct nl_msg *msg, void *arg);
int CB_getChannelInterface(struct nl_msg *msg, void *arg);

/* NL80211Driver.c */
CWBool nl80211CmdGetChannelInterface(char * interface, int * channel);
CWBool nl80211CmdGetPhyInfo(int indexPhy, struct WTPSinglePhyInfo * singlePhyInfo);
CWBool nl80211CmdSetNewInterface(int indexPhy, WTPInterfaceInfo * interfaceInfo);
CWBool nl80211CmdDelInterface(int indexPhy, char * ifName);
CWBool nl80211CmdSetInterfaceAPType(char * interface);
CWBool nl80211CmdSetInterfaceSTAType(char * interface);
CWBool nl80211CmdSetChannelInterface(char * interface, int channel);
CWBool nl80211CmdStartAP(WTPInterfaceInfo * interfaceInfo);
CWBool nl80211CmdStopAP(char * ifName);
CWBool nl80211CmdDelStation(WTPBSSInfo * infoBSS, char * macAddress);
CWBool nl80211CmdNewStation(WTPBSSInfo * infoBSS, WTPSTAInfo staInfo);
CWBool nl80211CmdSetStation(WTPBSSInfo * infoBSS, WTPSTAInfo staInfo);

CWBool ioctlActivateInterface(char * interface);
const char * nl80211_command_to_string(enum nl80211_commands cmd);

int CW80211SetAPTypeFrame(WTPInterfaceInfo * interfaceInfo, int radioID, WTPBSSInfo * WTPBSSInfoPtr);
int nl80211_alloc_mgmt_handle(WTPInterfaceInfo * interfaceInfo);
int nl80211_register_frame(WTPInterfaceInfo * interfaceInfo,
				  struct nl_handle *nl_handle,
				  u16 type, const u8 *match, size_t match_len);
int nl80211_register_spurious_class3(WTPInterfaceInfo * interfaceInfo);
void nl80211_mgmt_handle_register_eloop(WTPInterfaceInfo * interfaceInfo);
void nl80211_register_eloop_read(struct nl_handle **handle,
					eloop_sock_handler handler,
					void *eloop_data);
void CW80211EventReceive(void *eloop_ctx, void *handle);
void CW80211EventProcess(WTPBSSInfo * WTPBSSInfoPtr, int cmd, struct nlattr **tb, char * frameBuffer);
int nl80211_set_bss(WTPInterfaceInfo * interfaceInfo, int cts, int preamble);


/* CW80211ManagementFrame.c */
CWBool CW80211SendFrame(WTPBSSInfo * WTPBSSInfoPtr, unsigned int freq, unsigned int wait, char * buf, size_t buf_len, u64 *cookie_out, int no_cck, int no_ack);
WTPSTAInfo * addSTABySA(WTPBSSInfo * WTPBSSInfoPtr, char * sa);
WTPSTAInfo * findSTABySA(WTPBSSInfo * WTPBSSInfoPtr, char * sa);
CWBool delSTABySA(WTPBSSInfo * WTPBSSInfoPtr, char * sa);
CWBool CWSendFrameMgmtFromWTPtoAC(char * frameReceived, int len);
void CW80211HandleClass3Frame(WTPBSSInfo * WTPBSSInfoPtr, int cmd, struct nlattr **tb, char * frameBuffer);

CW_THREAD_RETURN_TYPE CWWTPBSSManagement(void *arg);
typedef void (*cw_sock_handler)(void *cb, void *handle);
void CW80211ManagementFrameEvent(struct nl_handle **handle, cw_sock_handler handler, void * cb);

int ieee80211_frequency_to_channel(int freq);


/* CW80211InformationElements.c */
char * CW80211AssembleProbeResponse(WTPBSSInfo * WTPBSSInfoPtr, struct CWFrameProbeRequest *request, int *offset);
char * CW80211AssembleAuthResponse(char * addrAP, struct CWFrameAuthRequest *request, int *offset);
char * CW80211AssembleAssociationResponse(WTPBSSInfo * WTPBSSInfoPtr, WTPSTAInfo * staInfo, struct CWFrameAssociationRequest *request, int *offset);
char * CW80211AssembleAssociationResponseAC(char * MACAddr, char * BSSID,  short int capabilityBit, short int staAID, char * suppRate, int suppRatesLen, struct CWFrameAssociationRequest *request, int *offset);
char * CW80211AssembleBeacon(WTPBSSInfo * WTPBSSInfoPtr, int *offset);
char *  CW80211AssembleACK(WTPBSSInfo * WTPBSSInfoPtr, char * DA, int *offset);

CWBool CW80211ParseProbeRequest(char * frame, struct CWFrameProbeRequest * probeRequest);
CWBool CW80211ParseAuthRequest(char * frame, struct CWFrameAuthRequest * authRequest);
CWBool CW80211ParseAssociationRequest(char * frame, struct CWFrameAssociationRequest * assocRequest);

CWBool CW80211AssembleIEFrameControl(char * frame, int * offset, int frameType, int frameSubtype);
CWBool CW80211AssembleIEDuration(char * frame, int * offset, int value);
CWBool CW80211AssembleIEAddr(char * frame, int * offset, char * value);
CWBool CW80211AssembleIEBeaconInterval(char * frame, int * offset, short int value);
CWBool CW80211AssembleIECapability(char * frame, int * offset, short int value);
CWBool CW80211AssembleIEAuthAlgoNum(char * frame, int * offset, short int value);
CWBool CW80211AssembleIEAuthTransNum(char * frame, int * offset, short int value);
CWBool CW80211AssembleIEStatusCode(char * frame, int * offset, short int value);
CWBool CW80211AssembleIEAssID(char * frame, int * offset, short int value);

CWBool CW80211AssembleIESSID(char * frame, int * offset, char * value);
float mapSupportedRatesValues(float rate, short int mode);
CWBool CW80211AssembleIESupportedRates(char * frame, int * offset, char * value, int numRates);
CWBool CW80211AssembleIEDSSS(char * frame, int * offset, char value);

CWBool CW80211ParseFrameIEControl(char * frameReceived, int * offsetFrameReceived, short int * value);
CWBool CW80211ParseFrameIEDuration(char * frameReceived, int * offsetFrameReceived, short int * value);
CWBool CW80211ParseFrameIEAddr(char * frameReceived, int * offsetFrameReceived, unsigned char * addr);
CWBool CW80211ParseFrameIECapability(char * frameReceived, int * offsetFrameReceived, short int * value);
CWBool CW80211ParseFrameIESeqCtrl(char * frameReceived, int * offsetFrameReceived, short int * value);
CWBool CW80211ParseFrameIEStatusCode(char * frameReceived, int * offsetFrameReceived, short int * value);
CWBool CW80211ParseFrameIEAuthAlgo(char * frameReceived, int * offsetFrameReceived, short int * value);
CWBool CW80211ParseFrameIEAuthTransaction(char * frameReceived, int * offsetFrameReceived, short int * value);
CWBool CW80211ParseFrameIESSID(char * frameReceived, int * offsetFrameReceived, char ** value);
CWBool CW80211ParseFrameIEListenInterval(char * frameReceived, int * offsetFrameReceived, short int * value);
CWBool CW80211ParseFrameIESupportedRates(char * frameReceived, int * offsetFrameReceived, char ** value, int * lenIE);
CWBool CW80211SetAssociationID(short int * assID);
CWBool CW80211ParseAssociationResponse(char * frame, struct CWFrameAssociationResponse * assocResponse);

