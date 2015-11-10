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



//Netlink socket
typedef struct nl80211SocketUnit {
	struct nl_sock *nl_sock;
	int nl80211_id;
	
	struct nl_cb *nl_cb;
	struct nl_handle * nl;
	
	int sockNetlink;
	int ioctl_sock;
}nl80211SocketUnit;
extern struct nl80211SocketUnit globalNLSock;

//Max num WTP radio interface
#define WTP_RADIO_MAX 5
//Max num WTP interface for each radio
#define WTP_MAX_INTERFACES 1
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
#define IE_TYPE_ERP 42
#define IE_TYPE_EXT_SUPP_RATES 50
#define IE_TYPE_BSS_MAX_IDLE_PERIOD 90

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
	//Elena Agostini: tunnel mode for add wlan
	int frameTunnelMode;
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
	//Elena Agostini: tunnel mode for add wlan
	int frameTunnelMode;
	char suppressSSID;
	char * SSID;
	char * MACaddr;
	char * BSSID;
	
	//Netlink: Receive frames on each interface
	struct nl_handle *nl_mgmt;
	struct nl_cb *nl_cb;

} WTPInterfaceInfo;

//0,1,2,3,4 ...
#define CW_WTP_DEFAULT_RADIO_CHANNEL 0

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
	
	WTPInterfaceInfo monitorInterface;
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

#define CW_WTP_STA_ASSOCIATION_REQUEST_TIMER 10

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
	char * extSupportedRates;
	int extSupportedRatesLen;
	
	CWBool phyHT20;
	CWBool phyHT40;
	//802.11a/b/g/n
	CWBool phyStandardA;
	CWBool phyStandardB;
	CWBool phyStandardG;
	CWBool phyStandardN;
	PhyFrequencyInfo phyFrequencyInfo;
	
	CWTimerID staAssociationRequestTimerID;

} WTPSTAInfo;


typedef struct WTPBSSInfo {
	CWBool active;
	
	CWThread threadBSS;
	
	nl80211SocketUnit BSSNLSock;
	
	WTPSinglePhyInfo * phyInfo;
	WTPInterfaceInfo * interfaceInfo;
	
	int numSTAActive;
	WTPSTAInfo * staList;
	
	CWThreadMutex bssMutex;
	CWBool destroyBSS;
	
} WTPBSSInfo;
extern struct WTPBSSInfo ** WTPGlobalBSSList;

/* WUM IEEE 802.11 */
typedef struct WUMWLANCmdParameters {
	int typeCmd;
	int radioID;
	int wlanID;
	int tunnelMode;
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
	
	short int supportedRatesLen;
	char * supportedRates;
	short int extSupportedRatesLen;
	char * extSupportedRates;
	
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
	short int extSupportedRatesLen;
	char * extSupportedRates;

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

typedef struct CWFrameDataHdr {
	short int frameControl;
	short int duration;
	unsigned char BSSID[ETH_ALEN];
	unsigned char SA[ETH_ALEN];
	unsigned char DA[ETH_ALEN];
	short int seqCtrl; 
} CWFrameDataHdr;

extern int rawInjectSocket;


//WTPRadio.c
CWBool CWWTPGetRadioGlobalInfo(void);
CWBool CWWTPCreateNewWlanInterface(int radioID, int wlanID);
CWBool CWWTPSetAPInterface(int radioIndex, int wlanIndex, WTPInterfaceInfo * interfaceInfo);
CWBool CWWTPDeleteWLANAPInterface(int radioID, int wlanID);
CWBool CWWTPCreateNewBSS(int radioID, int wlanID);
CWBool CWWTPDeleteBSS(int radioIndex, int wlanIndex);
CWBool CWWTPAddNewStation(int BSSIndex, int STAIndex);
CWBool CWWTPDelStation(WTPBSSInfo * BSSInfo, WTPSTAInfo * staInfo);
CWBool CWWTPDisassociateStation(WTPBSSInfo * BSSInfo, WTPSTAInfo * staInfo);
CWBool CWWTPDeauthStation(WTPBSSInfo * BSSInfo, WTPSTAInfo * staInfo);

#define WTP_NL80211_BITRATE_NUM NL80211_MAX_SUPP_RATES
#define WTP_NL80211_CHANNELS_NUM 50
#define WTP_NL80211_DEFAULT_MSDU 512

//WTP80211Netlink.c
int nl80211_init_socket(struct nl80211SocketUnit *nlSockUnit);
void nl80211_cleanup_socket(struct nl80211SocketUnit *nlSockUnit);
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
CWBool CWSetNewBridge(int sock, char * bridgeName);
CWBool CWAddNewBridgeInterface(int sock, char * bridgeName, int wlanID);
CWBool CWDelBridge(int sock, char * bridgeName);
CWBool CWDelBridgeInterface(int sock, char * bridgeName, int wlanID);
int CWGetBridge(char *brname, const char *ifname);

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
int CBget_channel_width(struct nl_msg *msg, void *arg);

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
CWBool nl80211CmdDelStation(WTPBSSInfo * infoBSS, unsigned char * macAddress);
CWBool nl80211CmdNewStation(WTPBSSInfo * infoBSS, WTPSTAInfo staInfo);
CWBool nl80211CmdSetStation(WTPBSSInfo * infoBSS, WTPSTAInfo staInfo);

CWBool ioctlActivateInterface(char * interface);
int CWInjectFrameMonitor(int rawSocket, void *data, size_t len, int encrypt, int noack);
const char * nl80211_command_to_string(enum nl80211_commands cmd);

int CW80211SetAPTypeFrame(WTPInterfaceInfo * interfaceInfo, WTPBSSInfo * WTPBSSInfoPtr);
int nl80211_alloc_mgmt_handle(WTPInterfaceInfo * interfaceInfo);
int nl80211_register_frame(WTPInterfaceInfo * interfaceInfo,
				  struct nl_handle *nl_handle,
				  u16 type, const u8 *match, size_t match_len);
int nl80211_register_spurious_class3(WTPInterfaceInfo * interfaceInfo);
void CW80211EventReceive(void *eloop_ctx, void *handle);
void CW80211EventDataReceive(int dataRawSock, struct WTPBSSInfo * BSSInfo);
void CW80211EventProcess(WTPBSSInfo * WTPBSSInfoPtr, int cmd, struct nlattr **tb, unsigned char * frameBuffer);
int nl80211_set_bss(WTPInterfaceInfo * interfaceInfo, int radioIndex, int cts, int preamble);


/* CW80211ManagementFrame.c */
CWBool CW80211SendFrame(WTPBSSInfo * WTPBSSInfoPtr, unsigned int freq, unsigned int wait, char * buf, size_t buf_len, u64 *cookie_out, int no_cck, int no_ack);
WTPSTAInfo * addSTABySA(WTPBSSInfo * WTPBSSInfoPtr, unsigned char * sa);
WTPSTAInfo * findSTABySA(WTPBSSInfo * WTPBSSInfoPtr, unsigned char * sa);
CWBool delSTABySA(WTPBSSInfo * WTPBSSInfoPtr, unsigned char * sa);
CWBool CWSendFrameMgmtFromWTPtoAC(char * frameReceived, int len);
void CW80211HandleClass3Frame(WTPBSSInfo * WTPBSSInfoPtr, int cmd, struct nlattr **tb, unsigned char * frameBuffer);

CW_THREAD_RETURN_TYPE CWWTPBSSManagement(void *arg);
typedef void (*cw_sock_handler)(void *cb, void *handle);
void CW80211ManagementFrameEvent(struct nl_handle **handle, cw_sock_handler handler, void * cb, WTPBSSInfo * WTPBSSInfoPtr);
CWBool CWStartAssociationRequestTimer(WTPSTAInfo * staInfo, WTPBSSInfo * WTPBSSInfoPtr);
void CWWTPAssociationRequestTimerExpiredHandler(void *arg);
int ieee80211_frequency_to_channel(int freq);
CWBool CWWTPEventRequestDeleteStation(int radioId, unsigned char * staAddr);

/* CW80211InformationElements.c */
char * CW80211AssembleProbeResponse(WTPBSSInfo * WTPBSSInfoPtr, struct CWFrameProbeRequest *request, int *offset);
char * CW80211AssembleAuthResponse(char * addrAP, struct CWFrameAuthRequest *request, int *offset);
char * CW80211AssembleAssociationResponse(WTPBSSInfo * WTPBSSInfoPtr, WTPSTAInfo * staInfo, struct CWFrameAssociationRequest *request, int *offset);
char * CW80211AssembleReassociationResponse(WTPBSSInfo * WTPBSSInfoPtr, WTPSTAInfo * staInfo, struct CWFrameAssociationRequest *request, int *offset);
char * CW80211AssembleReassociationResponse(WTPBSSInfo * WTPBSSInfoPtr, WTPSTAInfo * staInfo, struct CWFrameAssociationRequest *request, int *offset);
char * CW80211AssembleAssociationResponseAC(unsigned char * MACAddr, unsigned char * BSSID,  short int capabilityBit, short int staAID, unsigned char * suppRate, int suppRatesLen, struct CWFrameAssociationRequest *request, int *offset);
char * CW80211AssembleReassociationResponseAC(unsigned char * MACAddr, unsigned char * BSSID,  short int capabilityBit, short int staAID, unsigned char * suppRate, int suppRatesLen, struct CWFrameAssociationRequest *request, int *offset);
char * CW80211AssembleBeacon(WTPBSSInfo * WTPBSSInfoPtr, int *offset);
char *  CW80211AssembleACK(WTPBSSInfo * WTPBSSInfoPtr, char * DA, int *offset);
unsigned char *  CW80211AssembleDataFrameHdr(unsigned char * SA, unsigned char * DA, unsigned char * BSSID, short int seqctl, int *offset, int toDS, int fromDS);

CWBool CW80211ParseProbeRequest(char * frame, struct CWFrameProbeRequest * probeRequest);
CWBool CW80211ParseAuthRequest(char * frame, struct CWFrameAuthRequest * authRequest);
CWBool CW80211ParseAssociationRequest(char * frame, struct CWFrameAssociationRequest * assocRequest);

CWBool CW80211AssembleIEFrameControl(char * frame, int * offset, int frameType, int frameSubtype);
CWBool CW80211AssembleIEFrameControlData(char * frame, int * offset, int frameType, int frameSubtype, int toDS, int fromDS);
CWBool CW80211AssembleIEDuration(char * frame, int * offset, int value);
CWBool CW80211AssembleIEAddr(char * frame, int * offset, char * value);
CWBool CW80211AssembleIEBeaconInterval(char * frame, int * offset, short int value);
CWBool CW80211AssembleIECapability(char * frame, int * offset, short int value);
CWBool CW80211AssembleIEAuthAlgoNum(char * frame, int * offset, short int value);
CWBool CW80211AssembleIEAuthTransNum(char * frame, int * offset, short int value);
CWBool CW80211AssembleIEStatusCode(char * frame, int * offset, short int value);
CWBool CW80211AssembleIEAssID(char * frame, int * offset, short int value);

CWBool CW80211AssembleIEERP(char * frame, int * offset, short int value);
CWBool CW80211AssembleIESSID(char * frame, int * offset, char * value);
float mapSupportedRatesValues(float rate, short int mode);
CWBool CW80211AssembleIESupportedRates(char * frame, int * offset, char * value, int numRates);
CWBool CW80211AssembleIEExtendedSupportedRates(char * frame, int * offset, char * value, int numRates);
CWBool CW80211AssembleIEDSSS(char * frame, int * offset, char value);
CWBool CW8023AssembleHdrLength(char * frame, int * offset, short int value);

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
CWBool CW80211ParseFrameIEExtendedSupportedRates(char * frameReceived, int * offsetFrameReceived, char ** value, int * lenIE);
CWBool CW80211SetAssociationID(short int * assID);
CWBool CW80211ParseAssociationResponse(char * frame, struct CWFrameAssociationResponse * assocResponse);
CWBool CW80211ParseDataFrameToDS(char * frame, struct CWFrameDataHdr * dataFrame);
CWBool CW80211ParseDataFrameFromDS(char * frame, struct CWFrameDataHdr * dataFrame);
