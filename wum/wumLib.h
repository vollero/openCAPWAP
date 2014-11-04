
#include <stdio.h>

#define QUIT_MSG 0
#define LIST_MSG 1
#define CONF_UPDATE_MSG 2

#define MSG_ELEMENT_TYPE_VENDOR_WUM 3
//Elena Agostini - 09/2014: IEEE Binding
#define MSG_ELEMENT_TYPE_ADD_WLAN 4
#define MSG_ELEMENT_TYPE_DEL_WLAN 5

#define WTP_VERSION_REQUEST     1
#define WTP_VERSION_RESPONSE    2

#define WTP_UPDATE_REQUEST      3
#define WTP_UPDATE_RESPONSE     4

#define WTP_CUP_FRAGMENT        5
#define WTP_CUP_ACK             6

#define WTP_COMMIT_UPDATE       7
#define WTP_COMMIT_ACK          8

#define WTP_CANCEL_UPDATE_REQUEST       9
#define WTP_CANCEL_UPDATE_RESPONSE     10

#define WTP_WLAN_ADD_REQUEST       11
#define WTP_WLAN_ADD_RESPONSE      12

#define WTP_WLAN_DEL_REQUEST       13
#define WTP_WLAN_DEL_RESPONSE      14

#define SUCCESS	0
#define ERROR	1

#define FRAGMENT_SIZE 4000

struct WTPInfo {
	int wtpId;
	char *name;
};

struct version_info {
	char major;
	char minor;
	char revision;
	int size;
};

int ACServerConnect(char *address, int port);
void ACServerDisconnect(int acserver);
struct WTPInfo *ACServerWTPList(int acserver, int *nWTPs);	
void freeWTPList(struct WTPInfo *wtpList, int nWTPs);

int WUMGetWTPVersion(int acserver, int wtpId, struct version_info *);
int WUMReadCupVersion(char *cup_pathname, struct version_info *update_v);
int WUMUpdate(int acserver, int wtpId, void *cup_buf, struct version_info update_v);
int WUMSendCancelRequest(int acserver, int wtpId);

/*
 * Elena Agostini - 09/2014: IEEE 802.11 Binding
 */
void do_wlan_add_cmd(int acserver, char *wtpIds, char *wtpNames, char * ssid, char * radioID, char * wlanID, char * tunnel);
void do_wlan_del_cmd(int acserver, char *wtpIds, char *wtpNames, char * radioID, char * wlanID);


