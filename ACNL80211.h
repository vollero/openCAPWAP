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

//Elena Agostini: max num WTP radio interface
#define WTP_RADIO_MAX 5

/* Elena Agostini: nl80211 support */
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
