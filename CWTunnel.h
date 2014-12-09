#include "ieee802_11_defs.h"

/* ++++++++++ RADIOTAP ++++++++++++++++++ */
struct ieee80211_radiotap_header {
        u_int8_t        it_version;     // set to 0
        u_int8_t        it_pad;
        u_int16_t       it_len;         // entire length
        u_int32_t       it_present;     // fields present
} __attribute__((__packed__));

#define	IEEE80211_RADIOTAP_F_WEP	0x04	/* sent/received
						 * with WEP encryption
						 */
#define	IEEE80211_RADIOTAP_F_FRAG	0x08	//sent/received with fragmentation
#define	IEEE80211_RADIOTAP_F_FCS	0x10	// frame includes FCS
#define	IEEE80211_RADIOTAP_F_DATAPAD	0x20	// frame has padding between 802.11 header and payload (to 32-bit boundary)
#define IEEE80211_RADIOTAP_F_TX_NOACK	0x0008	// don't expect an ACK
/* ++++++++++++++++++++++++++++++++++++++ */

/* ++++++++++ UTILITY ++++++++++++++++++ */
#define HLEN_80211 24
#define ENCAPS_HDR_LEN 8

#define TYPE_LEN 2
#define ETH_ALEN 6
#define ETH_HLEN 14

#define IEEE80211_FCTL_TODS             0x0100
#define IEEE80211_FCTL_FROMDS           0x0200

#define SETBIT(ADDRESS,BIT) (ADDRESS |= (1<<BIT))
#define CLEARBIT(ADDRESS,BIT) (ADDRESS &= ~(1<<BIT))
#define CHECKBIT(ADDRESS,BIT) (ADDRESS & (1<<BIT))
/* ++++++++++++++++++++++++++++++++++++++ */

/* ++++++++++ UTILITY ++++++++++++++++++ */
//Bridge
extern u8 bridge_tunnel_header[];
/* Ethernet-II snap header (RFC1042 for most EtherTypes) */
extern u8 rfc1042_header[];
/* ++++++++++++++++++++++++++++++++++++++ */

int CWConvertDataFrame_8023_to_80211(unsigned char *frameReceived, int frameLen, unsigned char *outbuffer, int * WTPIndex);
CWBool CWConvertDataFrame_80211_to_8023(unsigned char *frameReceived, int frameLen, unsigned char *frame8023, int * frame8023Len);
CWBool checkAddressBroadcast(unsigned char * addr);
