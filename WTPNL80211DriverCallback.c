/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	NL80211 Integration
 * 
 ***************************************/

#include "CWWTP.h"

/* ************************************ UTILS ********************************************* */
int ack_handler(struct nl_msg *msg, void *arg)
{
	int *err = arg;
	*err = 0;
	return NL_STOP;
}

int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_SKIP;
}

int ieee80211_frequency_to_channel(int freq)
{
	/* see 802.11-2007 17.3.8.3.2 and Annex J */
	if (freq == 2484)
		return 14;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq <= 45000) /* DMG band lower limit */
		return (freq - 5000) / 5;
	else if (freq >= 58320 && freq <= 64800)
		return (freq - 56160) / 2160;
	else
		return 0;
}

void mac_addr_n2a(char *mac_addr, unsigned char *arg)
{
	int i, l;

	l = 0;
	for (i = 0; i < ETH_ALEN ; i++) {
		if (i == 0) {
			sprintf(mac_addr+l, "%02x", arg[i]);
			l += 2;
		} else {
			sprintf(mac_addr+l, ":%02x", arg[i]);
			l += 3;
		}
	}
}

int mac_addr_a2n(unsigned char *mac_addr, char *arg)
{
	int i;

	for (i = 0; i < ETH_ALEN ; i++) {
		int temp;
		char *cp = strchr(arg, ':');
		if (cp) {
			*cp = 0;
			cp++;
		}
		if (sscanf(arg, "%x", &temp) != 1)
			return -1;
		if (temp < 0 || temp > 255)
			return -1;

		mac_addr[i] = temp;
		if (!cp)
			break;
		arg = cp;
	}
	if (i < ETH_ALEN - 1)
		return -1;

	return 0;
}

/* ****************************** GET ********************************* */
int CB_getPhyInfo(struct nl_msg *msg, void * arg) {
	
	struct WTPSinglePhyInfo * singlePhyInfo = (struct WTPSinglePhyInfo *) arg;
	CWBool phy2GH=CW_FALSE;
	CWBool phy5GH=CW_FALSE;
	
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
	struct nlattr *tb_rate[NL80211_BAND_ATTR_MAX + 1];
	
	static bool band_had_freq = false;
	
	struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
	static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
		[NL80211_FREQUENCY_ATTR_FREQ] = { .type = NLA_U32 },
		[NL80211_FREQUENCY_ATTR_DISABLED] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_NO_IR] = { .type = NLA_FLAG },
		[__NL80211_FREQUENCY_ATTR_NO_IBSS] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_RADAR] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .type = NLA_U32 },
	};
	static struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
		[NL80211_BITRATE_ATTR_RATE] = { .type = NLA_U32 },
		[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] = { .type = NLA_FLAG },
	};
	
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *nl_band;
	struct nlattr *nl_freq;
	struct nlattr *nl_rate;
	struct nlattr *nl_mode;
	struct nlattr *nl_cmd;
	struct nlattr *nl_if, *nl_ftype;
	int rem_band, rem_freq, rem_rate, rem_mode, rem_cmd, rem_ftype, rem_if;
	
	int indexFreq=0;
	int indexMbps=0;
	
	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
	
	if(tb_msg[NL80211_ATTR_WIPHY])
	{
		CWLog("[NL80211] PHY index: %d\n", nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]));
		singlePhyInfo->realRadioID=nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
	}
	if(tb_msg[NL80211_ATTR_WIPHY_NAME])
	{
		CWLog("[NL80211] PHY name: %s\n", nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]));
		CW_CREATE_STRING_FROM_STRING_ERR(singlePhyInfo->phyName, nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]), return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}
	
	//Default values
	singlePhyInfo->txMSDU = WTP_NL80211_DEFAULT_MSDU;
	singlePhyInfo->rxMSDU = WTP_NL80211_DEFAULT_MSDU;
	
	//Fragmentation Threshold
	if (tb_msg[NL80211_ATTR_WIPHY_FRAG_THRESHOLD]) {
		unsigned int frag;

		singlePhyInfo->fragmentationTreshold = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FRAG_THRESHOLD]);
		if (singlePhyInfo->fragmentationTreshold != (unsigned int)-1)
			CWLog("\tFragmentation threshold: %d\n", singlePhyInfo->fragmentationTreshold);
	}
	
	//FRTS Threshold
	if (tb_msg[NL80211_ATTR_WIPHY_RTS_THRESHOLD]) {
		unsigned int rts;

		singlePhyInfo->rtsThreshold = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_RTS_THRESHOLD]);
		if (singlePhyInfo->rtsThreshold != (unsigned int)-1)
			CWLog("\tRTS threshold: %d\n", singlePhyInfo->rtsThreshold);
	}

	singlePhyInfo->shortRetry=0;
	singlePhyInfo->longRetry=0;
	//Retry
	if (tb_msg[NL80211_ATTR_WIPHY_RETRY_SHORT] ||
	    tb_msg[NL80211_ATTR_WIPHY_RETRY_LONG]) {
		
		if (tb_msg[NL80211_ATTR_WIPHY_RETRY_SHORT])
			singlePhyInfo->shortRetry = nla_get_u8(tb_msg[NL80211_ATTR_WIPHY_RETRY_SHORT]);
		if (tb_msg[NL80211_ATTR_WIPHY_RETRY_LONG])
			singlePhyInfo->longRetry = nla_get_u8(tb_msg[NL80211_ATTR_WIPHY_RETRY_LONG]);
			CWLog("\tRetry short limit: %d\n", singlePhyInfo->shortRetry);
			CWLog("\tRetry long limit: %d\n", singlePhyInfo->longRetry);
	}
	
	/* needed for split dump */
	if (tb_msg[NL80211_ATTR_WIPHY_BANDS]) {
		nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band) {

			nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);
			
			if (tb_band[NL80211_BAND_ATTR_FREQS]) {
				if (!band_had_freq) {
					CWLog("[NL80211] Frequencies:\n");
					band_had_freq = true;
				}
				
				nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], rem_freq) {
					uint32_t freq;
					
					nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, nla_data(nl_freq), nla_len(nl_freq), freq_policy);
					
					if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
						continue;
				
					freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
					CWLog("\t\t\t* %d MHz [%d]", freq, ieee80211_frequency_to_channel(freq));
					
					if (tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] && !tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
						CWLog(" (%.1f dBm)", 0.01 * nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]));
						
					singlePhyInfo->phyFrequencyInfo.frequencyList[indexFreq].frequency = freq;
					singlePhyInfo->phyFrequencyInfo.frequencyList[indexFreq].channel = ieee80211_frequency_to_channel(freq);
					singlePhyInfo->phyFrequencyInfo.frequencyList[indexFreq].maxTxPower = ((0.01)*nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]));
					singlePhyInfo->phyFrequencyInfo.totChannels++;
					
					if(freq >= 2400 && freq <= 2500)
						phy2GH=CW_TRUE;
					else if(freq >= 4000 && freq <= 6000)
						phy5GH=CW_TRUE;
					else
					{
						phy2GH=CW_FALSE;
						phy5GH=CW_FALSE;
						break;
					}
					
					indexFreq++;
				}
				
				if(phy2GH == CW_TRUE)
					singlePhyInfo->phyStandard2400MH=CW_TRUE;
				else
					singlePhyInfo->phyStandard2400MH=CW_FALSE;
					
				if(phy5GH == CW_TRUE)
					singlePhyInfo->phyStandard5000MH=CW_TRUE;
				else
					singlePhyInfo->phyStandard5000MH=CW_FALSE;

				if (tb_band[NL80211_BAND_ATTR_RATES]) {
					
					CWLog("\t\tBitrates (non-HT):\n");
				
					nla_for_each_nested(nl_rate, tb_band[NL80211_BAND_ATTR_RATES], rem_rate) {
						nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX, nla_data(nl_rate), nla_len(nl_rate), rate_policy);
						if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
							continue;
						CWLog("\t\t\t* %2.1f Mbps", 0.1 * nla_get_u32(tb_rate[NL80211_BITRATE_ATTR_RATE]));
						if(indexMbps < WTP_NL80211_BITRATE_NUM)
						{		
							singlePhyInfo->phyMbpsSet[indexMbps] = (float) (0.1 * nla_get_u32(tb_rate[NL80211_BITRATE_ATTR_RATE]));
							//CWLog("NL80211_BITRATE_ATTR_MAX: %d, singlePhyInfo->phyMbpsSet[%d]: %f", NL80211_BITRATE_ATTR_MAX, indexMbps, singlePhyInfo->phyMbpsSet[indexMbps]);
							indexMbps++;
						}
					}
				}
				
				singlePhyInfo->phyHT20=CW_FALSE;
				singlePhyInfo->phyHT40=CW_FALSE;
				//Funzionalita HT20(set channel 20MHz)/HT40(set channel 40MHz) disponibili solo se supportato il 802.11n
				if (tb_msg[NL80211_ATTR_WIPHY_CHANNEL_TYPE]) {
					switch (nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_CHANNEL_TYPE])) {
					/*case NL80211_CHAN_NO_HT:
						printf("NL80211_CHAN_NO_HT\n");
						break;
					*/
					case NL80211_CHAN_HT20:
						singlePhyInfo->phyHT20=CW_TRUE;
						CWLog("NL80211_CHAN_HT20\n");
						break;
					case NL80211_CHAN_HT40PLUS:
						singlePhyInfo->phyHT40=CW_TRUE;
						CWLog("NL80211_CHAN_HT40PLUS\n");
						break;
					case NL80211_CHAN_HT40MINUS:
						singlePhyInfo->phyHT40=CW_TRUE;
						CWLog("NL80211_CHAN_HT40MINUS\n");
						break;
					}
				}
				
				/* 80211.a/b/g/n */
				int indexMbps;
				singlePhyInfo->phyStandardA = CW_FALSE;
				singlePhyInfo->phyStandardB = CW_FALSE;
				singlePhyInfo->phyStandardG = CW_FALSE;
				singlePhyInfo->phyStandardN = CW_FALSE;
				
				for(indexMbps=0; indexMbps < WTP_NL80211_BITRATE_NUM; indexMbps++)
				{
					//802.11b
					if(
						(singlePhyInfo->phyStandard2400MH==CW_TRUE && singlePhyInfo->phyStandardB == CW_FALSE) &&
						(
							(singlePhyInfo->phyMbpsSet[indexMbps] == 1.0) ||
							(singlePhyInfo->phyMbpsSet[indexMbps] == 2.0) ||
							(singlePhyInfo->phyMbpsSet[indexMbps] == 5.5) ||
							(singlePhyInfo->phyMbpsSet[indexMbps] == 11.0)
						)
					)
						singlePhyInfo->phyStandardB = CW_TRUE;
					
					//802.11g
					if(
						(singlePhyInfo->phyStandard2400MH==CW_TRUE && singlePhyInfo->phyStandardG == CW_FALSE) &&
						(
							(singlePhyInfo->phyMbpsSet[indexMbps] == 6.0) ||
							(singlePhyInfo->phyMbpsSet[indexMbps] == 9.0) ||
							(singlePhyInfo->phyMbpsSet[indexMbps] == 12.0) ||
							(singlePhyInfo->phyMbpsSet[indexMbps] == 18.0) ||
							(singlePhyInfo->phyMbpsSet[indexMbps] == 24.0) ||
							(singlePhyInfo->phyMbpsSet[indexMbps] == 36.0) ||
							(singlePhyInfo->phyMbpsSet[indexMbps] == 48.0) ||
							(singlePhyInfo->phyMbpsSet[indexMbps] == 54.0)
						)
					)
						singlePhyInfo->phyStandardG = CW_TRUE;
				}
				
				//802.11a
				if(singlePhyInfo->phyStandard5000MH==CW_TRUE)
					singlePhyInfo->phyStandardA = CW_TRUE;
									
				//802.11n
				if(
					( singlePhyInfo->phyStandard2400MH==CW_TRUE || singlePhyInfo->phyStandard5000MH==CW_TRUE ) &&
					( singlePhyInfo->phyHT20 == CW_TRUE || singlePhyInfo->phyHT40 == CW_TRUE )
				)
					singlePhyInfo->phyStandardA = CW_TRUE;
			}
				
		}
	}
}

int CB_getQoSValues(struct nl_msg *msg, void *arg)
{
	struct WTPQosValues *qosValues = arg;
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	
	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
	
	if (tb_msg[NL80211_TXQ_ATTR_CWMIN])
		qosValues->cwMin = nla_get_u16(tb_msg[NL80211_TXQ_ATTR_CWMIN]);
	
	if (tb_msg[NL80211_TXQ_ATTR_CWMAX])
		qosValues->cwMax = nla_get_u16(tb_msg[NL80211_TXQ_ATTR_CWMAX]);
	
	if (tb_msg[NL80211_TXQ_ATTR_AIFS])
		qosValues->AIFS = nla_get_u8(tb_msg[NL80211_TXQ_ATTR_AIFS]);
	
	return NL_SKIP;
}

/* ****************************** SET ********************************* */
int CB_setNewInterface(struct nl_msg *msg, void * arg) {
	WTPInterfaceInfo * interfaceInfo = (WTPInterfaceInfo *) arg;
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	
	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
	
	if(tb_msg[NL80211_ATTR_IFINDEX])
	{
		//Real WlanID assigned by mac80211 module
		interfaceInfo->realWlanID = nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]);
		CWLog("[NL80211] IFINDEX : %d\n", interfaceInfo->realWlanID);
	}
	
	
	//MAC address
	/*CW_CREATE_ARRAY_CALLOC_ERR(interfaceInfo->MACaddr, ETH_ALEN, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	if (tb_msg[NL80211_ATTR_MAC]) {
		CW_COPY_MEMORY(nla_data(tb_msg[NL80211_ATTR_MAC]), interfaceInfo->MACaddr, ETH_ALEN);
		/*char mac_addr[20];
		mac_addr_n2a(interfaceInfo->MACaddr, nla_data(tb_msg[NL80211_ATTR_MAC]));
		CWLog("MAC ADDR %s\n", mac_addr);
	}*/
	
	CWLog("CB_setNewInterface");
}

/* OTHERS */
int CB_startAP(struct nl_msg *msg, void * arg) {
	void * atr;
	
	CWLog("CB_startAP");
}
