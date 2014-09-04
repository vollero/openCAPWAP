/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	NL80211 Integration
 * 
 ***************************************/
 
#include "CWWTP.h"

CWBool CWWTPGetRadioGlobalInfo(void) {
	
	int err, indexPhy=0;
	int index;
	
	gRadiosInfo.radioCount = gPhyInterfaceCount;
	CW_CREATE_ARRAY_ERR(gRadiosInfo.radiosInfo, gRadiosInfo.radioCount, CWWTPRadioInfoValues, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	err = nl80211_init_socket(&(globalNLSock));
	if(err != 0)
	{
		CWLog("[NL80211]: Error nl80211_init_socket: %d", err);
		return CWErrorRaise(CW_ERROR_GENERAL, NULL);
	}
	
	err = nl80211_init_socket(&(globalNLSock));
	if(err != 0)
	{
		CWLog("[NL80211]: Error nl80211_init_socket: %d", err);
		return CWErrorRaise(CW_ERROR_GENERAL, NULL);
	}
	
	err = netlink_create_socket(&(globalNLSock));
	if(err != 0)
	{
		CWLog("[NL80211]: Error netlink_create_socket: %d", err);
		return CWErrorRaise(CW_ERROR_GENERAL, NULL);
	}
	
	for(indexPhy=0; indexPhy < gRadiosInfo.radioCount; indexPhy++)
	{
		CWLog("[NL80211] Retrieving info for phy interface %d name: %s ...", indexPhy, gPhyInterfaceName[indexPhy]);
		gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.radioID = -1;
		//Not best practice with define
		//Frequencies array
		CW_CREATE_ARRAY_CALLOC_ERR(gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyFrequencyInfo.frequencyList, WTP_NL80211_CHANNELS_NUM, PhyFrequencyInfoList, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyFrequencyInfo.totChannels = 0;
		//Bitrate array
		CW_CREATE_ARRAY_CALLOC_ERR(gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyMbpsSet, WTP_NL80211_BITRATE_NUM, float, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		
		//Info about all phy info
		if(nl80211CmdGetPhyInfo(indexPhy, &(gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo)) == CW_FALSE)
		{
			CWLog("[NL80211 ERROR] Phy interface %d name: %s has some problems. WTP will stop.", indexPhy, gPhyInterfaceName[indexPhy]);
			return CW_FALSE;
		}
		
		if(gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.radioID == -1)
		{
			//free
			CW_FREE_OBJECT(gRadiosInfo.radiosInfo);
			CWLog("[NL80211 ERROR] Phy interface %d name: %s has some problems. WTP will stop.", indexPhy, gPhyInterfaceName[indexPhy]);
			return CW_FALSE;
		}
		
		gRadiosInfo.radiosInfo[indexPhy].radioID = gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.radioID;
		/* gRadiosInfo.radiosInfo[i].numEntries = 0; */
		gRadiosInfo.radiosInfo[indexPhy].decryptErrorMACAddressList = NULL;
		gRadiosInfo.radiosInfo[indexPhy].reportInterval= CW_REPORT_INTERVAL_DEFAULT;
		/* Default value for CAPWAP */
		gRadiosInfo.radiosInfo[indexPhy].adminState= ENABLED; 
		gRadiosInfo.radiosInfo[indexPhy].adminCause= AD_NORMAL;
		gRadiosInfo.radiosInfo[indexPhy].operationalState= DISABLED;
		gRadiosInfo.radiosInfo[indexPhy].operationalCause= OP_NORMAL;
		gRadiosInfo.radiosInfo[indexPhy].TxQueueLevel= 0;
		gRadiosInfo.radiosInfo[indexPhy].wirelessLinkFramesPerSec= 0;
		CWWTPResetRadioStatistics(&(gRadiosInfo.radiosInfo[indexPhy].statistics));
		
		
		//802.11a/b/g/n total value
		gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyStandardValue=PHY_NO_STANDARD;
		if(gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyStandardA == CW_TRUE)
			gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyStandardValue += PHY_STANDARD_A;
		if(gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyStandardB == CW_TRUE)
			gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyStandardValue += PHY_STANDARD_B;
		if(gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyStandardG == CW_TRUE)
			gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyStandardValue += PHY_STANDARD_G;
		if(gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyStandardN == CW_TRUE)
			gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyStandardValue += PHY_STANDARD_N;

		if(!CWWTPInitBinding(indexPhy)) {return CW_FALSE;}
		
		gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.numInterfaces=0;
		for(index=0; index < WTP_MAX_INTERFACES; index++)
		{
			gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.interfaces[index].wlanID = -1;
			gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.interfaces[index].realWlanID = -1;
		}
	}
	
	return CW_TRUE;
}

CWBool CWWTPCreateNewWlanInterface(int radioID, WTPInterfaceInfo * interfaceInfo)
{
	CWLog("CWWTPCreateNewWlanInterface radioID: %d, ifName: %s", radioID, interfaceInfo->ifName);
	if(!nl80211CmdSetNewInterface(radioID, interfaceInfo))
		return CW_FALSE;
	
	//Elena: some mac80211 module require a little bit of time for activate new interface. How to resolve it better?
	sleep(3);
	
	if(!nl80211CmdSetInterfaceAPType(interfaceInfo->ifName))
		return CW_FALSE;
		
	if(!ioctlActivateInterface(interfaceInfo->ifName))
		return CW_FALSE;
	
	if(!nl80211CmdSetChannelInterface(interfaceInfo->ifName, gRadiosInfo.radiosInfo[radioID].gWTPPhyInfo.phyFrequencyInfo.frequencyList[CW_WTP_DEFAULT_RADIO_CHANNEL].frequency))
		return CW_FALSE;
	
	if(!nl80211CmdStartAP(interfaceInfo))
		return CW_FALSE;
	
	int tmpIndexif = if_nametoindex(interfaceInfo->ifName);
	if(!netlink_send_oper_ifla(globalNLSock.sockNetlink, tmpIndexif, -1, IF_OPER_UP))
		return CW_FALSE;
	
	return CW_TRUE;
}

CWBool CWWTPDeleteWlanInterface(int radioID, int wlanID)
{
	if(!nl80211CmdDelInterface(radioID, wlanID))
		return CW_FALSE;
	
	return CW_TRUE;
}
