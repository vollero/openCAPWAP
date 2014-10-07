/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	NL80211 Integration
 * 
 ***************************************/
 
#include "CWWTP.h"

struct WTPBSSInfo ** WTPGlobalBSSList;

CWBool CWWTPGetRadioGlobalInfo(void) {
	
	int err, indexPhy=0;
	int indexWlan;
	
	gRadiosInfo.radioCount = gPhyInterfaceCount;
	CW_CREATE_ARRAY_ERR(gRadiosInfo.radiosInfo, gRadiosInfo.radioCount, CWWTPRadioInfoValues, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	//Inizializza la variabile globale che conterrà tutte le bss presenti da questo WTP
	CW_CREATE_ARRAY_ERR(WTPGlobalBSSList, (WTP_MAX_INTERFACES*gRadiosInfo.radioCount), WTPBSSInfo *, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
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
		gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.radioID = CWIEEEBindingGetDevFromIndexID(indexPhy);
		gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.realRadioID = -1;
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
		
		if(gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.realRadioID == -1)
		{
			//free
			CW_FREE_OBJECT(gRadiosInfo.radiosInfo);
			CWLog("[NL80211 ERROR] Phy interface %d name: %s has some problems. WTP will stop.", indexPhy, gPhyInterfaceName[indexPhy]);
			return CW_FALSE;
		}
		
		gRadiosInfo.radiosInfo[indexPhy].radioID = CWIEEEBindingGetIndexFromDevID(gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.radioID);
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
		for(indexWlan=0; indexWlan < WTP_MAX_INTERFACES; indexWlan++)
		{
			if(!CWWTPCreateNewWlanInterface(indexPhy,  indexWlan))
			{
				CWLog("NL80211: Error creating new interface. RadioID: %d, WLAN ID: %d", indexPhy, indexWlan);
				return CW_FALSE;
			}	
			
			if(!CWWTPCreateNewBSS(indexPhy, indexWlan))
			{
				CWLog("NL80211: Error creating new interface. RadioID: %d, WLAN ID: %d", indexPhy, indexWlan);
				return CW_FALSE;
			}			
		}
	}
	
	return CW_TRUE;
}

CWBool CWWTPCreateNewWlanInterface(int radioID, int wlanID)//WTPInterfaceInfo * interfaceInfo)
{
	//Create ifname: WTPWlan+radioID+wlanID
	CW_CREATE_ARRAY_CALLOC_ERR(gRadiosInfo.radiosInfo[radioID].gWTPPhyInfo.interfaces[wlanID].ifName, (WTP_NAME_WLAN_PREFIX_LEN+WTP_NAME_WLAN_SUFFIX_LEN+1), char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	snprintf(gRadiosInfo.radiosInfo[radioID].gWTPPhyInfo.interfaces[wlanID].ifName, (WTP_NAME_WLAN_PREFIX_LEN+WTP_NAME_WLAN_SUFFIX_LEN+1), "%s%d%d", WTP_NAME_WLAN_PREFIX, radioID, wlanID);
	
	if(!nl80211CmdSetNewInterface(radioID, &(gRadiosInfo.radiosInfo[radioID].gWTPPhyInfo.interfaces[wlanID])))
		return CW_FALSE;
	   
	gRadiosInfo.radiosInfo[radioID].gWTPPhyInfo.interfaces[wlanID].typeInterface = CW_STA_MODE;
	//RFC wlanID > 0
	gRadiosInfo.radiosInfo[radioID].gWTPPhyInfo.interfaces[wlanID].wlanID = CWIEEEBindingGetDevFromIndexID(wlanID);
	
	return CW_TRUE;
}

int getBSSIndex(int radioID, int wlanID) {
	return radioID + wlanID;
}

CWBool CWWTPCreateNewBSS(int radioIndex, int wlanIndex)
{
	int BSSId = getBSSIndex(radioIndex, wlanIndex);
	
	CW_CREATE_OBJECT_ERR(WTPGlobalBSSList[BSSId], WTPBSSInfo, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	if(nl80211_init_socket(&(WTPGlobalBSSList[BSSId]->interfaceNLSock)))
	{
		CWLog("[NL80211]: Error nl80211_init_socket");
		return CWErrorRaise(CW_ERROR_GENERAL, NULL);
	}
	
	if(netlink_create_socket(&(WTPGlobalBSSList[BSSId]->interfaceNLSock)))
	{
		CWLog("[NL80211]: Error netlink_create_socket");
		return CWErrorRaise(CW_ERROR_GENERAL, NULL);
	}
	
	WTPGlobalBSSList[BSSId]->radioInfo = &(gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo);
	WTPGlobalBSSList[BSSId]->interfaceInfo = &(gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex]);
	
	WTPGlobalBSSList[BSSId]->active = CW_FALSE;
	WTPGlobalBSSList[BSSId]->numSTAActive = 0;
	
	return CW_TRUE;
}

CWBool CWWTPSetAPInterface(int radioIndex, int wlanIndex, WTPInterfaceInfo * interfaceInfo)
{    
	/*  
	if (eloop_init()) {
		CWLog("Failed to initialize event loop");
		return -1;
	}
	*/
	if(!nl80211CmdSetInterfaceAPType(interfaceInfo->ifName))
		return CW_FALSE;
		
	if(!ioctlActivateInterface(interfaceInfo->ifName))
		return CW_FALSE;
	
	if(!nl80211CmdSetChannelInterface(interfaceInfo->ifName, gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.phyFrequencyInfo.frequencyList[CW_WTP_DEFAULT_RADIO_CHANNEL].frequency))
		return CW_FALSE;
	
	if(!nl80211CmdStartAP(interfaceInfo))
		return CW_FALSE;
	  
	int tmpIndexif = if_nametoindex(interfaceInfo->ifName);
	if(!netlink_send_oper_ifla(globalNLSock.sockNetlink, tmpIndexif, -1, IF_OPER_UP))
		return CW_FALSE;
	
	interfaceInfo->typeInterface = CW_AP_MODE;
	  
	if(!nl80211_set_bss(interfaceInfo, 1, 1))
		return CW_FALSE;
	 
	//Register mgmt functions
	if(CW80211SetAPTypeFrame(interfaceInfo, radioIndex) < 0)
		return CW_FALSE;
	
	//Setta nuova BSS
	int BSSId = getBSSIndex(radioIndex, wlanIndex);
	WTPGlobalBSSList[BSSId]->active = CW_TRUE;

	if(!CWErr(CWCreateThread(&(WTPGlobalBSSList[BSSId]->threadBSS), CWWTPBSSManagement, WTPGlobalBSSList[BSSId]))) {
		CWLog("Error starting Thread that receive binding frame");
		exit(1);
	}
	
	return CW_TRUE;
}

CWBool CWWTPDeleteWLANAPInterface(int radioIndex, int wlanIndex)
{
	/*
	if(!nl80211CmdDelInterface(radioIndex, wlanIndex))
		return CW_FALSE;
	*/
	
	int tmpIndexif = if_nametoindex(gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex].ifName);
	/*IF_OPER_DOWN*/
	/*if(!netlink_send_oper_ifla(globalNLSock.sockNetlink, tmpIndexif, -1, 2 ))
		return CW_FALSE;
	*/
	
	CWLog("Dentro CWWTPDeleteWLANAPInterface. interfaace: %s", gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex].ifName);
	if(!nl80211CmdSetInterfaceSTAType(gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex].ifName))
		return CW_FALSE;
	/*
	if(!netlink_send_oper_ifla(globalNLSock.sockNetlink, tmpIndexif, -1, IF_OPER_UP))
		return CW_FALSE;
	*/
	return CW_TRUE;
}
