/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	NL80211 Integration
 * 
 ***************************************/
 
#include "CWWTP.h"

struct WTPBSSInfo ** WTPGlobalBSSList;
#ifdef SPLIT_MAC
nodeAVL * avlTree = NULL;
CWThreadMutex mutexAvlTree;
#endif

CWBool CWWTPGetRadioGlobalInfo(void) {
	
	int err, indexPhy=0;
	int indexWlan;
	
	gRadiosInfo.radioCount = gPhyInterfaceCount;
	CW_CREATE_ARRAY_CALLOC_ERR(gRadiosInfo.radiosInfo, gRadiosInfo.radioCount, CWWTPRadioInfoValues, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	//Inizializza la variabile globale che conterrà tutte le bss presenti da questo WTP
	CW_CREATE_ARRAY_CALLOC_ERR(WTPGlobalBSSList, (WTP_MAX_INTERFACES*gRadiosInfo.radioCount), WTPBSSInfo *, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
#ifdef SPLIT_MAC
	CWCreateThreadMutex(&(mutexAvlTree));
#endif
	
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
	
	globalNLSock.ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (globalNLSock.ioctl_sock < 0) {
		CWLog("nl80211: socket(PF_INET,SOCK_DGRAM) failed: %s", strerror(errno));
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
		
		/*
		 * Retrocompatibilita. Da eliminare questo radioID in tutto il codice.
		 * il vero radioID sta nelle phyInfo
		 */
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
	
		
		CW_CREATE_ARRAY_CALLOC_ERR(gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.supportedRates, gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.lenSupportedRates, float, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		int indexRates;
		for(indexRates=0; indexRates < WTP_NL80211_BITRATE_NUM && gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.lenSupportedRates; indexRates++)
			gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.supportedRates[indexRates] = (char) mapSupportedRatesValues(gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.phyMbpsSet[indexRates], CW_80211_SUPP_RATES_CONVERT_VALUE_TO_FRAME);
			
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
				CWLog("NL80211: Error creating new bss. RadioID: %d, WLAN ID: %d", indexPhy, indexWlan);
				return CW_FALSE;
			}			
		}
	}
	
	CWLog("[80211 ERROR] bridge iface %s eth ifface: %s", gBridgeInterfaceName, gEthInterfaceName);

	int frameTunnelWTP = CWWTPGetFrameTunnelMode();
	//Local MAC impongo il bridgind locale: il WTP inoltra direttamente i pacchetti delle STA tramite un bridge
	if(frameTunnelWTP == CW_LOCAL_BRIDGING)
	{
		CWDelBridge(globalNLSock.ioctl_sock, gBridgeInterfaceName);
		
		if(!CWSetNewBridge(globalNLSock.ioctl_sock, gBridgeInterfaceName))
		{
			CWLog("[80211 ERROR] Cannot create bridge interface %s", gBridgeInterfaceName);
			return CW_FALSE;
		}
		
		ioctlActivateInterface(gBridgeInterfaceName);
	}
	//elena test now
	else if(frameTunnelWTP == CW_NATIVE_BRIDGING) {
		CW_CREATE_ARRAY_CALLOC_ERR(gRadiosInfo.radiosInfo[0].gWTPPhyInfo.monitorInterface.ifName, 9, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		snprintf(gRadiosInfo.radiosInfo[0].gWTPPhyInfo.monitorInterface.ifName, 9, "monitor0");	
		
		CWLog("CW_NATIVE_BRIDGING");
		if(!nl80211CmdSetNewMonitorInterface(0, &(gRadiosInfo.radiosInfo[0].gWTPPhyInfo.monitorInterface)))
			return CW_FALSE;
		
		if(!ioctlActivateInterface(gRadiosInfo.radiosInfo[0].gWTPPhyInfo.monitorInterface.ifName))
			return CW_FALSE;
	}
	
	return CW_TRUE;
}

CWBool CWWTPCreateNewWlanInterface(int radioID, int wlanID)//WTPInterfaceInfo * interfaceInfo)
{
	//pid_t wtpPid = getpid();
	
	//Create ifname: WTPWlan+radioID+wlanID+WTPpid
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
	int indexSTA, BSSId = getBSSIndex(radioIndex, wlanIndex);
	
	if(WTPGlobalBSSList[BSSId] != NULL)
		return CW_FALSE;
		
	CW_CREATE_OBJECT_ERR(WTPGlobalBSSList[BSSId], WTPBSSInfo, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	if(nl80211_init_socket(&(WTPGlobalBSSList[BSSId]->BSSNLSock)))
	{
		CWLog("[NL80211]: Error nl80211_init_socket");
		return CWErrorRaise(CW_ERROR_GENERAL, NULL);
	}
	
	if(netlink_create_socket(&(WTPGlobalBSSList[BSSId]->BSSNLSock)))
	{
		CWLog("[NL80211]: Error netlink_create_socket");
		return CWErrorRaise(CW_ERROR_GENERAL, NULL);
	}
	
	WTPGlobalBSSList[BSSId]->phyInfo = &(gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo);
	WTPGlobalBSSList[BSSId]->interfaceInfo = &(gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex]);
	
	WTPGlobalBSSList[BSSId]->active = CW_FALSE;
	
	WTPGlobalBSSList[BSSId]->numSTAActive = 0;
	CW_CREATE_ARRAY_CALLOC_ERR(WTPGlobalBSSList[BSSId]->staList, WTP_MAX_STA, WTPSTAInfo, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	for(indexSTA=0; indexSTA < WTP_MAX_STA; indexSTA++)
	{
		WTPGlobalBSSList[BSSId]->staList[indexSTA].state = CW_80211_STA_OFF;
		WTPGlobalBSSList[BSSId]->staList[indexSTA].address = NULL;
		WTPGlobalBSSList[BSSId]->staList[indexSTA].radioAdd = CW_FALSE;
	}
	
	CWCreateThreadMutex(&(WTPGlobalBSSList[BSSId]->bssMutex));
	WTPGlobalBSSList[BSSId]->destroyBSS = CW_FALSE;
	
	return CW_TRUE;
}

CWBool CWWTPDeleteBSS(int radioIndex, int wlanIndex)
{
	int indexSTA, BSSId = getBSSIndex(radioIndex, wlanIndex);
	
	CWLog("radioIndex: %d, wlanIndex; %d BSSId: %d", radioIndex, wlanIndex, BSSId);
	if(WTPGlobalBSSList[BSSId] == NULL)
		return CW_TRUE;
	
	//Destroy thread BSS
	CWThreadMutexLock(&(WTPGlobalBSSList[BSSId]->bssMutex));
	WTPGlobalBSSList[BSSId]->destroyBSS = CW_TRUE;
	CWThreadMutexUnlock(&(WTPGlobalBSSList[BSSId]->bssMutex));
	
	nl80211_cleanup_socket(&(WTPGlobalBSSList[BSSId]->BSSNLSock));

	CW_FREE_OBJECT((WTPGlobalBSSList[BSSId]->staList));
	
	CW_FREE_OBJECT(WTPGlobalBSSList[BSSId]);
	WTPGlobalBSSList[BSSId]=NULL;
	
	return CW_TRUE;
}

CWBool CWWTPSetAPInterface(int radioIndex, int wlanIndex, WTPInterfaceInfo * interfaceInfo)
{   
	if(interfaceInfo->typeInterface == CW_AP_MODE)
		return CW_TRUE;
	
	if(!nl80211CmdSetInterfaceAPType(interfaceInfo->ifName))
		return CW_FALSE;
	
	//BSSID == AP Address
	CW_CREATE_ARRAY_CALLOC_ERR(interfaceInfo->BSSID, ETH_ALEN+1, char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	CW_COPY_MEMORY(interfaceInfo->BSSID, interfaceInfo->MACaddr, ETH_ALEN);
	
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
	 
	//Setta nuova BSS
	int BSSId = getBSSIndex(radioIndex, wlanIndex);
	WTPGlobalBSSList[BSSId]->active = CW_TRUE;

	//Register mgmt functions
	if(CW80211SetAPTypeFrame(interfaceInfo, radioIndex, WTPGlobalBSSList[BSSId]) < 0)
		return CW_FALSE;

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
	
	//int tmpIndexif = if_nametoindex(gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex].ifName);
	/*IF_OPER_DOWN*/
	/*if(!netlink_send_oper_ifla(globalNLSock.sockNetlink, tmpIndexif, -1, 2 ))
		return CW_FALSE;
	*/
	
	CWLog("Dentro CWWTPDeleteWLANAPInterface. interface: %s", gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex].ifName);

	if(!nl80211CmdStopAP(gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex].ifName))
		return CW_FALSE;
		
	if(!nl80211CmdSetInterfaceSTAType(gRadiosInfo.radiosInfo[radioIndex].gWTPPhyInfo.interfaces[wlanIndex].ifName))
		return CW_FALSE;
	
	return CW_TRUE;
}

CWBool CWWTPAddNewStation(int BSSIndex, int STAIndex)
{	
	nodeAVL * tmpRoot;
	
	if(BSSIndex < 0 || BSSIndex >= (WTP_RADIO_MAX*WTP_MAX_INTERFACES) || STAIndex < 0 || STAIndex >= WTP_MAX_STA)
		return CW_FALSE;
	
	if(WTPGlobalBSSList[BSSIndex]->staList[STAIndex].address == NULL)
	{
		CWLog("[80211] This STA is no more in BSS. Probably it has send a Deauth/Disassoc frame");
		return CW_FALSE;
	}
	
	if(WTPGlobalBSSList[BSSIndex]->staList[STAIndex].radioAdd == CW_FALSE)
	{
		if(!nl80211CmdNewStation(WTPGlobalBSSList[BSSIndex], WTPGlobalBSSList[BSSIndex]->staList[STAIndex]))
			return CW_FALSE;
		WTPGlobalBSSList[BSSIndex]->staList[STAIndex].radioAdd = CW_TRUE;

#ifdef SPLIT_MAC
		//---- Insert new AVL node
		CWThreadMutexLock(&mutexAvlTree);
		tmpRoot = AVLinsert(BSSIndex, WTPGlobalBSSList[BSSIndex]->staList[STAIndex].address, WTPGlobalBSSList[BSSIndex]->interfaceInfo->MACaddr, WTPGlobalBSSList[BSSIndex]->phyInfo->radioID,avlTree);
		if(tmpRoot != NULL)
			avlTree = tmpRoot;
		CWThreadMutexUnlock(&mutexAvlTree);
		if(tmpRoot == NULL)
		{
			CWLog("NON aggiunto nell'AVL");
			return CW_FALSE;
		}
		//----
#endif
	}
	else
	{
		if(!nl80211CmdSetStation(WTPGlobalBSSList[BSSIndex], WTPGlobalBSSList[BSSIndex]->staList[STAIndex]))
			return CW_FALSE;
	}
		
	return CW_TRUE;
}

CWBool CWWTPDelStation(WTPBSSInfo * BSSInfo, WTPSTAInfo * staInfo)
{	
	nodeAVL * tmpRoot;
	int heightAVL=-1;
	
	if(staInfo->radioAdd == CW_FALSE)
		return CW_FALSE;
		
	if(!nl80211CmdDelStation(BSSInfo, staInfo->address))
	{
		CWLog("[CW80211] Problem deleting STA %02x:%02x:%02x:%02x:%02x:%02x", (int) staInfo->address[0], (int) staInfo->address[1], (int) staInfo->address[2], (int) staInfo->address[3], (int) staInfo->address[4], (int) staInfo->address[5]);
		return CW_FALSE;
	}
	
	staInfo->radioAdd=CW_FALSE;
	
#ifdef SPLIT_MAC
	//---- Delete AVL node
	CWThreadMutexLock(&mutexAvlTree);
//	heightAVL = AVLheight(avlTree);
	avlTree = AVLdeleteNode(avlTree, staInfo->address, BSSInfo->phyInfo->radioID);
	CWThreadMutexUnlock(&mutexAvlTree);
	/*if(
		tmpRoot != NULL && heightAVL > 1 ||
		tmpRoot == NULL && heightAVL == 1
	 )
		avlTree = tmpRoot;
	*/
	//----
#endif

	if(!delSTABySA(BSSInfo, staInfo->address))
	{
		CWLog("[CW80211] Problem deleting STA %02x:%02x:%02x:%02x:%02x:%02x", (int) staInfo->address[0], (int) staInfo->address[1], (int) staInfo->address[2], (int) staInfo->address[3], (int) staInfo->address[4], (int) staInfo->address[5]);
		return CW_FALSE;
	}
	
	CWLog("STA eliminata da WTP");
	return CW_TRUE;
}
