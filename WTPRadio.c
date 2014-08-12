/**************************************
 * 
 *  Elena Agostini elena.ago@gmail.com
 * 	NL80211 Integration
 * 
 ***************************************/
 
#include "CWWTP.h"

CWBool CWWTPGetRadioGlobalInfo(void) {
	
	int err, indexPhy=0;
	
	gRadiosInfo.radioCount = gPhyInterfaceCount;
	CW_CREATE_ARRAY_ERR(gRadiosInfo.radiosInfo, gRadiosInfo.radioCount, CWWTPRadioInfoValues, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	err = nl80211_init_socket(&(globalNLSock));
	if(err != 0)
	{
		CWLog("[NL80211]: Error nl80211_init_socket: %d", err);
		return CWErrorRaise(CW_ERROR_GENERAL, NULL);
	}
	
	for(indexPhy=0; indexPhy < gRadiosInfo.radioCount; indexPhy++)
	{
		CWLog("[NL80211] Retrieving info for phy interface %d name: %s ...", indexPhy, gPhyInterfaceName[indexPhy]);
		gRadiosInfo.radiosInfo[indexPhy].gWTPPhyInfo.radioID = -1;
		
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
	}
	
	return CW_TRUE;
}
