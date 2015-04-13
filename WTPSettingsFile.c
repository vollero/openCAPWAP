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
 * In addition, as a special exception, the copyright holders give permission to link the  *
 * code of portions of this program with the OpenSSL library under certain conditions as   *
 * described in each individual source file, and distribute linked combinations including  * 
 * the two. You must obey the GNU General Public License in all respects for all of the    *
 * code used other than OpenSSL.  If you modify file(s) with this exception, you may       *
 * extend this exception to your version of the file(s), but you are not obligated to do   *
 * so.  If you do not wish to do so, delete this exception statement from your version.    *
 * If you delete this exception statement from all source files in the program, then also  *
 * delete it here.                                                                         *
 * 
 * --------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                        *
 *                                                                                         *
 * Author :  Ludovico Rossi (ludo@bluepixysw.com)                                          *  
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                    *
 *           Giovannini Federica (giovannini.federica@gmail.com)                           *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                    *
 *           Mauro Bisson (mauro.bis@gmail.com)                                            *
 *******************************************************************************************/


#include "CWCommon.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

#define CW_SETTINGS_FILE 	"settings.wtp.txt"

FILE* gSettingsFile=NULL;
char* gInterfaceName=NULL;
char* gEthInterfaceName=NULL;
char* gBridgeInterfaceName=NULL;
char* gRadioInterfaceName_0=NULL;
char* gBaseMACInterfaceName=NULL;
char  gBoardReversionNo;

//Elena Agostini - 07/2014: nl80211 support
int gPhyInterfaceCount;
char ** gPhyInterfaceName=NULL;
int * gPhyInterfaceIndex=NULL;


/*
 * Elena Agostini - 02/2014
 *
 * QoS Static Values variables
 */
int qosStaticFreq;
int qosStaticBitRate;
int qosStaticFrag;
int qosStaticTxPower;
int qosStaticCwMin;
int qosStaticCwMax;
int qosStaticAifs;
int qosStaticWmeCwMin;
int qosStaticWmeCwMax;
int qosStaticWmeAifsn;

int gHostapd_port;
char*  gHostapd_unix_path;

void CWExtractValue(char* start, char** startValue, char** endValue, int* offset)
{
	*offset=strspn (start+1, " \t\n\r");
	*startValue = start +1+ *offset;

	*offset=strcspn (*startValue, " \t\n\r");
	*endValue = *startValue + *offset -1;
}

CWBool CWParseSettingsFile()
{
	char *line = NULL;
	int indexPhy=0;
	
	gSettingsFile = fopen (CW_SETTINGS_FILE, "rb");
	if (gSettingsFile == NULL) {
		CWErrorRaiseSystemError(CW_ERROR_GENERAL);
	}
	
	while((line = (char*)CWGetCommand(gSettingsFile)) != NULL) 
	{
		char* startTag=NULL;
		char* endTag=NULL;
		
		if((startTag=strchr (line, '<'))==NULL) 
		{
			CW_FREE_OBJECT(line);
			continue;
		}

		if((endTag=strchr (line, '>'))==NULL) 
		{
			CW_FREE_OBJECT(line);
			continue;
		}
		
		//Elena Agostini - 05/2014: Single log_file foreach WTP
		if (!strncmp(startTag+1, "LOG_FILE_WTP", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;

			CWExtractValue(endTag, &startValue, &endValue, &offset);
			
			CW_CREATE_STRING_ERR(wtpLogFile, offset, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL););
			strncpy(wtpLogFile, startValue, offset);
			wtpLogFile[offset] ='\0';
			CWLog(": %s", wtpLogFile);
			CW_FREE_OBJECT(line);
			continue;	
		}

		//Elena Agostini - 07/2014: nl80211 support
		if (!strncmp(startTag+1, "RADIO_PHY_TOT", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			char port_str[16];

			CWExtractValue(endTag, &startValue, &endValue, &offset);
		
			strncpy(port_str, startValue, offset);
			port_str[offset] ='\0';
			gPhyInterfaceCount = atoi(port_str);
			if(gPhyInterfaceCount > 0)
			{
				CW_CREATE_ARRAY_ERR(gPhyInterfaceName, gPhyInterfaceCount, char *, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL);)
				CW_CREATE_ARRAY_ERR(gPhyInterfaceIndex, gPhyInterfaceCount, int, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL);)
			}	
			CW_FREE_OBJECT(line);
			continue;
		}
		
		//Elena Agostini - 07/2014: nl80211 support
		if (!strncmp(startTag+1, "RADIO_PHY_NAME_", endTag-startTag-1-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			
			CWExtractValue(endTag, &startValue, &endValue, &offset);
			
			int endValueInt = atoi(endValue);
			if(indexPhy < gPhyInterfaceCount && gPhyInterfaceName != NULL)
			{
				//phy1 -> endvalue 1
				gPhyInterfaceIndex[indexPhy] = endValueInt;
				CW_CREATE_STRING_ERR(gPhyInterfaceName[indexPhy], offset, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL););
				strncpy(gPhyInterfaceName[indexPhy], startValue, offset);
				gPhyInterfaceName[indexPhy][offset] ='\0';
				CW_FREE_OBJECT(line);
				indexPhy++;
			}
			
			continue;
		}
		
		if (!strncmp(startTag+1, "IF_NAME", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;

			CWExtractValue(endTag, &startValue, &endValue, &offset);

			CW_CREATE_STRING_ERR(gInterfaceName, offset, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL););
			strncpy(gInterfaceName, startValue, offset);
			gInterfaceName[offset] ='\0';
			CWLog(": %s", gInterfaceName);
			CW_FREE_OBJECT(line);
			continue;	
		}

		if (!strncmp(startTag+1, "IF_NAME", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;

			CWExtractValue(endTag, &startValue, &endValue, &offset);

			CW_CREATE_STRING_ERR(gInterfaceName, offset, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL););
			strncpy(gInterfaceName, startValue, offset);
			gInterfaceName[offset] ='\0';
			CWLog(": %s", gInterfaceName);
			CW_FREE_OBJECT(line);
			continue;	
		}
		
		if (!strncmp(startTag+1, "WTP_ETH_IF_NAME", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;

			CWExtractValue(endTag, &startValue, &endValue, &offset);

			CW_CREATE_STRING_ERR(gEthInterfaceName, offset, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL););
			strncpy(gEthInterfaceName, startValue, offset);
			gEthInterfaceName[offset] ='\0';
			CWLog(": %s", gEthInterfaceName);
			CW_FREE_OBJECT(line);
			continue;	
		}		
		
		//Elena Agostini 11/2014: Local Bridgind support with mac80211
		if (!strncmp(startTag+1, "BRIDGE_IF_NAME", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;

			CWExtractValue(endTag, &startValue, &endValue, &offset);

			CW_CREATE_STRING_ERR(gBridgeInterfaceName, offset, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL););
			strncpy(gBridgeInterfaceName, startValue, offset);
			gBridgeInterfaceName[offset] ='\0';
			CWLog(": %s", gBridgeInterfaceName);
			CW_FREE_OBJECT(line);
			continue;	
		}	
		
		if (!strncmp(startTag+1, "RADIO_0_IF_NAME", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;

			CWExtractValue(endTag, &startValue, &endValue, &offset);

			CW_CREATE_STRING_ERR(gRadioInterfaceName_0, offset, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL););
			strncpy(gRadioInterfaceName_0, startValue, offset);
			gRadioInterfaceName_0[offset] ='\0';
			CWLog(": %s", gRadioInterfaceName_0);
			CW_FREE_OBJECT(line);
			continue;	
		}		

		if (!strncmp(startTag+1, "BASE_MAC_IF_NAME", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;

			CWExtractValue(endTag, &startValue, &endValue, &offset);

			CW_CREATE_STRING_ERR(gBaseMACInterfaceName, offset, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL););
			strncpy(gBaseMACInterfaceName, startValue, offset);
			gBaseMACInterfaceName[offset] ='\0';
			CWLog(": %s", gBaseMACInterfaceName);
			CW_FREE_OBJECT(line);
			continue;	
		}		

		if (!strncmp(startTag+1, "BOARD_REVISION_NO", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			char reversion[16];

			CWExtractValue(endTag, &startValue, &endValue, &offset);
		
			strncpy(reversion, startValue, offset);
			reversion[offset] ='\0';
			gBoardReversionNo = atoi(reversion);
			CWLog(": %d",gBoardReversionNo);
			CW_FREE_OBJECT(line);
			continue;	
		}
		if (!strncmp(startTag+1, "WTP_HOSTAPD_PORT", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			char port_str[16];

			CWExtractValue(endTag, &startValue, &endValue, &offset);
		
			strncpy(port_str, startValue, offset);
			port_str[offset] ='\0';
			gHostapd_port = atoi(port_str);
			CWLog(": %d",gHostapd_port);
			CW_FREE_OBJECT(line);
			continue;		
		}
		if (!strncmp(startTag+1, "WTP_HOSTAPD_UNIX_PATH", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;

			CWExtractValue(endTag, &startValue, &endValue, &offset);

			CW_CREATE_STRING_ERR(gHostapd_unix_path, offset, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL););
			strncpy(gHostapd_unix_path, startValue, offset);
			gHostapd_unix_path[offset] ='\0';
			CWLog(": %s", gHostapd_unix_path);
			CW_FREE_OBJECT(line);
			continue;	
		}


		/*
		 * Elena Agostini - 02/2014
		 *
		 * QoS Static Values variables
		 */
		if (!strncmp(startTag+1, "WTP_QOS_FREQ", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			char port_str[16];

			CWExtractValue(endTag, &startValue, &endValue, &offset);
		
			strncpy(port_str, startValue, offset);
			port_str[offset] ='\0';
			qosStaticFreq = atoi(port_str);
			CWLog("qosStaticFreq: %d",qosStaticFreq);
			CW_FREE_OBJECT(line);
			continue;	
		}

		if (!strncmp(startTag+1, "WTP_QOS_BITRATE", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			char port_str[16];

			CWExtractValue(endTag, &startValue, &endValue, &offset);
		
			strncpy(port_str, startValue, offset);
			port_str[offset] ='\0';
			qosStaticBitRate = atoi(port_str);
			CWLog("qosStaticBitRate: %d",qosStaticBitRate);
			CW_FREE_OBJECT(line);
			continue;	
		}

		if (!strncmp(startTag+1, "WTP_QOS_FRAG", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			char port_str[16];

			CWExtractValue(endTag, &startValue, &endValue, &offset);
		
			strncpy(port_str, startValue, offset);
			port_str[offset] ='\0';
			qosStaticFrag = atoi(port_str);
			CWLog("qosStaticFrag: %d",qosStaticFrag);
			CW_FREE_OBJECT(line);
			continue;	
		}

		if (!strncmp(startTag+1, "WTP_QOS_TXPOWER", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			char port_str[16];

			CWExtractValue(endTag, &startValue, &endValue, &offset);
		
			strncpy(port_str, startValue, offset);
			port_str[offset] ='\0';
			qosStaticTxPower = atoi(port_str);
			CWLog("qosStaticTxPower: %d",qosStaticTxPower);
			CW_FREE_OBJECT(line);
			continue;	
		}

		if (!strncmp(startTag+1, "WTP_QOS_CWMIN", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			char port_str[16];

			CWExtractValue(endTag, &startValue, &endValue, &offset);
		
			strncpy(port_str, startValue, offset);
			port_str[offset] ='\0';
			qosStaticCwMin = atoi(port_str);
			CWLog("qosStaticCwMin: %d",qosStaticCwMin);
			CW_FREE_OBJECT(line);
			continue;	
		}

		if (!strncmp(startTag+1, "WTP_QOS_CWMAX", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			char port_str[16];

			CWExtractValue(endTag, &startValue, &endValue, &offset);
		
			strncpy(port_str, startValue, offset);
			port_str[offset] ='\0';
			qosStaticCwMax = atoi(port_str);
			CWLog("qosStaticCwMax: %d",qosStaticCwMax);
			CW_FREE_OBJECT(line);
			continue;	
		}

		if (!strncmp(startTag+1, "WTP_QOS_AIFS", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			char port_str[16];

			CWExtractValue(endTag, &startValue, &endValue, &offset);
		
			strncpy(port_str, startValue, offset);
			port_str[offset] ='\0';
			qosStaticAifs = atoi(port_str);
			CWLog("qosStaticAifs: %d",qosStaticAifs);
			CW_FREE_OBJECT(line);
			continue;	
		}

		if (!strncmp(startTag+1, "WTP_QOS_WME_CWMIN", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			char port_str[16];

			CWExtractValue(endTag, &startValue, &endValue, &offset);
		
			strncpy(port_str, startValue, offset);
			port_str[offset] ='\0';
			qosStaticWmeCwMin = atoi(port_str);
			CWLog("qosStaticWmeCwMin: %d",qosStaticWmeCwMin);
			CW_FREE_OBJECT(line);
			continue;	
		}

		if (!strncmp(startTag+1, "WTP_QOS_WME_CWMAX", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			char port_str[16];

			CWExtractValue(endTag, &startValue, &endValue, &offset);
		
			strncpy(port_str, startValue, offset);
			port_str[offset] ='\0';
			qosStaticWmeCwMax = atoi(port_str);
			CWLog("qosStaticWmeCwMax: %d",qosStaticWmeCwMax);
			CW_FREE_OBJECT(line);
			continue;	
		}

		if (!strncmp(startTag+1, "WTP_QOS_AIFSN", endTag-startTag-1))
		{
			char* startValue=NULL;
			char* endValue=NULL;
			int offset = 0;
			char port_str[16];

			CWExtractValue(endTag, &startValue, &endValue, &offset);
		
			strncpy(port_str, startValue, offset);
			port_str[offset] ='\0';
			qosStaticWmeAifsn = atoi(port_str);
			CWLog("qosStaticAifsn: %d",qosStaticWmeAifsn);
			CW_FREE_OBJECT(line);
			continue;	
		}
		CW_FREE_OBJECT(line);
	}
	
	//Elena Agostini - 07/2014: nl80211 support
	if(gPhyInterfaceCount == 0)
	{
		fprintf(stderr, "WTP ERROR: RADIO_PHY_TOT is 0");
		return CW_FALSE;
	}
	
	if(gPhyInterfaceName == NULL)
	{
		fprintf(stderr, "WTP ERROR: you have to put RADIO_PHY_TOT before RADIO_PHY_NAME_X");
		return CW_FALSE;
	}
	
	if(!gPhyInterfaceName[0])
	{
		fprintf(stderr, "WTP ERROR: no RADIO_PHY_NAME_X detected");
		return CW_FALSE;
	}

	if(CWWTPGetFrameTunnelMode() == CW_LOCAL_BRIDGING && gBridgeInterfaceName == NULL)
	{
		fprintf(stderr, "WTP ERROR: no BRIDGE INTERFACE NAME detected");
		return CW_FALSE;
	}
		
	return CW_TRUE;
}
