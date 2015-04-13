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


#include "CWWTP.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

#define SIOCIWFIRSTPRIV			0x8BE0
#define IEEE80211_IOCTL_SETWMMPARAMS 	(SIOCIWFIRSTPRIV+4)
#define IEEE80211_IOCTL_GETWMMPARAMS 	(SIOCIWFIRSTPRIV+5)
#define IEEE80211_WMMPARAMS_CWMIN	1
#define IEEE80211_WMMPARAMS_CWMAX	2
#define IEEE80211_WMMPARAMS_AIFS	3


/*
 * Elena Agostini - 02/2014
 * 
 * No more ioctl() on wireless drivers. Those function simulate ioctl() query to wireless drivers
 * returning settings file params.
 * API coming soon..
 */

/**************************** iwconfig ****************************/
/*--------------------------- Frequency ---------------------------*/
int set_freq(int sock, struct iwreq wrq, int value)
{
	//CWLog("Frequensta impostata a: %d", qosStaticFreq);
	return 1;
}

int get_freq(int sock, struct iwreq* wrq)
{
	//CWLog("Frequensta impostata a: %d", qosStaticFreq);
	return 1;
}

/*--------------------------- Bit rate ---------------------------*/
int set_bitrate(int sock, struct iwreq wrq, int value)
{
      	//CWLog("nBit rate impostata a: %d", qosStaticBitRate);
	return 1;
}

int get_bitrate(int sock, struct iwreq* wrq)
{
	//CWLog("nBit rate impostata a: %d", qosStaticBitRate);
	return 1;
}

/*--------------------------- Fragmentation Threshold ---------------------------*/
int set_frag(int sock, struct iwreq wrq, int value)
{
	//CWLog("\nFragmentation threshold impostato a: %d", qosStaticFrag);
	return 1;
}

int get_frag(int sock, struct iwreq* wrq)
{
	//CWLog("Fragmentation threshold: %d", qosStaticFrag);
      	return 1;
}

extern int qosStaticTxq;
extern int ;
extern int qosStaticWmeCwMax;
extern int qosStaticAifsn;

/*--------------------------- Transmit Power ---------------------------*/
int set_txpower(int sock, struct iwreq wrq, int value)
{
	//CWLog("Transmit power impostato a: %d", qosStaticTxPower);
	return 1;
}

int get_txpower(int sock, struct iwreq* wrq)
{
	//CWLog("Transmit power: %d", qosStaticTxPower);
	return 1;
}

/**************************** iwpriv ****************************/
/*--------------------------- CWMIN ---------------------------*/
int set_cwmin(int sock, struct iwreq wrq, int acclass, int sta, int value)
{
	//CWLog("nCWMIN impostato a: %d", qosStaticCwMin);
	return 1;
}

int get_cwmin(int sock, struct iwreq* wrq, int acclass, int sta)
{
	//CWLog("nCWMIN a: %d\n", qosStaticCwMin);
	return 1;
}

/*--------------------------- CWMAX ---------------------------*/
int set_cwmax(int sock, struct iwreq wrq, int acclass, int sta, int value)
{
	//CWLog("nCWMAX impostato a: %d", qosStaticCwMax);
	return 1;
}

int get_cwmax(int sock, struct iwreq* wrq, int acclass, int sta)
{
	//CWLog("nCWMAX a: %d", qosStaticCwMax);
	return 1;
}

/*--------------------------- AIFS ---------------------------*/
int set_aifs(int sock, struct iwreq wrq, int acclass, int sta, int value)
{
	//CWLog("nAIFS impostato a: %d", qosStaticAifs);
	return 1;
}

int get_aifs(int sock, struct iwreq* wrq, int acclass, int sta)
{
	//CWLog("nAIFS a: %d\n", qosStaticAifs);
	return 1;
}

/*
int set_txq(int code, int cwmin, int cwmax, int aifs, int burst_time)
{
	char str[32];
	sprintf(str,"X%d %d %d %d %d", code, cwmin, cwmax, aifs, burst_time);
	
	CWWTPsend_command_to_hostapd_SET_TXQ(str, strlen(str));
	return 1;
}
*/

/* +++++++++++++++ SOFTMAC ++++++++++++++++ */
/*set CWMIN*/
int set_wme_cwmin(int class,int value){

	printf("\nCWMIN impostato a: %d", qosStaticWmeCwMin);
	return 1;
}

/*set CWMAX*/
int set_wme_cwmax(int class,int value){

	printf("\nCWMAX impostato a: %d", qosStaticWmeCwMax);
	return 1;
}

/*set AIFSN*/
int set_wme_aifsn(int class,int value){

	printf("\nAIFSN impostato a: %d", qosStaticWmeAifsn);
	return 1;
}
