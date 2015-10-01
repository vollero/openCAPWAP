#include "CWCommon.h"
#include <linux/if_ether.h>

//Bridge
u8 bridge_tunnel_header[] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8}; 
/* Ethernet-II snap header (RFC1042 for most EtherTypes) */
u8 rfc1042_header[] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00};

int CWConvertDataFrame_8023_to_80211(unsigned char *frameReceived, int frameLen, unsigned char *outbuffer, int * WTPIndex){

//CWLog("Ricevuto frame, devo convertire");
	int offset=0;
	unsigned char * hdr80211;
	unsigned char SA[ETH_ALEN];
	unsigned char DA[ETH_ALEN];
	unsigned char BSSID[ETH_ALEN];
	int sizeEncapsHdr=0, skipBytes=0;
	nodeAVL* tmpNode=NULL;

	CW_COPY_MEMORY(DA, frameReceived, ETH_ALEN);
	CW_COPY_MEMORY(SA, frameReceived+ETH_ALEN, ETH_ALEN);
	
	if(checkAddressBroadcast(DA))
	{
		memset(BSSID, 0xff, ETH_ALEN);
		*(WTPIndex) = -1;
	}
	else
	{
		//---- Search AVL node
		CWThreadMutexLock(&mutexAvlTree);
		tmpNode = AVLfind(DA, avlTree);
		//AVLdisplay_avl(avlTree);
		CWThreadMutexUnlock(&mutexAvlTree);
		if(tmpNode == NULL)
		{
			//CWLog("STA[%02x:%02x:%02x:%02x:%02x:%02x] non associata. Ignoro", (int) DA[0], (int) DA[1], (int) DA[2], (int) DA[3], (int) DA[4], (int) DA[5]);
			return -1;
		}
		else
		{
			//CWLog("STA trovata[%02x:%02x:%02x:%02x:%02x:%02x]", (int) DA[0], (int) DA[1], (int) DA[2], (int) DA[3], (int) DA[4], (int) DA[5]);
			CW_COPY_MEMORY(BSSID, tmpNode->BSSID, ETH_ALEN);
//			CWLog("Trovato BSSID[%02x:%02x:%02x:%02x:%02x:%02x]", (int) BSSID[0], (int) BSSID[1], (int) BSSID[2], (int) BSSID[3], (int) BSSID[4], (int) BSSID[5]);
			*(WTPIndex) = tmpNode->index;
		}
		//----
	}			
/*
	CWLog("FRAME ETHERNET RICEVUTO");
	CWLog("DA[%02x:%02x:%02x:%02x:%02x:%02x]", (int) DA[0], (int) DA[1], (int) DA[2], (int) DA[3], (int) DA[4], (int) DA[5]);
	CWLog("SA[%02x:%02x:%02x:%02x:%02x:%02x]", (int) SA[0], (int) SA[1], (int) SA[2], (int) SA[3], (int) SA[4], (int) SA[5]);
*/
	hdr80211 = CW80211AssembleDataFrameHdr(SA, DA, BSSID, 0, &(offset), 0, 1);
	
//	CWLog("Byte dopo eth addr: %02x %02x", (int)(frameReceived+ETH_ALEN+ETH_ALEN)[0], (int)(frameReceived+ETH_ALEN+ETH_ALEN)[1]);


	int ethertype = (frameReceived[12] << 8) | frameReceived[13];
	
	CW_COPY_MEMORY(outbuffer, hdr80211, HLEN_80211);
	//Encaps header
//	CWLog("ETHERTYPE: %02x", ethertype);
	if (ethertype == ETH_P_AARP || ethertype == ETH_P_IPX) {
			CW_COPY_MEMORY((outbuffer+HLEN_80211), bridge_tunnel_header, sizeof(bridge_tunnel_header));
			skipBytes=2;
			sizeEncapsHdr=sizeof(bridge_tunnel_header);

		//	CW_COPY_MEMORY((outbuffer+HLEN_80211+sizeof(bridge_tunnel_header)), &(sizeEncapsHdr), 2);
	} else if (ethertype >= ETH_P_802_3_MIN) {
		CW_COPY_MEMORY((outbuffer+HLEN_80211), rfc1042_header, sizeof(rfc1042_header));
		skipBytes=2;
		sizeEncapsHdr=sizeof(rfc1042_header);
		//CW_COPY_MEMORY((outbuffer+HLEN_80211+sizeof(rfc1042_header)), &(sizeEncapsHdr), 2);
	}
	else
		sizeEncapsHdr=0;

	CW_COPY_MEMORY((outbuffer+HLEN_80211+sizeEncapsHdr), (frameReceived+ETH_HLEN-skipBytes), frameLen-ETH_HLEN+skipBytes);
	
//	CWLog("Byte dopo llc: %02x %02x", (int)(outbuffer+HLEN_80211+sizeEncapsHdr)[0], (int)(outbuffer+HLEN_80211+sizeEncapsHdr)[1]);
//	CWLog("DIMENSIONE NUOVO 80211 frame: %d WTPIndex: %d", (frameLen-ETH_HLEN+skipBytes+HLEN_80211+sizeEncapsHdr), *(WTPIndex));
	return (frameLen-ETH_HLEN+skipBytes+HLEN_80211+sizeEncapsHdr);
}

CWBool CWConvertDataFrame_80211_to_8023(unsigned char *frameReceived, int frameLen, unsigned char *frame8023, int * frame8023Len){
	
	struct CWFrameDataHdr dataFrame;
	CWBool flagEncaps=CW_FALSE;
	int sizeEthFrame=0, offsetEthPayload=0, offsetFrame8023=0;
	
	unsigned char * payload = frameReceived+HLEN_80211;
	short int etherType = (payload[6] << 8) | payload[7];
	
	if(!CW80211ParseDataFrameToDS(frameReceived, &(dataFrame)))
	{
		CWLog("CW80211: Error parsing data frame");
		return CW_FALSE;
	}
	
	if(	
		(
			(!memcmp(payload, rfc1042_header, 6)) &&
			(etherType != ETH_P_AARP && etherType != ETH_P_IPX) 
		) ||
		(!memcmp(payload, bridge_tunnel_header, 6))
	  )
		flagEncaps=CW_TRUE;
					
		if(flagEncaps == CW_TRUE)
		{
			sizeEthFrame = ETH_HLEN+(frameLen - HLEN_80211 - ENCAPS_HDR_LEN);
			offsetEthPayload = HLEN_80211+ENCAPS_HDR_LEN;
			//	CWLog("Con ENCAPS. EthPayload Len: %d. EthType: %d", offsetEthPayload, etherType);
		}
		else
		{
			sizeEthFrame = ETH_HLEN+(frameLen - HLEN_80211);
			offsetEthPayload = HLEN_80211;
			//	CWLog("Senza LLC. EthPayload Len: %d", offsetEthPayload);
		}
				
		/* SET Eth vX Frame */
	//	CW_CREATE_ARRAY_CALLOC_ERR(frame8023, sizeEthFrame, unsigned char, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		if(!CW80211AssembleIEAddr(&(frame8023[offsetFrame8023]), &(offsetFrame8023), dataFrame.DA))
			return CW_FALSE;

		if(!CW80211AssembleIEAddr(&(frame8023[offsetFrame8023]), &(offsetFrame8023), dataFrame.SA))
			return CW_FALSE;

		if(flagEncaps == CW_TRUE)
		{	
			if(!CW8023AssembleHdrLength(&(frame8023[offsetFrame8023]), &(offsetFrame8023), htons(etherType)))
				return CW_FALSE;
		}
		else
		{
			if(!CW8023AssembleHdrLength(&(frame8023[offsetFrame8023]), &(offsetFrame8023), htons(frameLen-offsetEthPayload)))
				return CW_FALSE;
		}
		

		CW_COPY_MEMORY((frame8023+offsetFrame8023), (frameReceived+offsetEthPayload), (frameLen-offsetEthPayload));
/*
		CWLog("****** ETHERNET FRAME ******* ");
		if(flagEncaps == CW_TRUE)
			CWLog("** ENCAPS: %d bytes", ENCAPS_HDR_LEN);
		CWLog("** DA[%02x:%02x:%02x:%02x:%02x:%02x]: %d bytes", (int)dataFrame.DA[0], (int)dataFrame.DA[1], (int)dataFrame.DA[2], (int)dataFrame.DA[3], (int)dataFrame.DA[4], (int)dataFrame.DA[5], ETH_ALEN);
		CWLog("** SA[%02x:%02x:%02x:%02x:%02x:%02x]: %d bytes", (int)dataFrame.SA[0], (int)dataFrame.SA[1], (int)dataFrame.SA[2], (int)dataFrame.SA[3], (int)dataFrame.SA[4], (int)dataFrame.SA[5], ETH_ALEN);
		CWLog("** TOT LEN 802.3 Frame: %d", (ETH_HLEN+(frameLen - offsetEthPayload)));
	*/	
		*(frame8023Len) = (ETH_HLEN+(frameLen - offsetEthPayload));
	
		return CW_TRUE;	
}

CWBool checkAddressBroadcast(unsigned char * addr)
{
	int i;
	for(i=0; i<ETH_ALEN; i++)
	{
		if((addr[i] & 0xff) != 0xff)
			return CW_FALSE;
	}
	
	return CW_TRUE;	
}
