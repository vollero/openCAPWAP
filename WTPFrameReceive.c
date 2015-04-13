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

#include "WTPFrameReceive.h"
#include "common.h"
#include "ieee802_11_defs.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

#define EXIT_FRAME_THREAD(sock)	CWLog("ERROR Handling Frames: application will be closed!");		\
				close(sock);								\
				exit(1);



int CWWTPSendFrame(unsigned char *buf, int len){
    int FRAME_80211_LEN=24;
    int gRawSockLocal;
    struct sockaddr_ll addr;
    
    if ((gRawSockLocal=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0) 	{
		CWDebugLog("THR FRAME: Error creating socket");
		CWExitThread();
	}

    memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
//	addr.sll_protocol = htons(ETH_P_ALL);
//	addr.sll_pkttype = PACKET_HOST;
	addr.sll_ifindex = if_nametoindex("monitor0"); //if_nametoindex(gRadioInterfaceName_0);
 
	 
	if ((bind(gRawSockLocal, (struct sockaddr*)&addr, sizeof(addr)))<0) {
 		CWDebugLog("THR FRAME: Error binding socket");
 		CWExitThread();
 	}
 	
    if( send(gRawSockLocal, buf + FRAME_80211_LEN, len - FRAME_80211_LEN,0) < 1 ){
        CWDebugLog("Error to send frame on raw socket");
        return -1;
    }
    CWDebugLog("Send (%d) bytes on raw socket",len - FRAME_80211_LEN);

    return 1;
    
}

int getMacAddr(int sock, char* interface, unsigned char* macAddr){
	
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(s.ifr_name, interface);
	if(!ioctl(fd, SIOCGIFHWADDR, &s))
		memcpy(macAddr, s.ifr_addr.sa_data, MAC_ADDR_LEN);
	
	CWDebugLog("\n");

	return 1;
}

int extractFrameInfo(char* buffer, char* RSSI, char* SNR, int* dataRate){
	int signal, noise;

	*RSSI=buffer[RSSI_BYTE]-ATHEROS_CONV_VALUE;	//RSSI in dBm
	
	signal=buffer[SIGNAL_BYTE]-ATHEROS_CONV_VALUE;	
	noise=buffer[NOISE_BYTE];			
	*SNR=(char)signal-noise;			//RSN in dB

	*dataRate=(buffer[DATARATE_BYTE]/2)*10;		//Data rate in Mbps*10
	return 1;
}

int extractFrame(CWProtocolMessage** frame, unsigned char* buffer, int len){

	CW_CREATE_OBJECT_ERR(*frame, CWProtocolMessage, return 0;);
	CWProtocolMessage *auxPtr = *frame;
	CW_CREATE_PROTOCOL_MESSAGE(*auxPtr, len-PRISMH_LEN, return 0;);
	memcpy(auxPtr->msg, buffer+PRISMH_LEN, len-PRISMH_LEN);
	auxPtr->offset=len-PRISMH_LEN;
	return 1;
}

int extract802_11_Frame(CWProtocolMessage** frame, unsigned char* buffer, int len){
	CW_CREATE_OBJECT_ERR(*frame, CWProtocolMessage, return 0;);
	CWProtocolMessage *auxPtr = *frame;
	CW_CREATE_PROTOCOL_MESSAGE(*auxPtr, len, return 0;);
	memcpy(auxPtr->msg, buffer, len);
	auxPtr->offset=len;
	return 1;
}

int extractAddr(unsigned char* destAddr, unsigned char* sourceAddr, char* frame){
	memset(destAddr, 0, MAC_ADDR_LEN);
	memset(sourceAddr, 0, MAC_ADDR_LEN);
	memcpy(destAddr, frame+DEST_ADDR_START, MAC_ADDR_LEN);
	memcpy(sourceAddr, frame+SOURCE_ADDR_START, MAC_ADDR_LEN);

	return 1;
}

int macAddrCmp (unsigned char* addr1, unsigned char* addr2){
	int i, ok=1;

	for (i=0; i<MAC_ADDR_LEN; i++)	{
		if (addr1[i]!=addr2[i])
		{ok=0;}
	}

	if (ok==1) {CWDebugLog("MAC Address test: OK\n");}
	else {CWDebugLog("MAC Address test: Failed\n");}
	
	return ok;
}

int from_8023_to_80211( unsigned char *inbuffer,int inlen, unsigned char *outbuffer, unsigned char *own_addr){

	int indx=0;
	struct ieee80211_hdr hdr;
	os_memset(&hdr,0,sizeof(struct ieee80211_hdr));

	hdr.frame_control = IEEE80211_FC(WLAN_FC_TYPE_DATA, WLAN_FC_STYPE_DATA);
	hdr.duration_id = 0;
	hdr.seq_ctrl = 0;

	os_memcpy(hdr.addr1, own_addr, ETH_ALEN);
	os_memcpy(hdr.addr2, inbuffer + ETH_ALEN, ETH_ALEN);
	os_memcpy(hdr.addr3, inbuffer, ETH_ALEN);
	CLEARBIT(hdr.frame_control,9);
	SETBIT(hdr.frame_control,8);	
	
	os_memcpy(outbuffer + indx,&hdr,sizeof(hdr));
	indx += sizeof(hdr);
	os_memcpy(outbuffer + indx, inbuffer, inlen);
	indx += inlen;
	
	return indx;
}

#ifdef SPLIT_MAC

int gRawSock;
int rawInjectSocket;
extern int wtpInRunState;

CW_THREAD_RETURN_TYPE CWWTPReceiveFrame(void *arg){
 
	int n,encaps_len;
	unsigned char buffer[CW_BUFFER_SIZE];
	unsigned char buf80211[CW_BUFFER_SIZE];
	unsigned char macAddr[MAC_ADDR_LEN];
	struct ieee80211_radiotap_header * radiotapHeader;
	int frameRespLen=0;
	struct CWFrameDataHdr dataFrame;
	int tmpOffset;
	struct sockaddr_ll addr;
	CWProtocolMessage* frame=NULL;
	CWBindingDataListElement* listElement=NULL;
	struct ifreq ethreq;
	
	struct sockaddr_ll addr_inject;
	unsigned char macAddrInject[MAC_ADDR_LEN];


	CWThreadSetSignals(SIG_BLOCK, 1, SIGALRM);
	
	if ((gRawSock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0) 	{
		CWDebugLog("THR FRAME: Error creating socket");
		CWExitThread();
	}

    memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
//	addr.sll_protocol = htons(ETH_P_ALL);
//	addr.sll_pkttype = PACKET_HOST;
	addr.sll_ifindex = if_nametoindex("monitor0"); //if_nametoindex(gRadioInterfaceName_0);
 
	 
	if ((bind(gRawSock, (struct sockaddr*)&addr, sizeof(addr)))<0) {
 		CWDebugLog("THR FRAME: Error binding socket");
 		CWExitThread();
 	}
 
	if (!getMacAddr(gRawSock, "monitor0", macAddr)){
 		CWDebugLog("THR FRAME: Ioctl error");
		EXIT_FRAME_THREAD(gRawSock);
 	}
 
 	int optval;
 	int optlen = sizeof(optval);
	optval = 20;
	if (setsockopt
	    (gRawSock, SOL_SOCKET, SO_PRIORITY, &optval, optlen)) {
		CWLog("nl80211: Failed to set socket priority: %s",
			   strerror(errno));
	}

	nodeAVL * tmpNodeSta=NULL;
	
	/* RAW SOCKET on monitor interface to Inject packets */
	if ((rawInjectSocket=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0) 	{
		CWLog("THR FRAME: Error creating socket");
		//CWExitThread();
	}
	
	memset(&addr_inject, 0, sizeof(addr_inject));
	addr_inject.sll_family = AF_PACKET;
	addr_inject.sll_ifindex = if_nametoindex("monitor0");
						  
	if ((bind(rawInjectSocket, (struct sockaddr*)&addr_inject, sizeof(addr_inject)))<0) {
		CWLog("THR FRAME: Error binding socket");
		//CWExitThread();
	}
						 
	if (!getMacAddr(rawInjectSocket, "monitor0", macAddrInject)){
		CWLog("THR FRAME: Ioctl error");
		//EXIT_FRAME_THREAD(gRawSock);
	}

 	CW_REPEAT_FOREVER{
		n = recvfrom(gRawSock,buffer,sizeof(buffer),0,NULL,NULL);

		if(n<0)continue;

		if (!wtpInRunState){
			continue;
		}
		
		tmpNodeSta=NULL;
		
		//mac80211 puts radiotap header to data frames
		radiotapHeader = (struct ieee80211_radiotap_header *) buffer;
		if(!CW80211ParseFrameIEControl((buffer+radiotapHeader->it_len), &(tmpOffset), &(dataFrame.frameControl)))
			return;
		
		//if it's not data frame, continue
		if (!(WLAN_FC_GET_TYPE(dataFrame.frameControl) == WLAN_FC_TYPE_DATA))
			continue;
		
		if(!CW80211ParseDataFrameToDS((buffer+radiotapHeader->it_len), &(dataFrame)))
		{
			CWLog("CW80211: Error parsing data frame");
			continue;
		}
		
		//If data frame && toDS
		if(
			WLAN_FC_GET_STYPE(dataFrame.frameControl) == WLAN_FC_STYPE_DATA &&
			((dataFrame.frameControl & IEEE80211_FCTL_TODS) == IEEE80211_FCTL_TODS)
			)
		{
			//---- Search AVL node
			CWThreadMutexLock(&mutexAvlTree);
			tmpNodeSta = AVLfind(dataFrame.SA, avlTree);
			//AVLdisplay_avl(avlTree);
			CWThreadMutexUnlock(&mutexAvlTree);
			if(tmpNodeSta == NULL)
			{
	//			CWLog("STA[%02x:%02x:%02x:%02x:%02x:%02x] non associata. Ignoro", (int) dataFrame.SA[0], (int) dataFrame.SA[1], (int) dataFrame.SA[2], (int) dataFrame.SA[3], (int) dataFrame.SA[4], (int) dataFrame.SA[5]);
				continue;
			}
		//	else
		//		CWLog("STA trovata [%02x:%02x:%02x:%02x:%02x:%02x]", (int) tmpNodeSta->staAddr[0], (int) tmpNodeSta->staAddr[1], (int) tmpNodeSta->staAddr[2], (int) tmpNodeSta->staAddr[3], (int) tmpNodeSta->staAddr[4], (int) tmpNodeSta->staAddr[5]);
			//----
			
			encaps_len = n-radiotapHeader->it_len;
		//	CWLog("[80211] Pure frame data. %d byte letti, %d byte data frame", n, encaps_len);
			if (!extract802_11_Frame(&frame, (buffer+radiotapHeader->it_len), encaps_len)){
				CWLog("THR FRAME: Error extracting a frame");
				EXIT_FRAME_THREAD(gRawSock);
			}
			
			CWBindingTransportHeaderValues *bindValues;
			CW_CREATE_OBJECT_ERR(listElement, CWBindingDataListElement, EXIT_FRAME_THREAD(gRawSock););
				
			listElement->frame = frame;
			listElement->bindingValues = NULL;
			listElement->frame->data_msgType = CW_IEEE_802_11_FRAME_TYPE;
					
			CWLockSafeList(gFrameList);
			CWAddElementToSafeListTail(gFrameList, listElement, sizeof(CWBindingDataListElement));
			CWUnlockSafeList(gFrameList);
		}
		//Puo inviarlo la STA per fare richiesta di power saving. Rispondere con ACK sse indica che vuole stare UP
		else if(WLAN_FC_GET_STYPE(dataFrame.frameControl) == WLAN_FC_STYPE_NULLFUNC)
		{
	//		CWLog("[80211] Pure frame null func");
		//	frameResponse = CW80211AssembleACK(WTPBSSInfoPtr, tb[NL80211_ATTR_MAC], &frameRespLen);
		}
		//Altri casi?
 	}
 	
	close(gRawSock);
	return(NULL);
}

#endif
