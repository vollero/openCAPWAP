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


#define SETBIT(ADDRESS,BIT) (ADDRESS |= (1<<BIT))
#define CLEARBIT(ADDRESS,BIT) (ADDRESS &= ~(1<<BIT))
#define CHECKBIT(ADDRESS,BIT) (ADDRESS & (1<<BIT))

#define TYPE_LEN 2
#define ETH_ALEN 6
#define ETH_HLEN 14
#define FRAME_80211_LEN	24

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

#define EXIT_FRAME_THREAD(sock)	CWLog("ERROR Handling Frames: application will be closed!");		\
				close(sock);								\
				exit(1);



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


int gRawSock;
extern int wtpInRunState;

int CWWTPSendFrame(unsigned char *buf, int len){
	
	if( send(gRawSock, buf + FRAME_80211_LEN, len - FRAME_80211_LEN,0) < 1 ){
		CWDebugLog("Error to send frame on raw socket");
		return -1;
	}
	CWDebugLog("Send (%d) bytes on raw socket",len - FRAME_80211_LEN);

	return 1;
	
}


CW_THREAD_RETURN_TYPE CWWTPReceiveFrame(void *arg){
 
	int n,encaps_len;
	unsigned char buffer[CW_BUFFER_SIZE];
	unsigned char buf80211[CW_BUFFER_SIZE];
	unsigned char macAddr[MAC_ADDR_LEN];
	int len;
	struct ieee80211_radiotap_iterator iter;
	int ret;
	int datarate = 0, ssi_signal = 0;
	int injected = 0, failed = 0, rxflags = 0;
	
	struct sockaddr_ll addr;
 
	CWProtocolMessage* frame=NULL;
	CWBindingDataListElement* listElement=NULL;
	struct ifreq ethreq;
 
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
 
 
 	/* Set the network card in promiscuos mode */
 /*	strncpy(ethreq.ifr_name, "monitor0",IFNAMSIZ);
	if (ioctl(gRawSock,SIOCGIFFLAGS,&ethreq)==-1){
 		CWDebugLog("THR FRAME: Error ioctl");
		EXIT_FRAME_THREAD(gRawSock);
 	}
 	ethreq.ifr_flags|=IFF_PROMISC;
	if (ioctl(gRawSock,SIOCSIFFLAGS,&ethreq)==-1){
 		CWDebugLog("THR FRAME: Error ioctl");
		EXIT_FRAME_THREAD(gRawSock);
 	}
 	*/
 
 /*
 #ifdef FILTER_ON
 	// Attach the filter to the socket
 	if(setsockopt(gRawSock, SOL_SOCKET, SO_ATTACH_FILTER, &Filter, sizeof(Filter))<0)
 	{
 		CWDebugLog("THR FRAME: Error attaching filter");
		EXIT_FRAME_THREAD(gRawSock);
 	}
 #endif
 */
 	int optval;
 	int optlen = sizeof(optval);
	optval = 20;
	if (setsockopt
	    (gRawSock, SOL_SOCKET, SO_PRIORITY, &optval, optlen)) {
		CWLog("nl80211: Failed to set socket priority: %s",
			   strerror(errno));
	}
	
	
 	int frameRespLen=0, offsetFrameReceived=0;
		struct CWFrameDataHdr dataFrame;
		
 	CWLog("Monitor loop");
 	CW_REPEAT_FOREVER{
		
		n = recvfrom(gRawSock,buffer,sizeof(buffer),0,NULL,NULL);

		if(n<0)continue;

		if (!wtpInRunState){
			CWLog("WTP is not in RUN state");
			continue;
		}
		
		CWLog("*** Monitor ha letto %d byte", n);
		
		/*int indexPacket=0;
		for(indexPacket=0; indexPacket<n; indexPacket++)
		{
			CWLog("frame[%d]: %02x", indexPacket, buffer[indexPacket]);
		}
		continue;
		*/
	/*	
		if (ieee80211_radiotap_iterator_init(&iter, (void *) buffer, len, NULL)) {
		CWLog( "nl80211: received invalid radiotap frame");
		return;
		}

	while (1) {
		CWLog("Loop radio tap");
		ret = ieee80211_radiotap_iterator_next(&iter);
		if (ret == -ENOENT)
			break;
		if (ret) {
			CWLog( "nl80211: received invalid radiotap frame (%d)",
				   ret);
			return;
		}
		switch (iter.this_arg_index) {
		case IEEE80211_RADIOTAP_FLAGS:
			if (*iter.this_arg & IEEE80211_RADIOTAP_F_FCS)
				len -= 4;
			break;
		case IEEE80211_RADIOTAP_RX_FLAGS:
			rxflags = 1;
			break;
		case IEEE80211_RADIOTAP_TX_FLAGS:
			injected = 1;
			failed = le_to_host16((*(uint16_t *) iter.this_arg)) &
					IEEE80211_RADIOTAP_F_TX_FAIL;
			break;
		case IEEE80211_RADIOTAP_DATA_RETRIES:
			break;
		case IEEE80211_RADIOTAP_CHANNEL:
			break;
		case IEEE80211_RADIOTAP_RATE:
			datarate = *iter.this_arg * 5;
			break;
		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
			ssi_signal = (s8) *iter.this_arg;
			break;
		}
	}
	*/
		/*
		 encaps_len = from_8023_to_80211(buffer, n, buf80211, macAddr);
			
		if (!extract802_11_Frame(&frame, buf80211, encaps_len)){
			CWDebugLog("THR FRAME: Error extracting a frame");
			EXIT_FRAME_THREAD(gRawSock);
		}

		CWDebugLog("Recv 802.11 data(len:%d) from monitor0",encaps_len);
		*/
		
		CWLog("Radiotap version: %d", buffer[0]);
		CWLog("Radiotap pad: %d", buffer[1]);
		short int radioTapLen=0;
		CW_COPY_MEMORY(&(radioTapLen),(buffer+2), 2);
		CWLog("Radiotap len: %02x", radioTapLen);
		
		int radioTapVersion=0;
		CW_COPY_MEMORY(&(radioTapVersion),(buffer+4), 4);
		CWLog("Radiotap version: %d", radioTapVersion);
		continue;
		
		CWLog("CW80211: Parse del frame control");
		if(!CW80211ParseFrameIEControl((buffer+offsetFrameReceived), &(offsetFrameReceived), &(dataFrame.frameControl)))
			return;
		
		CWLog("CW80211: Frame Control %02x", dataFrame.frameControl);
		//Duration
		if(!CW80211ParseFrameIEControl((buffer+offsetFrameReceived), &(offsetFrameReceived), &(dataFrame.duration)))
			return CW_FALSE;
		CWLog("CW80211: Duration %02x", dataFrame.duration);

		//DA
		if(!CW80211ParseFrameIEAddr((buffer+offsetFrameReceived), &(offsetFrameReceived), dataFrame.DA))
			return CW_FALSE;
		CWLog("CW80211: DA %02x:%02x:%02x:%02x:%02x:%02x", (int)dataFrame.DA[0], (int)dataFrame.DA[1], (int)dataFrame.DA[2], (int)dataFrame.DA[3], (int)dataFrame.DA[4], (int)dataFrame.DA[5]);
		
		//SA
		if(!CW80211ParseFrameIEAddr((buffer+offsetFrameReceived), &(offsetFrameReceived), dataFrame.SA))
			return CW_FALSE;
		CWLog("CW80211: SA %02x:%02x:%02x:%02x:%02x:%02x", (int)dataFrame.SA[0], (int)dataFrame.SA[1], (int)dataFrame.SA[2], (int)dataFrame.SA[3], (int)dataFrame.SA[4], (int)dataFrame.SA[5]);
			
		//BSSID
		if(!CW80211ParseFrameIEAddr((buffer+offsetFrameReceived), &(offsetFrameReceived), dataFrame.BSSID))
			return CW_FALSE;
		CWLog("CW80211: BSSID %02x:%02x:%02x:%02x:%02x:%02x", (int)dataFrame.BSSID[0], (int)dataFrame.BSSID[1], (int)dataFrame.BSSID[2], (int)dataFrame.BSSID[3], (int)dataFrame.BSSID[4], (int)dataFrame.BSSID[5]);
		
		
		CWLog("CW80211: type: %02x, subtype: %02x", (int)WLAN_FC_GET_TYPE(dataFrame.frameControl), (int)WLAN_FC_GET_STYPE(dataFrame.frameControl));
		
		if (WLAN_FC_GET_TYPE(dataFrame.frameControl) == WLAN_FC_TYPE_DATA)
		{
			if(WLAN_FC_GET_STYPE(dataFrame.frameControl) == WLAN_FC_STYPE_NULLFUNC)
			{
				CWLog("[80211] Pure frame null func");
			//	frameResponse = CW80211AssembleACK(WTPBSSInfoPtr, tb[NL80211_ATTR_MAC], &frameRespLen);
			}
			else if(WLAN_FC_GET_STYPE(dataFrame.frameControl) == WLAN_FC_STYPE_DATA)
			{
				CWLog("[80211] Pure frame data");
			}
			else if(WLAN_FC_GET_STYPE(dataFrame.frameControl) == WLAN_FC_STYPE_CFACK)
			{
				CWLog("[80211] WLAN_FC_STYPE_CFACK");
			}
		}
		
		/*
		CWBindingTransportHeaderValues *bindValues;
		
		CW_CREATE_OBJECT_ERR(listElement, CWBindingDataListElement, EXIT_FRAME_THREAD(gRawSock););
			
		listElement->frame = frame;
		listElement->bindingValues = NULL;
				
		listElement->frame->data_msgType = CW_IEEE_802_11_FRAME_TYPE;
				
		CWLockSafeList(gFrameList);
			CWAddElementToSafeListTail(gFrameList, listElement, sizeof(CWBindingDataListElement));
		CWUnlockSafeList(gFrameList);
	*/
		
 	}
 	
	close(gRawSock);
	return(NULL);
}

static const struct radiotap_align_size rtap_namespace_sizes[] = {
	[IEEE80211_RADIOTAP_TSFT] = { .align = 8, .size = 8, },
	[IEEE80211_RADIOTAP_FLAGS] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_RATE] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_CHANNEL] = { .align = 2, .size = 4, },
	[IEEE80211_RADIOTAP_FHSS] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_DBM_ANTSIGNAL] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_DBM_ANTNOISE] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_LOCK_QUALITY] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_TX_ATTENUATION] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_DB_TX_ATTENUATION] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_DBM_TX_POWER] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_ANTENNA] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_DB_ANTSIGNAL] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_DB_ANTNOISE] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_RX_FLAGS] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_TX_FLAGS] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_RTS_RETRIES] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_DATA_RETRIES] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_MCS] = { .align = 1, .size = 3, },
	[IEEE80211_RADIOTAP_AMPDU_STATUS] = { .align = 4, .size = 8, },
	/*
	 * add more here as they are defined in radiotap.h
	 */
};

static const struct ieee80211_radiotap_namespace radiotap_ns = {
	.n_bits = sizeof(rtap_namespace_sizes) / sizeof(rtap_namespace_sizes[0]),
	.align_size = rtap_namespace_sizes,
};

int ieee80211_radiotap_iterator_next(
	struct ieee80211_radiotap_iterator *iterator)
{
	while (1) {
		int hit = 0;
		int pad, align, size, subns;
		uint32_t oui;

		/* if no more EXT bits, that's it */
		if ((iterator->_arg_index % 32) == IEEE80211_RADIOTAP_EXT &&
		    !(iterator->_bitmap_shifter & 1))
			return -ENOENT;

		if (!(iterator->_bitmap_shifter & 1))
			goto next_entry; /* arg not present */

		/* get alignment/size of data */
		switch (iterator->_arg_index % 32) {
		case IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE:
		case IEEE80211_RADIOTAP_EXT:
			align = 1;
			size = 0;
			break;
		case IEEE80211_RADIOTAP_VENDOR_NAMESPACE:
			align = 2;
			size = 6;
			break;
		default:
#ifdef RADIOTAP_SUPPORT_OVERRIDES
			if (find_override(iterator, &align, &size)) {
				/* all set */
			} else
#endif
			if (!iterator->current_namespace ||
			    iterator->_arg_index >= iterator->current_namespace->n_bits) {
				if (iterator->current_namespace == &radiotap_ns)
					return -ENOENT;
				align = 0;
			} else {
				align = iterator->current_namespace->align_size[iterator->_arg_index].align;
				size = iterator->current_namespace->align_size[iterator->_arg_index].size;
			}
			if (!align) {
				/* skip all subsequent data */
				iterator->_arg = iterator->_next_ns_data;
				/* give up on this namespace */
				iterator->current_namespace = NULL;
				goto next_entry;
			}
			break;
		}

		/*
		 * arg is present, account for alignment padding
		 *
		 * Note that these alignments are relative to the start
		 * of the radiotap header.  There is no guarantee
		 * that the radiotap header itself is aligned on any
		 * kind of boundary.
		 *
		 * The above is why get_unaligned() is used to dereference
		 * multibyte elements from the radiotap area.
		 */

		pad = ((unsigned long)iterator->_arg -
		       (unsigned long)iterator->_rtheader) & (align - 1);

		if (pad)
			iterator->_arg += align - pad;

		if (iterator->_arg_index % 32 == IEEE80211_RADIOTAP_VENDOR_NAMESPACE) {
			int vnslen;

			if ((unsigned long)iterator->_arg + size -
			    (unsigned long)iterator->_rtheader >
			    (unsigned long)iterator->_max_length)
				return -EINVAL;

			oui = (*iterator->_arg << 16) |
				(*(iterator->_arg + 1) << 8) |
				*(iterator->_arg + 2);
			subns = *(iterator->_arg + 3);

			find_ns(iterator, oui, subns);

			vnslen = get_unaligned_le16(iterator->_arg + 4);
			iterator->_next_ns_data = iterator->_arg + size + vnslen;
			if (!iterator->current_namespace)
				size += vnslen;
		}

		/*
		 * this is what we will return to user, but we need to
		 * move on first so next call has something fresh to test
		 */
		iterator->this_arg_index = iterator->_arg_index;
		iterator->this_arg = iterator->_arg;
		iterator->this_arg_size = size;

		/* internally move on the size of this arg */
		iterator->_arg += size;

		/*
		 * check for insanity where we are given a bitmap that
		 * claims to have more arg content than the length of the
		 * radiotap section.  We will normally end up equalling this
		 * max_length on the last arg, never exceeding it.
		 */

		if ((unsigned long)iterator->_arg -
		    (unsigned long)iterator->_rtheader >
		    (unsigned long)iterator->_max_length)
			return -EINVAL;

		/* these special ones are valid in each bitmap word */
		switch (iterator->_arg_index % 32) {
		case IEEE80211_RADIOTAP_VENDOR_NAMESPACE:
			iterator->_reset_on_ext = 1;

			iterator->is_radiotap_ns = 0;
			/*
			 * If parser didn't register this vendor
			 * namespace with us, allow it to show it
			 * as 'raw. Do do that, set argument index
			 * to vendor namespace.
			 */
			iterator->this_arg_index =
				IEEE80211_RADIOTAP_VENDOR_NAMESPACE;
			if (!iterator->current_namespace)
				hit = 1;
			goto next_entry;
		case IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE:
			iterator->_reset_on_ext = 1;
			iterator->current_namespace = &radiotap_ns;
			iterator->is_radiotap_ns = 1;
			goto next_entry;
		case IEEE80211_RADIOTAP_EXT:
			/*
			 * bit 31 was set, there is more
			 * -- move to next u32 bitmap
			 */
			iterator->_bitmap_shifter =
				get_unaligned_le32(iterator->_next_bitmap);
			iterator->_next_bitmap++;
			if (iterator->_reset_on_ext)
				iterator->_arg_index = 0;
			else
				iterator->_arg_index++;
			iterator->_reset_on_ext = 0;
			break;
		default:
			/* we've got a hit! */
			hit = 1;
 next_entry:
			iterator->_bitmap_shifter >>= 1;
			iterator->_arg_index++;
		}

		/* if we found a valid arg earlier, return it now */
		if (hit)
			return 0;
	}
}

int ieee80211_radiotap_iterator_init(
	struct ieee80211_radiotap_iterator *iterator,
	struct ieee80211_radiotap_header *radiotap_header,
	int max_length, const struct ieee80211_radiotap_vendor_namespaces *vns)
{
	/* must at least have the radiotap header */
	if (max_length < (int)sizeof(struct ieee80211_radiotap_header))
	{
		CWLog("errore 1");
		return -EINVAL;
	}
	/* Linux only supports version 0 radiotap format */
	if (radiotap_header->it_version)
	{
		CWLog("errore 2");
		return -EINVAL;
	}
	/* sanity check for allowed length and radiotap length field */
	if (max_length < get_unaligned_le16(&radiotap_header->it_len))
	{
		CWLog("errore 3");
		return -EINVAL;
	}

	iterator->_rtheader = radiotap_header;
	iterator->_max_length = get_unaligned_le16(&radiotap_header->it_len);
	iterator->_arg_index = 0;
	iterator->_bitmap_shifter = get_unaligned_le32(&radiotap_header->it_present);
	iterator->_arg = (uint8_t *)radiotap_header + sizeof(*radiotap_header);
	iterator->_reset_on_ext = 0;
	iterator->_next_bitmap = &radiotap_header->it_present;
	iterator->_next_bitmap++;
	iterator->_vns = vns;
	iterator->current_namespace = &radiotap_ns;
	iterator->is_radiotap_ns = 1;
#ifdef RADIOTAP_SUPPORT_OVERRIDES
	iterator->n_overrides = 0;
	iterator->overrides = NULL;
#endif

	/* find payload start allowing for extended bitmap(s) */

	if (iterator->_bitmap_shifter & (1<<IEEE80211_RADIOTAP_EXT)) {
		if ((unsigned long)iterator->_arg -
		    (unsigned long)iterator->_rtheader + sizeof(uint32_t) >
		    (unsigned long)iterator->_max_length)
			return -EINVAL;
		while (get_unaligned_le32(iterator->_arg) &
					(1 << IEEE80211_RADIOTAP_EXT)) {
			iterator->_arg += sizeof(uint32_t);

			/*
			 * check for insanity where the present bitmaps
			 * keep claiming to extend up to or even beyond the
			 * stated radiotap header length
			 */

			if ((unsigned long)iterator->_arg -
			    (unsigned long)iterator->_rtheader +
			    sizeof(uint32_t) >
			    (unsigned long)iterator->_max_length)
				return -EINVAL;
		}

		iterator->_arg += sizeof(uint32_t);

		/*
		 * no need to check again for blowing past stated radiotap
		 * header length, because ieee80211_radiotap_iterator_next
		 * checks it before it is dereferenced
		 */
	}

	iterator->this_arg = iterator->_arg;

	/* we are all initialized happily */

	return 0;
}

void find_ns(struct ieee80211_radiotap_iterator *iterator,
		    uint32_t oui, uint8_t subns)
{
	int i;

	iterator->current_namespace = NULL;

	if (!iterator->_vns)
		return;

	for (i = 0; i < iterator->_vns->n_ns; i++) {
		if (iterator->_vns->ns[i].oui != oui)
			continue;
		if (iterator->_vns->ns[i].subns != subns)
			continue;

		iterator->current_namespace = &iterator->_vns->ns[i];
		break;
	}
}
