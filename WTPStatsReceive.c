/*******************************************************************************************
 * Copyright (c) 2008 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
 *                      Universita' Campus BioMedico - Italy                               *
 *                                                                                         *
 * This program is free software; you can redistribute it and/or modify it under the terms *
 * of the GNU General Public License as published by the Free Software Foundation; either  *
 * version 2 of the License, or (at your option) any later version.                        *
 *                                                                                         *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY         *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A         *
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
 * Author : Daniele De Sanctis (danieledesanctis@gmail.com)                                *
 *                                            						   *
 *******************************************************************************************/


#include "WTPStatsReceive.h"

int create_data_Frame(CWProtocolMessage** frame, char* buffer, int len)	
{
	
	CW_CREATE_OBJECT_ERR(*frame, CWProtocolMessage, return 0;);
	CWProtocolMessage *auxPtr = *frame;
	CW_CREATE_PROTOCOL_MESSAGE(*auxPtr, len, return 0;);
	memcpy(auxPtr->msg, buffer, len);
	auxPtr->offset=len;
	return 1;
}



CW_THREAD_RETURN_TYPE CWWTPReceiveStats(void *arg)
{
	
	int sock,rlen,len,k,fragmentsNum = 0,fromlen;
        MM_MONITOR_DATA* pData;
        struct  sockaddr_un servaddr; 
        struct  sockaddr_un from;
	static char buffer[PACKET_SIZE + 1];
	CWProtocolMessage *completeMsgPtr = NULL;
	CWProtocolMessage* data=NULL;
	CWBindingTransportHeaderValues *bindingValuesPtr=NULL;

	CWThreadSetSignals(SIG_BLOCK, 1, SIGALRM);
	
	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		CWDebugLog("THR STATS: Error creating socket");
		CWExitThread();
	}
	/*
	    if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) 
		{
            CWDebugLog("THR STATS: Error creating socket");
			CWExitThread();
        }
      */  
	/*      Set up address structure for server socket      */
        bzero(&servaddr, sizeof(servaddr));
		bzero(&from, sizeof(from));
        servaddr.sun_family = AF_PACKET; //AF_UNIX;
        strcpy(servaddr.sun_path, SOCKET_PATH);

        unlink(SOCKET_PATH);

		len = sizeof(servaddr.sun_family) + strlen(servaddr.sun_path);

        if (bind(sock, (const struct sockaddr *) &servaddr,len) < 0) 
		{
                CWDebugLog("THR STATS: Error binding socket");
		CWExitThread();
        }

	CW_CREATE_OBJECT_ERR( pData, MM_MONITOR_DATA , EXIT_THREAD);
        fromlen = sizeof(from);


/*      Receive data */
	CW_REPEAT_FOREVER 
	{
		rlen = recvfrom(sock, buffer,PACKET_SIZE, 0, (struct sockaddr *)&from,(socklen_t *)&fromlen);
        	if (rlen == -1) 
		{
        		CWDebugLog("THR STATS: Error receiving from unix socket");
			CWExitThread();   
        	} 
		else 
		{	completeMsgPtr = NULL;
			
			
			if(!create_data_Frame(&data,buffer,rlen)){
								CWDebugLog("Error extracting a data stats frame");
								CWExitThread();
							};

			pData = (MM_MONITOR_DATA*)data->msg;
		
        		
			CW_CREATE_OBJECT_ERR(bindingValuesPtr, CWBindingTransportHeaderValues, EXIT_THREAD);
			bindingValuesPtr->dataRate = -1; //to distinguish between wireless frame e data message (Daniele) see CWBindig.c line 224 
		
			if (CWAssembleDataMessage(&completeMsgPtr, 
						   &fragmentsNum, 
						   gWTPPathMTU, 
						   data, 
						   bindingValuesPtr,
#ifdef CW_NO_DTLS
			       			   CW_PACKET_PLAIN
#else			       
			       			   CW_PACKET_CRYPT
#endif
						   ,0))
				{		
					for (k = 0; k < fragmentsNum; k++) 
					{
#ifdef CW_NO_DTLS
					if (!CWNetworkSendUnsafeConnected(gWTPSocket, completeMsgPtr[k].msg, completeMsgPtr[k].offset)) {
#else
					if (!CWSecuritySend(gWTPSession, completeMsgPtr[k].msg, completeMsgPtr[k].offset)) {
#endif
					CWDebugLog("Failure sending Request");
					break;
						}	
					}	
				}
								
			
			
			for (k = 0; k < fragmentsNum; k++)
			{
				CW_FREE_PROTOCOL_MESSAGE(completeMsgPtr[k]);
			}
			
			CW_FREE_OBJECT(completeMsgPtr);				
			CW_FREE_OBJECT(data);
			CW_FREE_OBJECT(bindingValuesPtr);
		}	
	
	} 
	
	close(sock);
	return(NULL);
}








