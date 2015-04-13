/*******************************************************************************************
 * Copyright (c) 2006-7 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
 *                      Universita' Campus BioMedico - Italy                               *
 *                                                                                         *
 * This program is free software; you can redistribute it and/or modify it under the terms *
 * of the GNU General Public License as published by the Free Software Foundation; either  *
 * version 2 of the License, or (at your option) any later version.                        *
 *                                                                                         *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY         *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 	   *
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

CWBool CWAssembleChangeStateEventRequest(CWProtocolMessage **messagesPtr,
					 int *fragmentsNumPtr,
					 int PMTU,
					 int seqNum,
					 CWList msgElemList);

CWBool CWParseChangeStateEventResponseMessage(char *msg,
					      int len,
					      int seqNum,
					      void *values);

CWBool CWSaveChangeStateEventResponseMessage(void *changeStateEventResp);

CWStateTransition CWWTPEnterDataCheck() {

	int seqNum;
	
	CWLog("\n");
	CWLog("######### Data Check State #########");
	
	CWLog("\n");
	CWLog("#________ Change State Event (Data Check) ________#");
	
	/* Send Change State Event Request */
	seqNum = CWGetSeqNum();
	
	if(!CWErr(CWWTPSendAcknowledgedPacket(seqNum, 
					      NULL,
					      CWAssembleChangeStateEventRequest,
					      CWParseChangeStateEventResponseMessage,
					      CWSaveChangeStateEventResponseMessage,
					      NULL)))
		return CW_ENTER_RESET;
	
/*
 * Elena Agostini - 03/2014
 * Initilize DTLS Data Session WTP + first KeepAlive
 */

#ifdef CW_DTLS_DATA_CHANNEL

	int 			n,readBytes;
	char 			buf[CW_BUFFER_SIZE];
	CWNetworkLev4Address	addr;
	CWList 			fragments = NULL;
	CWProtocolMessage 	msgPtr;
	CWBool 			dataFlag = CW_TRUE;
	int msg_len;
	
	struct sockaddr_in *tmpAdd = (struct sockaddr_in *) &(gACInfoPtr->preferredAddress);
	tmpAdd->sin_port = htons(5247);
	CWLog("[DTLS] WTP Run Handshake with %s:%d", inet_ntoa(tmpAdd->sin_addr), ntohs(tmpAdd->sin_port));

	CWNetworkLev4Address * gACAddressDataChannel = (CWNetworkLev4Address *)tmpAdd;
	
	if(!CWErr(CWSecurityInitSessionClient(gWTPDataSocket,
					      gACAddressDataChannel,
					      gPacketReceiveDataList,
					      gWTPSecurityContext,
					      &gWTPSessionData,
					      &gWTPPathMTU))) {
		
		/* error setting up DTLS session */
		CWSecurityDestroyContext(gWTPSecurityContext);
		gWTPSecurityContext = NULL;
		return CW_FALSE;
	}
	
	CWLog("[DTLS] OK now assemble first KeepAlive");
	
	/*
	 * If handshake ok, first KeepAlive DTLS to AC 
	 */
	CWProtocolMessage *messages = NULL;
	CWProtocolMessage sessionIDmsgElem;
	int fragmentsNum = 1;

	CWAssembleMsgElemSessionID(&sessionIDmsgElem, &gWTPSessionID[0]);
	sessionIDmsgElem.data_msgType = CW_DATA_MSG_KEEP_ALIVE_TYPE;
	
	//Send WTP Event Request
	if (!CWAssembleDataMessage(&messages, 
			    &fragmentsNum, 
			    gWTPPathMTU, 
			    &sessionIDmsgElem, 
			    NULL,
				CW_PACKET_CRYPT,
			    1
			    ))
	{
		int i;

		CWDebugLog("Failure Assembling KeepAlive Request");
		if(messages)
			for(i = 0; i < fragmentsNum; i++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[i]);
			}	
		CW_FREE_OBJECT(messages);
		return;
	}
	
	int i;
	for(i = 0; i < fragmentsNum; i++) {
		if(!(CWSecuritySend(gWTPSessionData, messages[i].msg, messages[i].offset))) {
			CWLog("Failure sending  KeepAlive Request");
			int k;
			for(k = 0; k < fragmentsNum; k++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[k]);
			}	
			CW_FREE_OBJECT(messages);
			break;
		}
	}

	int k;
	for(k = 0; messages && k < fragmentsNum; k++) {
		CW_FREE_PROTOCOL_MESSAGE(messages[k]);
	}	
	CW_FREE_OBJECT(messages);
	
	CWLog("Send KeepAlive");
	
	if(!CWReceiveDataMessage(&msgPtr))
		{
			CW_FREE_PROTOCOL_MESSAGE(msgPtr);
			CWDebugLog("Failure Receiving DTLS Data Channel");
			return CW_ENTER_RESET;		
		}
				
	if (msgPtr.data_msgType == CW_DATA_MSG_KEEP_ALIVE_TYPE) {
		return CW_ENTER_RUN;
	}
			
#endif
	
	return CW_ENTER_RUN;
}

CWBool CWAssembleChangeStateEventRequest(CWProtocolMessage **messagesPtr,
					 int *fragmentsNumPtr,
					 int PMTU,
					 int seqNum,
					 CWList msgElemList) {

	CWProtocolMessage 	*msgElems= NULL;
	CWProtocolMessage 	*msgElemsBinding= NULL;
	const int		msgElemCount = 2;
	int 			msgElemBindingCount=0;
	int 			resultCode = CW_PROTOCOL_SUCCESS;
	int 			k = -1;
	
	if(messagesPtr == NULL || fragmentsNumPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, 
					 msgElemCount,
					 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););	
		
	CWLog("Assembling Change State Event Request...");	

	/* Assemble Message Elements */
	if (!(CWAssembleMsgElemRadioOperationalState(-1, &(msgElems[++k]))) ||
	    !(CWAssembleMsgElemResultCode(&(msgElems[++k]), resultCode))) {

		int i;
	
		for(i = 0; i <= k; i++) { 
			
			CW_FREE_PROTOCOL_MESSAGE(msgElems[i]);
		}
		CW_FREE_OBJECT(msgElems);
		/* error will be handled by the caller */
		return CW_FALSE;
	}

	if (!(CWAssembleMessage(messagesPtr,
				fragmentsNumPtr,
				PMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_CHANGE_STATE_EVENT_REQUEST,
				msgElems, msgElemCount,
				msgElemsBinding,
				msgElemBindingCount,
#ifdef CW_NO_DTLS
				CW_PACKET_PLAIN
#else
				CW_PACKET_CRYPT
#endif
				)))
	 	return CW_FALSE;
	
	CWLog("Change State Event Request Assembled");
	return CW_TRUE;
}

CWBool CWParseChangeStateEventResponseMessage(char *msg,
					      int len,
					      int seqNum,
					      void *values) {

	CWControlHeaderValues controlVal;
	CWProtocolMessage completeMsg;
	
	if(msg == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWLog("Parsing Change State Event Response...");
	
	completeMsg.msg = msg;
	completeMsg.offset = 0;
	
	/* error will be handled by the caller */
	if(!(CWParseControlHeader(&completeMsg, &controlVal))) return CW_FALSE; 
	
	if(controlVal.messageTypeValue != CW_MSG_TYPE_VALUE_CHANGE_STATE_EVENT_RESPONSE)
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, 
				    "Message is not Change State Event Response as Expected");
	
	if(controlVal.seqNum != seqNum) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Different Sequence Number");
	
	/* skip timestamp */
	controlVal.msgElemsLen -= CW_CONTROL_HEADER_OFFSET_FOR_MSG_ELEMS;
	
	if(controlVal.msgElemsLen != 0 ) 
		return CWErrorRaise(CW_ERROR_INVALID_FORMAT, 
				    "Change State Event Response must carry no message elements");

	CWLog("Change State Event Response Parsed");
	return CW_TRUE;
}

CWBool CWSaveChangeStateEventResponseMessage (void *changeStateEventResp)
{
	CWDebugLog("Saving Change State Event Response...");
	CWDebugLog("Change State Event Response Saved");
	return CW_TRUE;
}
