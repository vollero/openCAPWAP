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
 * --------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                        *
 *                                                                                         *
 * Author :  Ludovico Rossi (ludo@bluepixysw.com)                                          *  
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                    *
 *           Giovannini Federica (giovannini.federica@gmail.com)                           *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                    *
 *           Mauro Bisson (mauro.bis@gmail.com)                                            *
 *******************************************************************************************/


 
#include "CWAC.h"
#include "CWCommon.h"
#include "tap.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

/*_________________________________________________________*/
/*  *******************___VARIABLES___*******************  */
CWThreadMutex gCreateIDMutex;

/* array that stores per WTPs infos */
CWWTPManager gWTPs[CW_MAX_WTP];
CWThreadMutex gWTPsMutex;

int gEnabledLog;
int gMaxLogFileSize;
char gLogFileName[]=AC_LOG_FILE_NAME;

/* number of active WTPs */
int gActiveWTPs = 0;
CWThreadMutex gActiveWTPsMutex;

/* max WTPs */
int gMaxWTPs;
/* The Radio MAC Field of the discovery response */
/* Elena Agostini - 02/2014: Radio MAC Field is not reserved */
int gRMACField = 2;
/* The Wireless Field of the discovery response */
int gWirelessField = 0;
/* DTLS Policy for data channel */
int gDTLSPolicy=DTLS_ENABLED_DATA;
/* special socket to handle multiple network interfaces */
CWMultiHomedSocket gACSocket;
/* AC's network interfaces */
CWProtocolNetworkInterface *gInterfaces = NULL;
int gInterfacesCount = 0;
/* DTLS Context */
CWSecurityContext gACSecurityContext;
int gActiveStations = 0;
/*
 * Elena Agostini - 02/2014
 * OpenSSL params variables
 */
char *gACCertificate=NULL;
char *gACKeyfile=NULL;
char *gACPassword=NULL;
/*
 * Elena Agostini - 02/2014
 *
 * ECN Support Msg Elem MUST be included in Join Request/Response Messages
 */
int gACECNSupport=0;

/*
 * Elena Agostini - 03/2014: DTLS Data Channel
 */
CWBool ACSessionDataActive;
genericHandshakeThreadPtr listGenericThreadDTLSData[WTP_MAX_TMP_THREAD_DTLS_DATA];

/* max stations */
int gLimit;
char **gMulticastGroups;
int gMulticastGroupsCount;
CWAuthSecurity gACDescriptorSecurity;
int gACHWVersion;
int gACSWVersion;
char *gACName = NULL;

int gDiscoveryTimer=20;
int gEchoRequestTimer=CW_ECHO_INTERVAL_DEFAULT;
/* PROVVISORIO: Il valore e' scelto a caso */
int gIdleTimeout=10;

//Elena Agostini - 11/2014: avlTree for WTP - STA associated
nodeAVL * avlTree = NULL;
CWThreadMutex mutexAvlTree;

int ACTap_FD;
char * ACTap_name;


/*_________________________________________________________*/
/*  *******************___FUNCTIONS___*******************  */
int main (int argc, const char * argv[]) {

	/* Daemon mode */
	
	if (argc <= 1)
		printf("Usage: AC working_path\n");

	if (daemon(1, 0) < 0)
		exit(1);

	if (chdir(argv[1]) != 0)
		exit(1);
	
	CWACInit();
	CWACEnterMainLoop();
	CWACDestroy();  
	 
	return 0;
}

int CWACSemPostForOpenSSLHack(void *s) {

	CWThreadTimedSem *semPtr = (CWThreadTimedSem*) s;
	
	if(!CWThreadTimedSemIsZero(semPtr)) {
		CWLog("This Semaphore's Value should really be 0");
		/* note: we can consider setting the value to 0 and going on,
		 * that is what we do here
		 */
		if(!CWErr(CWThreadTimedSemSetValue(semPtr, 0))) return 0;
	}
	
	if(!CWErr(CWThreadTimedSemPost(semPtr))) {
		return 0;
	}
	 
	return 1;
}

void CWACInit() {
	int i, index=0;
	CWNetworkLev4Address *addresses = NULL;
	struct sockaddr_in *IPv4Addresses = NULL;
	
	CWLogInitFile(AC_LOG_FILE_NAME);

	#ifndef CW_SINGLE_THREAD
		CWDebugLog("Use Threads");
	#else
		CWDebugLog("Don't Use Threads");
	#endif
	
	CWErrorHandlingInitLib();
	
	if(!CWParseSettingsFile())
	{
		CWLog("Can't start AC");
		exit(1);
	}
	
	//Elena Agostini - 07/2014: initialize listGenericThreadDTLSData
	for(index=0; index < WTP_MAX_TMP_THREAD_DTLS_DATA; index++)
		listGenericThreadDTLSData[index] = NULL;
	
	CWLog("Starting AC");

	CWThreadSetSignals(SIG_BLOCK, 1, SIGALRM);
	if (timer_init() == 0) {
		CWLog("Can't init timer module");
		exit(1);
	}

/* Elena Agostini - 04/2014 */
	if(!CWErr(CWParseConfigFile()) ||
#if !defined(CW_NO_DTLS) || defined(CW_DTLS_DATA_CHANNEL)
	   !CWErr(CWSecurityInitLib()) ||
#endif
	   !CWErr(CWNetworkInitSocketServerMultiHomed(&gACSocket, CW_CONTROL_PORT, gMulticastGroups, gMulticastGroupsCount)) ||
	   !CWErr(CWNetworkGetInterfaceAddresses(&gACSocket, &addresses, &IPv4Addresses)) ||
	   !CWErr(CWCreateThreadMutex(&gWTPsMutex)) ||
	   !CWErr(CWCreateThreadMutex(&gActiveWTPsMutex))) {

		/* error starting */
		CWLog("Can't start AC");
		exit(1);
	}

/* Elena Agostini - 04/2014 */
#if !defined(CW_NO_DTLS) || defined(CW_DTLS_DATA_CHANNEL)
	if(gACDescriptorSecurity == CW_X509_CERTIFICATE) {

		/*
		 * Elena Agostini - 02/2014
		 * Dynamic OpenSSL params
		 */
		if(!CWErr(CWSecurityInitContext(&gACSecurityContext,
						gACCertificate,
						gACKeyfile,
						gACPassword,
						CW_FALSE,
						CWACSemPostForOpenSSLHack))) {
			CWLog("Can't start AC");
			exit(1);
		}
	} else { /* preshared */
		if(!CWErr(CWSecurityInitContext(&gACSecurityContext,
						NULL,
						NULL,
						NULL,
						CW_FALSE,
						CWACSemPostForOpenSSLHack))) {
			CWLog("Can't start AC");
			exit(1);
		}
	}
#endif
	CW_FREE_OBJECTS_ARRAY(gMulticastGroups, gMulticastGroupsCount);

	for(i = 0; i < gMaxWTPs; i++) {
		gWTPs[i].isNotFree = CW_FALSE;
		
		/*
		if (!gWTPs[i].tap_fd){
		    init_AC_tap_interface(i);
		}
		*/
	}
//Elena Agostini: Unique AC Tap Interface
	if(!CWACTapInterfaceInit())
	{
		CWLog("Error in AC Tap Interface creation");
		exit(-1);
	}
	/* store network interface's addresses */
	gInterfacesCount = CWNetworkCountInterfaceAddresses(&gACSocket);
	CWLog("Found %d Network Interface(s)", gInterfacesCount);
	
	if (gInterfacesCount<=0){
		CWLog("Can't start AC");
		exit(1);
	}

	CW_CREATE_ARRAY_ERR(gInterfaces, 
			    gInterfacesCount,
			    CWProtocolNetworkInterface,
			    CWLog("Out of Memory"); return;);

	for(i = 0; i < gInterfacesCount; i++) {
		gInterfaces[i].WTPCount = 0;
		CW_COPY_NET_ADDR_PTR(&(gInterfaces[i].addr), ((CWNetworkLev4Address*)&((addresses)[i])) );
		if(IPv4Addresses != NULL) {
			CW_COPY_NET_ADDR_PTR(&(gInterfaces[i].addrIPv4), &((IPv4Addresses)[i]));
		}
	}
	CW_FREE_OBJECT(addresses);
	CW_FREE_OBJECT(IPv4Addresses);

	if(!CWErr(CWCreateThreadMutex(&gCreateIDMutex))) {
		exit(1);
	}

	//Elena Agostini - 11/2014: AVL WTP - STA mutex
	CWCreateThreadMutex(&(mutexAvlTree));
	
	CWLog("AC Started");
}

void CWACDestroy() {
	
	CWNetworkCloseMultiHomedSocket(&gACSocket);
	
	/*
	for(i = 0; i < CW_MAX_WTP; i++) {
		//CW_FREE_OBJECT(gWTPs[i].addr);
	}
	*/

	CWSslCleanUp();

	CWDestroyThreadMutex(&gWTPsMutex);
	CWDestroyThreadMutex(&gCreateIDMutex);
	CWDestroyThreadMutex(&gActiveWTPsMutex);
	
	CW_FREE_OBJECT(gACName);
	CW_FREE_OBJECT(gInterfaces);
	
	CWLog("AC Destroyed");
}


__inline__ unsigned int CWGetSeqNum() {

	static unsigned int seqNum = 0;
	unsigned int r;
	
	if(!CWThreadMutexLock(&gCreateIDMutex)) {
		
		CWDebugLog("Error Locking a mutex");
	}
	
	r = seqNum;
	
	if (seqNum==CW_MAX_SEQ_NUM) 
		seqNum=0;
	else 
		seqNum++;

	CWThreadMutexUnlock(&gCreateIDMutex);
	return r;
}


__inline__ int CWGetFragmentID() {

	static int fragID = 0;
	int r;

	if(!CWThreadMutexLock(&gCreateIDMutex)) {
		
		CWDebugLog("Error Locking a mutex");
	}
	
	r = fragID;
	
	if (fragID==CW_MAX_FRAGMENT_ID) 
		fragID=0;
	else 
		fragID++;

	CWThreadMutexUnlock(&gCreateIDMutex);
	return r;
}


