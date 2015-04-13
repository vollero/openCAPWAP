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

int gCWForceMTU = 0;
int gCWRetransmitTimer = CW_RETRANSMIT_INTERVAL_DEFAULT;	//Default value for RetransmitInterval
int gCWNeighborDeadInterval = CW_NEIGHBORDEAD_INTERVAL_DEFAULT; //Default value for NeighbourDeadInterval (no less than 2*EchoInterval and no greater than 240) 
int gCWMaxRetransmit = CW_MAX_RETRANSMIT_DEFAULT;		//Default value for MaxRetransmit 

int CWTimevalSubtract(struct timeval *res, const struct timeval *x, const struct timeval *y){
	int nsec;
	struct timeval z=*y;
   
	// Perform the carry for the later subtraction by updating Y
	if (x->tv_usec < z.tv_usec) {
		nsec = (z.tv_usec - x->tv_usec) / 1000000 + 1;
		z.tv_usec -= 1000000 * nsec;
		z.tv_sec += nsec;
	}
	if (x->tv_usec - z.tv_usec > 1000000) {
		nsec = (x->tv_usec - z.tv_usec) / 1000000;
		z.tv_usec += 1000000 * nsec;
		z.tv_sec -= nsec;
	}

	// Compute the time remaining to wait. `tv_usec' is certainly positive
	if ( res != NULL){
		res->tv_sec = x->tv_sec - z.tv_sec;
		res->tv_usec = x->tv_usec - z.tv_usec;
	}

	// Return 1 if result is negative (x < y)
	return ((x->tv_sec < z.tv_sec) || ((x->tv_sec == z.tv_sec) && (x->tv_usec < z.tv_usec)));
}

/*
 * Elena Agostini - 09/2014: IEEE Binding utils: radioID and wlanID cannot be <= 0
 */
int CWIEEEBindingGetIndexFromDevID(int devID)
{
	return devID;
	/*
	 if(devID <= 0)
		return -1;
		
	return (devID-1);
	*/
}

int CWIEEEBindingGetDevFromIndexID(int indexID)
{
	 if(indexID < 0)
		return -1;
		
	return (indexID+1);
}

void CWPrintEthernetAddress(unsigned char * address, char * string) {
	
	if(address == NULL)
		return;
	
	if(string == NULL)
		CWLog("%02x:%02x:%02x:%02x:%02x:%02x", (int)address[0], (int)address[1], (int)address[2], (int)address[3], (int)address[4], (int)address[5]);
	else
		CWLog("%s -> %02x:%02x:%02x:%02x:%02x:%02x", string, (int)address[0], (int)address[1], (int)address[2], (int)address[3], (int)address[4], (int)address[5]);
}

int CWCompareEthernetAddress(unsigned char * address1, unsigned char * address2) {
	
	int index;
	
	if(address1 == NULL || address2 == NULL)
		return -1;
	
	for(index=0; index < ETH_ALEN; index++)
	{
		if(
			address1[index] && address2[index] &&
			address1[index] != address2 [index]
		)
			return -1;
	}
	
	return 0;
}
