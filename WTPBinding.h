/************************************************************************************************
 * Copyright (c) 2006-2009 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica	*
 *                          Universita' Campus BioMedico - Italy								*
 *																								*
 * This program is free software; you can redistribute it and/or modify it under the terms		*
 * of the GNU General Public License as published by the Free Software Foundation; either		*
 * version 2 of the License, or (at your option) any later version.								*
 *																								*
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY				*
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A				*
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.						*
 *																								*
 * You should have received a copy of the GNU General Public License along with this			*
 * program; if not, write to the:																*
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,							*
 * MA  02111-1307, USA.																			*
 *											
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
 * -------------------------------------------------------------------------------------------- *
 * Project:  Capwap																				*
 *																								*
 * Authors : Ludovico Rossi (ludo@bluepixysw.com)												*  
 *           Del Moro Andrea (andrea_delmoro@libero.it)											*
 *           Giovannini Federica (giovannini.federica@gmail.com)								*
 *           Massimo Vellucci (m.vellucci@unicampus.it)											*
 *           Mauro Bisson (mauro.bis@gmail.com)													*
 *	         Antonio Davoli (antonio.davoli@gmail.com)											*
 ************************************************************************************************/


#ifndef __CAPWAP_WTPBinding_HEADER__
#define __CAPWAP_WTPBinding_HEADER__

typedef struct {
	unsigned char radioID;
	WTPQosValues qosValues[NUM_QOS_PROFILES];
} RadioQosValues;

typedef struct {
	int qosCount;
	RadioQosValues *radioQosValues;
} CWBindingConfigurationRequestValues;

typedef struct {
	int qosCount;
	RadioQosValues *radioQosValues;
} CWBindingConfigurationUpdateRequestValues;

/****************************************************
 * 2009 Updates:									*
 *				New Structure for mananagement of	*
 *				OFDM Message Element				*
 ****************************************************/

typedef struct {
  unsigned char radioID;
  OFDMControlValues *radioOFDMValues;
} CWBindingConfigurationUpdateRequestValuesOFDM;


/****************************************************
 * 2009 Updates:									*
 *				Definition of port number and type	*
 *				of commands of Frequency Server		*
 *				Manager (WTP side).					*
 ****************************************************/

#define FREQ_SERVER_ADDR "127.0.0.1"
#define FREQ_SERVER_PORT 1236

CWBool CWWTPInitBinding(int radioIndex);
CWBool CWBindingSaveConfigureResponse(void* bindingValuesPtr, CWProtocolResultCode* resultCode);
CWBool CWBindingSetQosValues(int qosCount, RadioQosValues *radioQosValues, CWProtocolResultCode *resultCode);
CWBool CWBindingParseConfigurationUpdateRequest (char *msg, int len, void **valuesPtr);
CWBool CWBindingParseConfigureResponse (char *msg, int len, void **valuesPtr);
/****************************************************
 * 2009 Updates: (SaveConfiguration)				*	
 *				Prototype Modification (int * added)*
 ****************************************************/
CWBool CWBindingSaveConfigurationUpdateRequest(void* bindingValuesPtr, CWProtocolResultCode* resultCode, int *updateRequestType);
#endif
