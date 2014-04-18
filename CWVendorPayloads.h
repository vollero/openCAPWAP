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
 * Project:  Capwap
 * Authors : Matteo Latini (mtylty@gmail.com)
 * 	     Donato Capitella (d.capitella@gmail.com)											*  
 ************************************************************************************************/


#ifndef __CAPWAP_VendorPayloads__
#define __CAPWAP_VendorPayloads__

/*#include "CWCommon.h"*/
#include "CWAC.h"

/***********************************************************************
 * Vendor specific payloads types
 * *********************************************************************/
#define		CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_UCI		1
#define 	CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_WUM		2

/***********************************************************************
 * UCI Server Port
 * *********************************************************************/
#define UCI_SERVER_PORT 31337

typedef struct {
	unsigned char command;
	char *commandArgs;
	char *response;
} CWVendorUciValues;

CWBool CWParseVendorPayload(CWProtocolMessage *msg, int len, CWProtocolVendorSpecificValues* valPtr);
CWBool CWParseUCIPayload(CWProtocolMessage *msg, CWVendorUciValues **payloadPtr);
CWBool CWWTPSaveUCIValues(CWVendorUciValues *uciPayload, CWProtocolResultCode *resultCode);
CWBool CWAssembleWTPVendorPayloadUCI(CWProtocolMessage *msgPtr);

/*************************************************************************
 *  WTP Update Messages 
 *************************************************************************/

typedef struct { unsigned char major_v; unsigned char min_v; unsigned char revision; } mess_version_info;
typedef struct { mess_version_info v_info; unsigned int pack_size; } mess_up_req;
typedef struct { unsigned int seq_num; unsigned int size; char *buf; } mess_cup;

typedef struct {
	unsigned char type;		/* Message type */
	union {		
		mess_version_info v_resp;
		mess_up_req up_req;
		mess_cup cup;
	} args;
} CWVendorWumValues;

#define _major_v_ args.v_resp.major_v
#define _minor_v_ args.v_resp.min_v
#define _revision_v_ args.v_resp.revision
#define _pack_size_ args.up_req.pack_size
#define _seq_num_ args.cup.seq_num
#define _cup_ args.cup.buf 
#define _cup_fragment_size_ args.cup.size

#define CUP_FRAGMENT_SIZE 4000

//CWBool CWParseWUMPayload(CWProtocolMessage *msg, CWVendorUciValues **payloadPtr);
CWBool CWWTPSaveWUMValues(CWVendorWumValues *wumPayload, CWProtocolResultCode *resultCode);
CWBool CWAssembleWTPVendorPayloadWUM(CWProtocolMessage *msgPtr);


#endif
