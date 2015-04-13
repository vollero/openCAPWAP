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

const char *CW_CONFIG_FILE = "config.wtp";

CWBool CWConfigFileInitLib() {
	
	gConfigValuesCount = 14;

	CW_CREATE_ARRAY_ERR(gConfigValues, gConfigValuesCount, CWConfigValue, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	gConfigValues[0].type = CW_STRING_ARRAY;
	gConfigValues[0].code = "<AC_ADDRESSES>";
	gConfigValues[0].endCode = "</AC_ADDRESSES>";
	gConfigValues[0].value.str_array_value = NULL;
	gConfigValues[0].count = 0;
	
	gConfigValues[1].type = CW_INTEGER;
	gConfigValues[1].code = "</WTP_FORCE_MTU>";
	gConfigValues[1].value.int_value = 0;
	
	gConfigValues[2].type = CW_STRING;
	gConfigValues[2].code = "</WTP_LEV3_PROTOCOL>";
	gConfigValues[2].value.str_value = NULL;
	
	gConfigValues[3].type = CW_STRING;
	gConfigValues[3].code = "</WTP_NAME>";
	gConfigValues[3].value.str_value = NULL;
	
	gConfigValues[4].type = CW_STRING;
	gConfigValues[4].code = "</WTP_LOCATION>";
	gConfigValues[4].value.str_value = NULL;
	
	gConfigValues[5].type = CW_STRING;
	gConfigValues[5].code = "</WTP_FORCE_AC_ADDRESS>";
	gConfigValues[5].value.str_value = NULL;
	
	gConfigValues[6].type = CW_STRING;
	gConfigValues[6].code = "</WTP_FORCE_SECURITY>";
	gConfigValues[6].value.str_value = NULL;

	gConfigValues[7].type = CW_INTEGER;
	gConfigValues[7].code = "</WTP_LOG_FILE_ENABLE>";
	gConfigValues[7].value.int_value = 0;

	gConfigValues[8].type = CW_INTEGER;
	gConfigValues[8].code = "</WTP_LOG_FILE_SIZE>";
	gConfigValues[8].value.int_value = DEFAULT_LOG_SIZE;
	
	/* Elena Agostini - 02/2014: OpenSSL params config.wtp */
	gConfigValues[9].type = CW_STRING;
	gConfigValues[9].code = "</WTP_SECURITY_CERTIFICATE>";
	gConfigValues[9].value.str_value = NULL;

	gConfigValues[10].type = CW_STRING;
	gConfigValues[10].code = "</WTP_SECURITY_KEYFILE>";
	gConfigValues[10].value.str_value = NULL;

	gConfigValues[11].type = CW_STRING;
	gConfigValues[11].code = "</WTP_SECURITY_PASSWORD>";
	gConfigValues[11].value.str_value = NULL;


	/* Elena Agostini - 02/2014: Port number params config.wtp */
	gConfigValues[12].type = CW_INTEGER;
	gConfigValues[12].code = "</WTP_PORT_CONTROL>";
	gConfigValues[12].value.int_value = -1;

	gConfigValues[13].type = CW_INTEGER;
	gConfigValues[13].code = "</WTP_PORT_DATA>";
	gConfigValues[13].value.int_value = -1;

/*
	gConfigValues[14].type = CW_STRING;
	gConfigValues[14].code = "</WTP_LOG_FILE>";
	gConfigValues[14].value.str_value = NULL;
*/
	return CW_TRUE;
}

CWBool CWConfigFileDestroyLib() {
	int  i;
	int indexBlank=0;

	// save the preferences we read	
	CW_CREATE_ARRAY_ERR(gCWACAddresses, gConfigValues[0].count, char*, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < gConfigValues[0].count; i++) {
		CW_CREATE_STRING_FROM_STRING_ERR(gCWACAddresses[i], ((gConfigValues[0].value.str_array_value)[i])+indexBlank, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}
	
	gCWACCount = gConfigValues[0].count;
	
	#ifdef CW_DEBUGGING
		CW_PRINT_STRING_ARRAY(gCWACAddresses, gCWACCount);
	#endif
	
	gCWForceMTU = gConfigValues[1].value.int_value;
	
	if(gConfigValues[2].value.str_value != NULL && !strcmp(gConfigValues[2].value.str_value, "IPv6")) {
		gNetworkPreferredFamily = CW_IPv6;
	} else { // default
		gNetworkPreferredFamily = CW_IPv4;
	}
	
	if(gConfigValues[3].value.str_value != NULL) {
		/*
		 * Elena Agostini - 02/2014
		 *
		 * Ignore spaces in configuration values
		 */
		CW_STRING_GET_START_WHITE_SPACES((gConfigValues[3].value.str_value), indexBlank);
		CW_CREATE_STRING_FROM_STRING_ERR(gWTPName, (gConfigValues[3].value.str_value)+indexBlank, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}
	if(gConfigValues[4].value.str_value != NULL) {
		/*
		 * Elena Agostini - 02/2014
		 *
		 * Ignore spaces in configuration values
		 */
		CW_STRING_GET_START_WHITE_SPACES((gConfigValues[4].value.str_value), indexBlank);
		CW_CREATE_STRING_FROM_STRING_ERR(gWTPLocation, (gConfigValues[4].value.str_value)+indexBlank, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}
	if(gConfigValues[5].value.str_value != NULL) {
		/*
		 * Elena Agostini - 02/2014
		 *
		 * Ignore spaces in configuration values
		 */
		CW_STRING_GET_START_WHITE_SPACES((gConfigValues[5].value.str_value), indexBlank);
		CW_CREATE_STRING_FROM_STRING_ERR(gWTPForceACAddress, (gConfigValues[5].value.str_value)+indexBlank, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}
	
	
	/*
	 * Elena Agostini - 02/2014
	 *
	 * Ignore spaces in configuration values
	 */
	if(gConfigValues[6].value.str_value != NULL)
	{
		CW_STRING_GET_START_WHITE_SPACES((gConfigValues[6].value.str_value), indexBlank);
		if(!strcmp((gConfigValues[6].value.str_value)+indexBlank, "PRESHARED")) {	
			gWTPForceSecurity = CW_PRESHARED;
		} else { 
			/* default */
			gWTPForceSecurity = CW_X509_CERTIFICATE;
		}
	}

	
	/*
	 * Elena Agostini - 02/2014
	 *
	 * Ignore spaces in configuration values
	 * Get OpenSSL params values
	 */
	gEnabledLog=gConfigValues[7].value.int_value;
	gMaxLogFileSize=gConfigValues[8].value.int_value;

	if(gConfigValues[9].value.str_value != NULL) {
		CW_STRING_GET_START_WHITE_SPACES((gConfigValues[9].value.str_value), indexBlank);
		CW_CREATE_STRING_FROM_STRING_ERR(gWTPCertificate, (gConfigValues[9].value.str_value)+indexBlank, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););


	}
	if(gConfigValues[10].value.str_value != NULL) {
		CW_STRING_GET_START_WHITE_SPACES((gConfigValues[10].value.str_value), indexBlank);
		CW_CREATE_STRING_FROM_STRING_ERR(gWTPKeyfile, (gConfigValues[10].value.str_value)+indexBlank, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	}
	if(gConfigValues[11].value.str_value != NULL) {
		CW_STRING_GET_START_WHITE_SPACES((gConfigValues[11].value.str_value), indexBlank);
		CW_CREATE_STRING_FROM_STRING_ERR(gWTPPassword, (gConfigValues[11].value.str_value)+indexBlank, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}

	/* Elena Agostini - 02/2014: Port number params config.wtp */
	WTP_PORT_CONTROL=gConfigValues[12].value.int_value;
	WTP_PORT_DATA=gConfigValues[13].value.int_value;
	
	/* Elena Agostini - 04/2014: custom WTP log file name */
	/*
	if(gConfigValues[14].value.str_value != NULL) {
		CW_STRING_GET_START_WHITE_SPACES((gConfigValues[14].value.str_value), indexBlank);
		CW_CREATE_STRING_FROM_STRING_ERR(WTP_LOG_FILE_NAME, (gConfigValues[14].value.str_value)+indexBlank, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}
	*/
	for(i = 0; i < gConfigValuesCount; i++) {
		if(gConfigValues[i].type == CW_STRING) {
			CW_FREE_OBJECT(gConfigValues[i].value.str_value);
		} else if(gConfigValues[i].type == CW_STRING_ARRAY) {
			CW_FREE_OBJECTS_ARRAY((gConfigValues[i].value.str_array_value), gConfigValues[i].count);
		}
	}

	CW_FREE_OBJECT(gConfigValues);
	
	return CW_TRUE;
}

