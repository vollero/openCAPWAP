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
 *											   *
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

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

const char *CW_CONFIG_FILE = "config.ac";

CWBool CWConfigFileInitLib() {

	gConfigValuesCount = 14;

	CW_CREATE_ARRAY_ERR(gConfigValues,
			    gConfigValuesCount,
			    CWConfigValue,
			    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	gConfigValues[0].type = CW_INTEGER;
	gConfigValues[0].code = "</AC_HW_VERSION>";
	gConfigValues[0].value.int_value = 0;
	
	gConfigValues[1].type = CW_INTEGER;
	gConfigValues[1].code = "</AC_SW_VERSION>";
	gConfigValues[1].value.int_value = 0;
	
	gConfigValues[2].type = CW_INTEGER;
	gConfigValues[2].code = "</AC_MAX_STATIONS>";
	gConfigValues[2].value.int_value = 0;
	
	gConfigValues[3].type = CW_INTEGER;
	gConfigValues[3].code = "</AC_MAX_WTPS>";
	gConfigValues[3].value.int_value = 0;
	
	gConfigValues[4].type = CW_STRING;
	gConfigValues[4].code = "</AC_SECURITY>";
	gConfigValues[4].value.str_value = NULL;
	
	gConfigValues[5].type = CW_STRING;
	gConfigValues[5].code = "</AC_NAME>";
	gConfigValues[5].value.str_value = NULL;
	
	gConfigValues[6].type = CW_STRING_ARRAY;
	gConfigValues[6].code = "<AC_MCAST_GROUPS>";
	gConfigValues[6].endCode = "</AC_MCAST_GROUPS>";
	gConfigValues[6].value.str_array_value = NULL;
	gConfigValues[6].count = 0;
	
	gConfigValues[7].type = CW_INTEGER;
	gConfigValues[7].code = "</AC_FORCE_MTU>";
	gConfigValues[7].value.int_value = 0;
	
	gConfigValues[8].type = CW_STRING;
	gConfigValues[8].code = "</AC_LEV3_PROTOCOL>";
	gConfigValues[8].value.str_value = NULL;

	gConfigValues[9].type = CW_INTEGER;
	gConfigValues[9].code = "</AC_LOG_FILE_ENABLE>";
	gConfigValues[9].value.int_value = 0;

	gConfigValues[10].type = CW_INTEGER;
	gConfigValues[10].code = "</AC_LOG_FILE_SIZE>";
	gConfigValues[10].value.int_value = DEFAULT_LOG_SIZE;
	
	/*
	* Elena Agostini - 02/2014
	*
	* OpenSSL params config.ac
	*/
	gConfigValues[11].type = CW_STRING;
	gConfigValues[11].code = "</AC_SECURITY_CERTIFICATE>";
	gConfigValues[11].value.str_value = NULL;

	gConfigValues[12].type = CW_STRING;
	gConfigValues[12].code = "</AC_SECURITY_KEYFILE>";
	gConfigValues[12].value.str_value = NULL;

	gConfigValues[13].type = CW_STRING;
	gConfigValues[13].code = "</AC_SECURITY_PASSWORD>";
	gConfigValues[13].value.str_value = NULL;

	return CW_TRUE;
}

CWBool CWConfigFileDestroyLib() {

	int  i;
	int indexBlank=0;

	/* save the preferences we read */
	gACHWVersion = gConfigValues[0].value.int_value;
	gACSWVersion = gConfigValues[1].value.int_value;
	gLimit = gConfigValues[2].value.int_value;
	gMaxWTPs = gConfigValues[3].value.int_value;

	/*
	 * Elena Agostini - 02/2014
	 *
	 * Ignore spaces in configuration values
	 */

	if(gConfigValues[4].value.str_value != NULL)
	{
		CW_STRING_GET_START_WHITE_SPACES((gConfigValues[4].value.str_value), indexBlank);
		if(!strcmp((gConfigValues[4].value.str_value)+indexBlank, "PRESHARED")) {	
			gACDescriptorSecurity = CW_PRESHARED;
		} else { 
			/* default */
			gACDescriptorSecurity = CW_X509_CERTIFICATE;
		}
	}

	if(gConfigValues[5].value.str_value != NULL) {
		/*
		 * Elena Agostini - 02/2014
		 *
		 * Ignore spaces in configuration values
		 */
		CW_STRING_GET_START_WHITE_SPACES((gConfigValues[5].value.str_value), indexBlank);
		CW_CREATE_STRING_FROM_STRING_ERR(gACName,
						 (gConfigValues[5].value.str_value)+indexBlank,
						 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		//CW_FREE_OBJECT(gACName);
	}
	
	/* avoid to allocate 0 bytes */
	if (gConfigValues[6].count) {
	
		CW_CREATE_ARRAY_ERR(gMulticastGroups, gConfigValues[6].count, char*, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
		for(i = 0; i < gConfigValues[6].count; i++) {

			CW_CREATE_STRING_FROM_STRING_ERR(gMulticastGroups[i],
							 (gConfigValues[6].value.str_array_value)[i],
							 return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		}
	}

	gMulticastGroupsCount = gConfigValues[6].count;
	CW_PRINT_STRING_ARRAY(gMulticastGroups, gMulticastGroupsCount);
	
	gCWForceMTU = gConfigValues[7].value.int_value;
	
	if(gConfigValues[8].value.str_value != NULL && !strcmp(gConfigValues[8].value.str_value, "IPv6")) {
		
		gNetworkPreferredFamily = CW_IPv6;
	} else { 
		/* default */
		gNetworkPreferredFamily = CW_IPv4;
	}
	
	/*
	 * Elena Agostini - 02/2014
	 *
	 * Ignore spaces in configuration values
	 * Get OpenSSL params values
	 */
	gEnabledLog = gConfigValues[9].value.int_value;
	gMaxLogFileSize = gConfigValues[10].value.int_value;

	if(gConfigValues[11].value.str_value != NULL) {
		CW_STRING_GET_START_WHITE_SPACES((gConfigValues[11].value.str_value), indexBlank);
		CW_CREATE_STRING_FROM_STRING_ERR(gACCertificate, (gConfigValues[11].value.str_value)+indexBlank, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}
	if(gConfigValues[12].value.str_value != NULL) {
		CW_STRING_GET_START_WHITE_SPACES((gConfigValues[12].value.str_value), indexBlank);
		CW_CREATE_STRING_FROM_STRING_ERR(gACKeyfile, (gConfigValues[12].value.str_value)+indexBlank, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}
	if(gConfigValues[13].value.str_value != NULL) {
		CW_STRING_GET_START_WHITE_SPACES((gConfigValues[13].value.str_value), indexBlank);
		CW_CREATE_STRING_FROM_STRING_ERR(gACPassword, (gConfigValues[13].value.str_value)+indexBlank, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}


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

