/* 
 * Copyright (C) 2012 Yee Young Han <websearch@naver.com> (http://blog.naver.com/websearch)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */

#include "SnmpPlatformDefine.h"
#include "TestSnmpParser.h"
#include <openssl/des.h>
#include <string.h>
#include "MemoryDebug.h"

static bool TestDecrypt( )
{
	const char * pszHexPacket = "308180020103300f02022905020300ffe304010702010304383036040d80001f88809b26630b890ed353020109020302d7dc04057573657231040c3559f2da879ea3b86b2b9679040800000001166d411204305a06d0740666bc6dac3e93518b6afd5487784cf5c58b2d338ef8b05a368838d107d9409ba135bb1be39b9c0c78e48cc9";
	const char * pszEngineId = "80001f88809b26630b890ed353";
	const char * pszPrivParam = "00000001166d4112";
	int iHexLen = strlen(pszHexPacket);
	unsigned char szPacket[1500], szEngineId[51], szPrivParam[51], szPdu[1500], szIv[8];
	int iIndex = 0, iEngineIdLen = 0, iPrivParamLen = 0, iPduPos = 83;

	unsigned char szKey[16], szAuthKey[16], szResult[512];
	unsigned int iResultSize = sizeof(szResult);

	iIndex = HexToString( pszHexPacket, (char *)szPacket, sizeof(szPacket) );
	if( iIndex == -1 ) return false;

	iEngineIdLen = HexToString( pszEngineId, (char *)szEngineId, sizeof(szEngineId) );
	if( iEngineIdLen == -1 ) return false;

	iPrivParamLen = HexToString( pszPrivParam, (char *)szPrivParam, sizeof(szPrivParam) );
	if( iPrivParamLen == -1 ) return false;

	GetKey( "xpassword", szKey );
	GetAuthKey( szKey, szEngineId, iEngineIdLen, szAuthKey );

	for( int i = 0; i < 8; ++i )
	{
		szIv[i] = szPrivParam[i] ^ szAuthKey[8+i];
	}

	memset( szPdu, 0, sizeof(szPdu) );

  DES_key_schedule	sttKeySchedule;
  DES_cblock				sttBlock;

	memcpy( sttBlock, szAuthKey, sizeof(sttBlock) );
	DES_key_sched( &sttBlock, &sttKeySchedule );

	DES_cbc_encrypt( szPacket + iPduPos, szPdu, iIndex - iPduPos, &sttKeySchedule, (DES_cblock *)szIv, DES_DECRYPT );

	return true;
}

static bool TestEncrypt( )
{
	const char * pszHexPdu = "302d040d80001f88809b26630b890ed3530400a01a020267e8020100020100300e300c06082b060102010101000500";
	const char * pszEngineId = "80001f88809b26630b890ed353";
	const char * pszPrivParam = "00000001166d4112";
	const char * pszResult = "5a06d0740666bc6dac3e93518b6afd5487784cf5c58b2d338ef8b05a368838d107d9409ba135bb1be39b9c0c78e48cc9";
	unsigned char szEngineId[51], szPrivParam[51], szPdu[255], szEncrypt[255], szIv[8], szHex[255];
	int iEngineIdLen = 0, iPrivParamLen = 0, iPduLen = 0;

	unsigned char szKey[16], szAuthKey[16], szResult[512];
	unsigned int iResultSize = sizeof(szResult);

	iPduLen = HexToString( pszHexPdu, (char *)szPdu, sizeof(szPdu) );
	if( iPduLen == -1 ) return false;

	int iPadLen = 8 - iPduLen % 8;
	if( iPadLen == 8 ) iPadLen = 0;

	if( iPadLen > 0 )
	{
		for( int i = 0; i < iPadLen; ++i )
		{
			szPdu[iPduLen+i] = 1;
		}

		iPduLen += iPadLen;
	}

	iEngineIdLen = HexToString( pszEngineId, (char *)szEngineId, sizeof(szEngineId) );
	if( iEngineIdLen == -1 ) return false;

	iPrivParamLen = HexToString( pszPrivParam, (char *)szPrivParam, sizeof(szPrivParam) );
	if( iPrivParamLen == -1 ) return false;

	GetKey( "xpassword", szKey );
	GetAuthKey( szKey, szEngineId, iEngineIdLen, szAuthKey );

	for( int i = 0; i < 8; ++i )
	{
		szIv[i] = szPrivParam[i] ^ szAuthKey[8+i];
	}

  DES_key_schedule	sttKeySchedule;
  DES_cblock				sttBlock;

	memcpy( sttBlock, szAuthKey, sizeof(sttBlock) );
	DES_key_sched( &sttBlock, &sttKeySchedule );

	DES_cbc_encrypt( szPdu, szEncrypt, iPduLen, &sttKeySchedule, (DES_cblock *)szIv, DES_ENCRYPT );
	StringToHex( (char *)szEncrypt, iPduLen, (char *)szHex, sizeof(szHex) );

	if( strcmp( (char *)szHex, pszResult ) )
	{
		printf( "%s error\n", __FUNCTION__ );
		return false;
	}

	return true;
}

bool TestEncryptedPdu()
{
	if( TestDecrypt() == false ) return false;
	if( TestEncrypt() == false ) return false;

	return true;
}

