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

#include "SipPlatformDefine.h"
#include "TestSnmpParser.h"
#include <openssl/hmac.h>
#include <openssl/des.h>
#include <string.h>
#include "MemoryDebug.h"

bool GetKey( const char * pszPassWord, unsigned char * pszKey )
{
	int iPassWordLen = strlen(pszPassWord);

	int iInputLen = 1024 * 1024;
	int iIndex = 0;
	char szBuf[64];

	unsigned int iResultLen = 16;

	EVP_MD_CTX * psttCtx = EVP_MD_CTX_create();
	EVP_DigestInit( psttCtx, EVP_md5() );

	while( iInputLen > 0 )
	{
		for( int i = 0; i < 64; ++i )
		{
			szBuf[i] = pszPassWord[iIndex % iPassWordLen];
			++iIndex;
		}

		EVP_DigestUpdate( psttCtx, szBuf, 64 );

		iInputLen -= 64;
	}
	
	EVP_DigestFinal( psttCtx, (unsigned char *)pszKey, &iResultLen );
	EVP_MD_CTX_destroy( psttCtx );

	return true;
}

bool GetAuthKey( unsigned char * pszKey, unsigned char * pszEngineId, int iEngineIdLen, unsigned char * pszAuthKey )
{
	char szBuf[255];
	int iBufLen = 0;
	unsigned int iResultLen = 16;

	memcpy( szBuf, pszKey, 16 );
	iBufLen += 16;
	memcpy( szBuf + iBufLen, pszEngineId, iEngineIdLen );
	iBufLen += iEngineIdLen;
	memcpy( szBuf + iBufLen, pszKey, 16 );
	iBufLen += 16;

	EVP_MD_CTX * psttCtx = EVP_MD_CTX_create();
	EVP_DigestInit( psttCtx, EVP_md5() );
	EVP_DigestUpdate( psttCtx, szBuf, iBufLen );
	EVP_DigestFinal( psttCtx, (unsigned char *)pszAuthKey, &iResultLen );
	EVP_MD_CTX_destroy( psttCtx );

	return true;
}

static bool TestKey( )
{
	unsigned char szResult[16];
	char szKey[33];

	GetKey( "apassword", szResult );

	StringToHex( (char *)szResult, sizeof(szResult), szKey, sizeof(szKey) );

	if( strcmp( szKey, "9bcf0656023951f83ff7c8585a1f0684" ) )
	{
		printf( "auth key create error\n" );
		return false;
	}

	GetKey( "xpassword", szResult );

	StringToHex( (char *)szResult, sizeof(szResult), szKey, sizeof(szKey) );

	if( strcmp( szKey, "6c4c29e2765e6d3070983b951b298948" ) )
	{
		printf( "auth key create error\n" );
		return false;
	}

	return true;
}

static bool TestHmac( )
{
	const char * pszHexPacket = "3074020103300f02020522020300ffe3040105020103042f302d040d80001f88809b26630b890ed3530201090202031804057573657231040c0000000000000000000000000400302d040d80001f88809b26630b890ed3530400a01a02022cf1020100020100300e300c06082b060102010101000500";
	const char * pszEngineId = "80001f88809b26630b890ed353";
	unsigned char szPacket[1500], szEngineId[51];
	int iIndex = 0, iEngineIdLen = 0;

	iIndex = HexToString( pszHexPacket, (char *)szPacket, sizeof(szPacket) );
	if( iIndex == -1 ) return false;

	iEngineIdLen = HexToString( pszEngineId, (char *)szEngineId, sizeof(szEngineId) );
	if( iEngineIdLen == -1 ) return false;

	unsigned char szKey[16], szAuthKey[16], szResult[512];
	unsigned int iResultSize = sizeof(szResult);

	GetKey( "apassword", szKey );
	GetAuthKey( szKey, szEngineId, iEngineIdLen, szAuthKey );

	HMAC( EVP_md5(), szAuthKey, 16, szPacket, iIndex, szResult, &iResultSize );

	char szHmac[33];
	int iHmacLen = 0;

	for( int i = 0; i < 12; ++i )
	{
		iHmacLen += snprintf( szHmac + iHmacLen, sizeof(szHmac) - iHmacLen, "%02x", szResult[i] );
	}

	if( strcmp( szHmac, "01eff216f0f319f0fde104aa" ) )
	{
		printf( "hmac create error\n" );
		return false;
	}

	return true;
}

static bool TestHmac2( )
{
	const char * pszHexPacket = "308180020103300f02022905020300ffe304010702010304383036040d80001f88809b26630b890ed353020109020302d7dc04057573657231040c000000000000000000000000040800000001166d411204305a06d0740666bc6dac3e93518b6afd5487784cf5c58b2d338ef8b05a368838d107d9409ba135bb1be39b9c0c78e48cc9";
	const char * pszEngineId = "80001f88809b26630b890ed353";
	unsigned char szPacket[1500], szEngineId[51];
	int iIndex = 0, iEngineIdLen = 0;

	iIndex = HexToString( pszHexPacket, (char *)szPacket, sizeof(szPacket) );
	if( iIndex == -1 ) return false;

	iEngineIdLen = HexToString( pszEngineId, (char *)szEngineId, sizeof(szEngineId) );
	if( iEngineIdLen == -1 ) return false;

	unsigned char szKey[16], szAuthKey[16], szResult[512];
	unsigned int iResultSize = sizeof(szResult);

	GetKey( "apassword", szKey );
	GetAuthKey( szKey, szEngineId, iEngineIdLen, szAuthKey );

	HMAC( EVP_md5(), szAuthKey, 16, szPacket, iIndex, szResult, &iResultSize );

	char szHmac[33];
	int iHmacLen = 0;

	for( int i = 0; i < 12; ++i )
	{
		iHmacLen += snprintf( szHmac + iHmacLen, sizeof(szHmac) - iHmacLen, "%02x", szResult[i] );
	}

	if( strcmp( szHmac, "3559f2da879ea3b86b2b9679" ) )
	{
		printf( "hmac create error\n" );
		return false;
	}

	return true;
}

static bool TestHmac3( )
{
	const char * pszHexPacket = "3081c9020103300f02026ed9020300ffe304010102010304333031041180001f8880fdc04c3b64a9f55300000000020108020200a904057573657231040c0000000000000000000000000400307e041180001f8880fdc04c3b64a9f553000000000400a26702021855020100020100305b305906082b06010201010100044d4c696e7578206d617374657220322e362e33322d3335382e656c362e7838365f363420233120534d5020467269204665622032322030303a33313a3236205554432032303133207838365f3634";
	const char * pszEngineId = "80001f8880fdc04c3b64a9f55300000000";
	unsigned char szPacket[1500], szEngineId[51];
	int iIndex = 0, iEngineIdLen = 0;

	iIndex = HexToString( pszHexPacket, (char *)szPacket, sizeof(szPacket) );
	if( iIndex == -1 ) return false;

	iEngineIdLen = HexToString( pszEngineId, (char *)szEngineId, sizeof(szEngineId) );
	if( iEngineIdLen == -1 ) return false;

	unsigned char szKey[16], szAuthKey[16], szResult[512];
	unsigned int iResultSize = sizeof(szResult);

	GetKey( "apassword", szKey );
	GetAuthKey( szKey, szEngineId, iEngineIdLen, szAuthKey );

	HMAC( EVP_md5(), szAuthKey, 16, szPacket, iIndex, szResult, &iResultSize );

	char szHmac[33];
	int iHmacLen = 0;

	for( int i = 0; i < 12; ++i )
	{
		iHmacLen += snprintf( szHmac + iHmacLen, sizeof(szHmac) - iHmacLen, "%02x", szResult[i] );
	}

	if( strcmp( szHmac, "6eff6c2cf4523a7613ddf8db" ) )
	{
		printf( "hmac create error\n" );
		return false;
	}

	return true;
}

bool TestAuthenticationParameters()
{
	if( TestKey() == false ) return false;
	if( TestHmac() == false ) return false;
	if( TestHmac2() == false ) return false;
	if( TestHmac3() == false ) return false;

	return true;
}
