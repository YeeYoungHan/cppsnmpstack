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
#include "SnmpAuth.h"
#include <openssl/hmac.h>
#include <string.h>
#include "MemoryDebug.h"

/**
 * @ingroup SnmpParser
 * @brief 비밀번호로 key 를 생성한다.
 * @param pszPassWord 비밀번호
 * @param pszKey			생성된 key 저장 변수
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool SnmpMakeKey( const char * pszPassWord, uint8_t * pszKey )
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

/**
 * @ingroup SnmpParser
 * @brief authentication key 를 생성한다.
 * @param pszKey				key
 * @param pszEngineId		SNMPv3 engine ID
 * @param iEngineIdLen	SNMPv3 engine ID 길이
 * @param pszAuthKey		authentication key 저장 변수
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool SnmpMakeAuthKey( const uint8_t * pszKey, const uint8_t * pszEngineId, int iEngineIdLen, uint8_t * pszAuthKey )
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

/**
 * @ingroup SnmpParser
 * @brief SNMPv3 msgAuthenticationParameters 를 계산한다.
 * @param pszPacket			패킷
 * @param iPacketLen		패킷 길이
 * @param pszPassWord		비밀번호
 * @param pszEngineId		SNMPv3 engine ID
 * @param iEngineIdLen	SNMPv3 engine ID 길이
 * @param strAuthParams SNMPv3 msgAuthenticationParameters 저장 변수
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool SnmpMakeHmac( const char * pszPacket, int iPacketLen, const char * pszPassWord, const char * pszEngineId, int iEngineIdLen, std::string & strAuthParams )
{
	uint8_t szKey[16], szAuthKey[16], szResult[16];
	unsigned int iResultSize = sizeof(szResult);

	if( SnmpMakeKey( pszPassWord, szKey ) == false ) return false;
	if( SnmpMakeAuthKey( szKey, (const uint8_t *)pszEngineId, iEngineIdLen, szAuthKey ) == false ) return false;

	HMAC( EVP_md5(), szAuthKey, 16, (const uint8_t *)pszPacket, iPacketLen, szResult, &iResultSize );

	strAuthParams.clear();
	strAuthParams.append( (char *)szResult, 12 );

	return true;
}