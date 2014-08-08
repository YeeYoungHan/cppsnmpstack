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
#include <openssl/hmac.h>
#include <string.h>

static bool TestKey()
{
	char * pszPassWord = "apassword";
	int iPassWordLen = strlen(pszPassWord);

	int iInputLen = 1024 * 1024;
	int iIndex = 0;
	char szBuf[64];

	unsigned char szResult[16];
	unsigned int iResultLen = sizeof(szResult);

	char szKey[33];
	int iKeyLen = 0;

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
	
	EVP_DigestFinal( psttCtx, (unsigned char *)szResult, &iResultLen );

	for( int i = 0; i < 16; ++i )
	{
		iKeyLen += snprintf( szKey + iKeyLen, sizeof(szKey) - iKeyLen, "%02x", szResult[i] );
	}

	if( strcmp( szKey, "9bcf0656023951f83ff7c8585a1f0684" ) )
	{
		printf( "authentication key create error\n" );
		return false;
	}

	return true;
}

bool TestAuthenticationParameters()
{
	if( TestKey() == false ) return false;

	return true;
}
