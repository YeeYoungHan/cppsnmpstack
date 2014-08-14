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
#include <string.h>
#include <stdio.h>
#include "MemoryDebug.h"

int HexToString( const char * pszHex, char * pszPacket, int iPacketLen )
{
	int iHexLen = strlen( pszHex );
	int iIndex = 0;
	int iValue;

	memset( pszPacket, 0, iPacketLen );

	for( int i = 0; i < iHexLen; i += 2 )
	{
		if( iIndex == iPacketLen ) return -1;

		sscanf( pszHex + i, "%02x", &iValue );
		pszPacket[iIndex++] = iValue;
	}

	return iIndex;
}

int StringToHex( const char * pszPacket, int iPacketLen, char * pszHex, int iHexLen )
{
	int iLen = 0;

	memset( pszHex, 0, iHexLen );

	for( int i = 0; i < iPacketLen; ++i )
	{
		if( ( iLen + 2 ) >= iHexLen ) return -1;

		iLen += snprintf( pszHex + iLen, iHexLen - iLen, "%02x", pszPacket[i] );
	}

	return iLen;
}
