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

#include "TestSnmpParser.h"
#include "AsnLong.h"

bool TestAsnLong( const char * pszHex, uint64_t iValue )
{
	CAsnLong clsLong;
	char szPacket[255];
	int iPacketLen, n;

	iPacketLen = HexToString( pszHex, szPacket, sizeof(szPacket) );

	n = clsLong.ParsePacket( szPacket, iPacketLen );
	if( n == -1 )
	{
		printf( "%s clsInt.ParseHeader return(%d)\n", __FUNCTION__, n );
		return false;
	}

	if( clsLong.m_iValue != iValue )
	{
		printf( "%s clsInt.m_iValue(%llu) != %llu\n", __FUNCTION__, clsLong.m_iValue, iValue );
		return false;
	}

	return true;
}

bool TestAsnLong( )
{
	if( TestAsnLong( "46060096ecf70c31", 648220707889 ) == false ) return false;
	if( TestAsnLong( "4606008401A23296", 566963090070 ) == false ) return false;

	CAsnLong clsLong;
	char szPacket[1500], szHex[1500];
	int iPacketLen;

	clsLong.m_iValue = 111681615645ULL;

	iPacketLen = clsLong.MakePacket( szPacket, sizeof(szPacket) );
	if( iPacketLen == -1 ) return false;

	StringToHex( szPacket, iPacketLen, szHex, sizeof(szHex) );
	if( strcmp( szHex, "46051a00be371d" ) ) return false;

	return true;
}


