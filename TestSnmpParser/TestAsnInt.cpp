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
#include "AsnInt.h"

bool TestAsnInt()
{
	CAsnInt clsInt;
	char szPacket[255];
	int iPacketLen, n;

	iPacketLen = HexToString( "41050099e7eee6", szPacket, sizeof(szPacket) );

	n = clsInt.ParsePacket( szPacket, iPacketLen );
	if( n != 7 )
	{
		printf( "%s clsInt.ParseHeader return(%d) != 196\n", __FUNCTION__, n );
		return false;
	}

	if( clsInt.m_iValue != 2582114022 )
	{
		printf( "%s clsInt.m_iValue(%u) != 2582114022\n", __FUNCTION__, clsInt.m_iValue );
		return false;
	}

	return true;
}

