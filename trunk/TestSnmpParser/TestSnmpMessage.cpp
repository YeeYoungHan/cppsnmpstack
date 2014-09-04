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
#include "SnmpMessage.h"
#include "MemoryDebug.h"

bool TestSnmpMessage()
{
	const char * pszHex = "303002010104067075626c6963a2230202021f02010002010030173015060c2b060102011f0101010aa70f46051a00be371d";
	char szPacket[1500];
	int iPacketLen, n;
	CSnmpMessage clsMessage;

	iPacketLen = HexToString( pszHex, (char *)szPacket, sizeof(szPacket) );
	if( iPacketLen == -1 ) 
	{
		printf( "%s HexToString error\n", __FUNCTION__ );
		return false;
	}

	n = clsMessage.ParsePacket( szPacket, iPacketLen );
	if( n == -1 ) 
	{
		printf( "%s clsMessage.ParsePacket error\n", __FUNCTION__ );
		return false;
	}

	return true;
}
