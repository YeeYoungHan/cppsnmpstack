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

bool TestParseSnmpv3Packet( )
{
	const char * pszHexPacket = "3066020103300f02020523020300ffe3040100020103041e301c040d80001f88809b26630b890ed353020109020203180400040004003030040d80001f88809b26630b890ed3530400a81d02022cf20201000201003011300f060a2b060106030f0101040041010a";
	char szPacket[1500], szHex[3000];
	int iPacketLen, n;
	CSnmpMessage clsMessage;

	iPacketLen = HexToString( pszHexPacket, (char *)szPacket, sizeof(szPacket) );
	if( iPacketLen == -1 ) return false;

	n = clsMessage.ParsePacket( szPacket, iPacketLen );
	if( n == -1 ) return false;

	pszHexPacket = "3081c3020103300f02027f53020300ffe30401010201030430302e040d80001f88809b26630b890ed35302010902030211c604057573657231040c37095a108c412a8594fe20730400307b040d80001f88809b26630b890ed3530400a26802027f53020100020100305c305a06082b06010201010100044e4c696e75782063656e746f7336335f333220322e362e33322d3237392e656c362e6936383620233120534d5020467269204a756e2032322031303a35393a35352055544320323031322069363836";
	iPacketLen = HexToString( pszHexPacket, (char *)szPacket, sizeof(szPacket) );
	if( iPacketLen == -1 ) return false;

	n = clsMessage.ParsePacket( szPacket, iPacketLen );
	if( n == -1 ) return false;

	// 00ffe3 때문에 길이가 1 차이가 발생한다.
	n = clsMessage.MakePacket( szPacket, sizeof(szPacket) );
	if( n != iPacketLen )
	{
		printf( "n(%d) != iPacketLen(%d)\n", n, iPacketLen );
		return false;
	}

	n = StringToHex( szPacket, iPacketLen, szHex, sizeof(szHex) );
	if( n == -1 )
	{
		return false;
	}

	if( strcmp( szHex, pszHexPacket ) )
	{
		return false;
	}

	return true;
}
