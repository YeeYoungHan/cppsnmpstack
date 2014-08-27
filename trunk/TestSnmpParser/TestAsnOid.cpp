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
#include "AsnOid.h"

bool TestAsnOid()
{
	const char * pszHexPacket = "060c2b0601020102020101848003";
	char szPacket[1500];
	int iPacketLen;
	CAsnOid clsOid;
	std::string	strValue;

	iPacketLen = HexToString( pszHexPacket, szPacket, sizeof(szPacket) );

	if( clsOid.ParsePacket( szPacket, iPacketLen ) == -1 ) return false;

	clsOid.GetString( strValue );

	if( strcmp( strValue.c_str(), "1.3.6.1.2.1.2.2.1.1.65539" ) )
	{
		return false;
	}

	return true;
}
