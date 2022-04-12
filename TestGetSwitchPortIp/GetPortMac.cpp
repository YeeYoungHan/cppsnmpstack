/* 
 * Copyright (C) 2021 Yee Young Han <websearch@naver.com> (http://blog.naver.com/websearch)
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

#include "TestGetSwitchPortIp.h"

bool GetPortMac( CSnmpSession & clsSession )
{
	CAsnType * pclsValue;
	std::string strOid = MAC_PORT_OID;
	std::string * pstrOid;
	const char * pszMib = strOid.c_str();
	uint32_t iValue;

	while( 1 )
	{
		if( clsSession.SendGetNextRequest( pszMib, &pstrOid, &pclsValue ) == false )
		{
			printf( "%s timeout\n", __FUNCTION__ );
			break;
		}

		if( strncmp( strOid.c_str(), pstrOid->c_str(), strOid.length() ) )
		{
			break;
		}

		if( pclsValue->GetInt( iValue ) )
		{
			printf( "[%s] [%u]\n", pstrOid->c_str(), iValue );

			gclsPortMap.InsertOidPort( pstrOid->c_str(), iValue );
		}

		pszMib = pstrOid->c_str();
	}

	return true;
}
