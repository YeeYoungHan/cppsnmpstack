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

#include "PortMap.h"
#include "StringUtility.h"
#include "Log.h"

CPortMap gclsPortMap;

bool CPortInfo::InsertMac( const char * pszMac )
{
	MAC_IP_MAP::iterator itMap;

	itMap = m_clsMap.find( pszMac );
	if( itMap == m_clsMap.end() )
	{
		m_clsMap.insert( MAC_IP_MAP::value_type( pszMac, "" ) );
	}

	return true;
}

bool CPortInfo::UpdateMacIp( const char * pszMac, const char * pszIp )
{
	MAC_IP_MAP::iterator itMap;

	itMap = m_clsMap.find( pszMac );
	if( itMap != m_clsMap.end() )
	{
		itMap->second = pszIp;
	}

	return true;
}

bool CPortMap::InsertOidPort( const char * pszOid, uint32_t iPort )
{
	int iMacPortOidLen = strlen( MAC_PORT_OID );

	if( strncmp( pszOid, MAC_PORT_OID, iMacPortOidLen ) )
	{
		CLog::Print( LOG_ERROR, "%s( %s, %u ) is not %s", __FUNCTION__, pszOid, iPort, MAC_PORT_OID );
		return false;
	}

	int iHex, iPos = 0;
	STRING_LIST clsList;
	char szMac[21];

	pszOid += iMacPortOidLen + 1;

	SplitString( pszOid, clsList, '.' );

	for( STRING_LIST::iterator itList = clsList.begin(); itList != clsList.end(); ++itList )
	{
		iHex = atoi( itList->c_str() );

		iPos += snprintf( szMac + iPos, sizeof(szMac) - iPos, "%02X", iHex );
	}

	InsertPortMac( iPort, szMac );

	return true;
}

bool CPortMap::InsertPortMac( uint32_t iPort, const char * pszMac )
{
	PORT_MAP::iterator itMap;

	itMap = m_clsMap.find( iPort );
	if( itMap == m_clsMap.end() )
	{
		CPortInfo clsInfo;

		m_clsMap.insert( PORT_MAP::value_type( iPort, clsInfo ) );
		itMap = m_clsMap.find( iPort );
	}

	itMap->second.InsertMac( pszMac );

	return true;
}

bool CPortMap::InsertOidIp( const char * pszOid, std::string & strMac )
{
	int iIpMacOidLen = strlen( IP_MAC_OID );

	if( strncmp( pszOid, IP_MAC_OID, iIpMacOidLen ) )
	{
		CLog::Print( LOG_ERROR, "%s( %s ) is not %s", __FUNCTION__, pszOid, IP_MAC_OID );
		return false;
	}

	pszOid += iIpMacOidLen + 1;

	char szMac[21];

	if( strMac.length() != 6 )
	{
		CLog::Print( LOG_ERROR, "%s strMac.length(%d) != 6", __FUNCTION__, strMac.length() );
		return false;
	}

	const char * pszMac = strMac.c_str();
	int iPos = 0;

	for( int i = 0; i < 6; ++i )
	{
		iPos += snprintf( szMac + iPos, sizeof(szMac) - iPos, "%02X", (uint8_t)pszMac[i] );
	}

	UpdateMacIp( szMac, pszOid );

	return true;
}

bool CPortMap::UpdateMacIp( const char * pszMac, const char * pszIp )
{
	PORT_MAP::iterator itMap;

	for( itMap = m_clsMap.begin(); itMap != m_clsMap.end(); ++itMap )
	{
		itMap->second.UpdateMacIp( pszMac, pszIp );
	}

	return true;
}

void CPortMap::PrintAll( )
{
	PORT_MAP::iterator itMap;
	MAC_IP_MAP::iterator itMacIp;

	for( itMap = m_clsMap.begin(); itMap != m_clsMap.end(); ++itMap )
	{
		printf( "port(%d) => ", itMap->first );

		for( itMacIp = itMap->second.m_clsMap.begin(); itMacIp != itMap->second.m_clsMap.end(); ++itMacIp )
		{
			printf( "%s ", itMacIp->second.c_str() );
		}

		printf( "\n" );
	}
}
