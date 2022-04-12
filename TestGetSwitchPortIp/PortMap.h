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

#ifndef _PORT_MAP_H_
#define _PORT_MAP_H_

#include "SipPlatformDefine.h"
#include <map>
#include <string>

#define MAC_PORT_OID	"1.3.6.1.2.1.17.4.3.1.2"
#define IP_MAC_OID		"1.3.6.1.2.1.3.1.1.2.4"

// key = mac address
// value = ip address
typedef std::map< std::string, std::string > MAC_IP_MAP;

class CPortInfo
{
public:
	bool InsertMac( const char * pszMac );
	bool UpdateMacIp( const char * pszMac, const char * pszIp );

	MAC_IP_MAP m_clsMap;
};

// key = switch port number
typedef std::map< uint32_t, CPortInfo > PORT_MAP;

class CPortMap
{
public:
	bool InsertOidPort( const char * pszOid, uint32_t iPort );
	bool InsertPortMac( uint32_t iPort, const char * pszMac );
	bool InsertOidIp( const char * pszOid, std::string & strMac );
	bool UpdateMacIp( const char * pszMac, const char * pszIp );

	void PrintAll( );

	PORT_MAP m_clsMap;
};

extern CPortMap gclsPortMap;

#endif
