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

#ifndef _ASN_VARIABLE_H_
#define _ASN_VARIABLE_H_

#include "SnmpPlatformDefine.h"
#include "AsnType.h"
#include <string>

class CAsnVariable
{
public:
	CAsnVariable();
	~CAsnVariable();

	int ParsePacket( const char * pszPacket, int iPacketLen );
	int MakePacket( char * pszPacket, int iPacketSize );

	bool GetInt( uint32_t & iValue );
	bool GetString( std::string & strValue );
	bool GetOid( std::string & strValue );

	bool SetInt( int iValue );
	bool SetString( const char * pszValue );
	bool SetOid( const char * pszValue );
	void SetNull( );

	void Clear( );

	uint8_t	m_cType;
	uint8_t	m_cLength;
	void *  m_pValue;
};

#endif
