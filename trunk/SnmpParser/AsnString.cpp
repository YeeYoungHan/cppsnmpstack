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

#include "AsnString.h"

CAsnString::CAsnString()
{
	m_cType = ASN_TYPE_OCTET_STR;
}

CAsnString::~CAsnString()
{
}

int CAsnString::ParsePacket( const char * pszPacket, int iPacketLen )
{
	int			iPos = 0;
	uint8_t	cLength;

	m_strValue.clear();

	m_cType = pszPacket[iPos++];
	cLength = pszPacket[iPos++];
	m_strValue.append( pszPacket + iPos, cLength );

	iPos += cLength;

	return iPos;
}

int CAsnString::MakePacket( char * pszPacket, int iPacketSize )
{
	int			iPos = 0;
	uint8_t	cLength = m_strValue.length();

	pszPacket[iPos++] = m_cType;
	pszPacket[iPos++] = cLength;
	memcpy( pszPacket + iPos, m_strValue.c_str(), cLength );
	iPos += cLength;

	return iPos;
}

CAsnType * CAsnString::Copy( )
{
	CAsnString * pclsValue = new CAsnString();
	if( pclsValue == NULL ) return NULL;

	pclsValue->m_strValue = m_strValue;

	return pclsValue;
}
