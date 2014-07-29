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

#include "AsnInt.h"

CAsnInt::CAsnInt() : m_iValue(0)
{
}

CAsnInt::~CAsnInt()
{
}

int CAsnInt::ParsePacket( const char * pszPacket, int iPacketLen )
{
	int		iPos = 0;
	char	cLength;

	m_cType = pszPacket[iPos++];
	cLength = pszPacket[iPos++];

	if( cLength == 1 )
	{
		m_iValue = pszPacket[iPos++];
	}
	else if( cLength == 2 )
	{
		int16_t sValue;

		memcpy( &sValue, pszPacket + iPos, 2 );
		m_iValue = ntohs( sValue );
		iPos += 2;
	}
	else if( cLength == 4 )
	{
		int32_t iValue;

		memcpy( &iValue, pszPacket + iPos, 2 );
		m_iValue = ntohl( iValue );
		iPos += 4;
	}

	return iPos;
}

int CAsnInt::MakePacket( char * pszPacket, int iPacketSize )
{
	int iPos = 0;

	pszPacket[iPos++] = m_cType;

	if( m_iValue <= 0xFF )
	{
		pszPacket[iPos++] = 1;
		pszPacket[iPos++] = m_iValue;
	}
	else if( m_iValue <= 0xFFFF )
	{
		pszPacket[iPos++] = 2;

		int16_t sValue = htons( m_iValue );
		memcpy( pszPacket + iPos, &sValue, 2 );
		iPos += 2;
	}
	else
	{
		pszPacket[iPos++] = 4;

		uint32_t iValue = htons( m_iValue );
		memcpy( pszPacket + iPos, &iValue, 2 );
		iPos += 4;
	}

	return iPos;
}
