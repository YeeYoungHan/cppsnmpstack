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

#include "AsnType.h"
#include "MemoryDebug.h"

/**
 * @ingroup SnmpParser
 * @brief ASN 변수에 정수가 저장되어 있으면 정수값을 가져온다.
 * @param iValue 정수를 저장할 변수
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CAsnType::GetInt( uint32_t & iValue )
{
	return false;
}

/**
 * @ingroup SnmpParser
 * @brief ASN 변수에 문자열이 저장되어 있으면 문자열을 가져온다.
 * @param strValue 문자열을 저장할 변수
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CAsnType::GetString( std::string & strValue )
{
	return false;
}

int CAsnType::ParseHeader( const char * pszPacket, int iPacketLen )
{
	int iPos = 0, iIndex = 0;

	m_cType = pszPacket[iPos++];
	m_iLen = 0;

	if( pszPacket[iPos] & 0x80 )
	{
		uint8_t cLength = pszPacket[iPos] & 0x7F;
		++iPos;

		int n = ParseInt( pszPacket + iPos, iPacketLen - iPos, cLength, m_iLen );
		if( n == -1 ) return -1;

		iPos += n;
	}
	else
	{
		m_iLen = pszPacket[iPos++];
	}

	return iPos;
}

int CAsnType::ParseInt( const char * pszPacket, int iPacketLen, uint8_t cLength, uint32_t & iValue )
{
	if( iPacketLen < cLength ) return -1;

	if( cLength == 1 )
	{
		iValue = (uint8_t)pszPacket[0];
		return 1;
	}
	
	if( cLength == 2 )
	{
		int16_t sTemp;

		memcpy( &sTemp, pszPacket, cLength );
		iValue = ntohs( sTemp );
		return 2;
	}

	if( cLength == 3 )
	{
		int32_t iTemp = 0;

		memcpy( ((char *)&iTemp) + 1, pszPacket, cLength );
		iValue = ntohl( iTemp );
		return 3;
	}

	if( cLength == 4 )
	{
		int32_t iTemp;

		memcpy( &iTemp, pszPacket, cLength );
		iValue = ntohl( iTemp );
		return 4;
	}

	return -1;
}
