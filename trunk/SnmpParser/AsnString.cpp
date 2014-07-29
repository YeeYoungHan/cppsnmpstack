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
#include "MemoryDebug.h"

CAsnString::CAsnString()
{
	m_cType = ASN_TYPE_OCTET_STR;
}

CAsnString::~CAsnString()
{
}

/**
 * @ingroup SnmpParser
 * @brief 패킷을 파싱하여서 내부 변수에 패킷 데이터를 저장한다.
 * @param pszPacket		패킷
 * @param iPacketLen	패킷 길이
 * @returns 성공하면 파싱한 패킷 길이를 리턴하고 실패하면 -1 을 리턴한다.
 */
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

/**
 * @ingroup SnmpParser
 * @brief 내부 변수를 패킷에 저장한다.
 * @param pszPacket		패킷
 * @param iPacketSize 패킷 크기
 * @returns 성공하면 저장된 패킷 길이를 리턴하고 실패하면 -1 을 리턴한다.
 */
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

/**
 * @ingroup SnmpParser
 * @brief 복사한 객체를 리턴한다.
 * @returns 복사한 객체를 리턴한다.
 */
CAsnType * CAsnString::Copy( )
{
	CAsnString * pclsValue = new CAsnString();
	if( pclsValue == NULL ) return NULL;

	pclsValue->m_strValue = m_strValue;

	return pclsValue;
}

/**
 * @ingroup SnmpParser
 * @brief 문자열을 가져온다.
 * @param strValue 문자열을 저장할 변수
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CAsnString::GetString( std::string & strValue )
{
	strValue = m_strValue;

	return true;
}
