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

#include "AsnNull.h"
#include "MemoryDebug.h"

CAsnNull::CAsnNull()
{
	m_cType = ASN_TYPE_NULL;
}

CAsnNull::~CAsnNull()
{
}

/**
 * @ingroup SnmpParser
 * @brief 패킷을 파싱하여서 내부 변수에 패킷 데이터를 저장한다.
 * @param pszPacket		패킷
 * @param iPacketLen	패킷 길이
 * @returns 성공하면 파싱한 패킷 길이를 리턴하고 실패하면 -1 을 리턴한다.
 */
int CAsnNull::ParsePacket( const char * pszPacket, int iPacketLen )
{
	m_cType = pszPacket[0];

	return 2;
}

/**
 * @ingroup SnmpParser
 * @brief 내부 변수를 패킷에 저장한다.
 * @param pszPacket		패킷
 * @param iPacketSize 패킷 크기
 * @returns 성공하면 저장된 패킷 길이를 리턴하고 실패하면 -1 을 리턴한다.
 */
int CAsnNull::MakePacket( char * pszPacket, int iPacketSize )
{
	pszPacket[0] = m_cType;
	pszPacket[1] = 0;

	return 2;
}

/**
 * @ingroup SnmpParser
 * @brief 복사한 객체를 리턴한다.
 * @returns 복사한 객체를 리턴한다.
 */
CAsnType * CAsnNull::Copy( )
{
	CAsnNull * pclsValue = new CAsnNull();
	if( pclsValue == NULL ) return NULL;

	pclsValue->m_cType = m_cType;

	return pclsValue;
}
