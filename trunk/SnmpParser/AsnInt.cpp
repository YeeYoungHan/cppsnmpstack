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
#include "SnmpUdp.h"
#include "MemoryDebug.h"

CAsnInt::CAsnInt() : m_iValue(0)
{
	m_cType = ASN_TYPE_INT;
}

CAsnInt::CAsnInt( uint8_t cType ) : m_iValue(0)
{
	m_cType = cType;
}

CAsnInt::~CAsnInt()
{
}

/**
 * @ingroup SnmpParser
 * @brief ��Ŷ�� �Ľ��Ͽ��� ���� ������ ��Ŷ �����͸� �����Ѵ�.
 * @param pszPacket		��Ŷ
 * @param iPacketLen	��Ŷ ����
 * @returns �����ϸ� �Ľ��� ��Ŷ ���̸� �����ϰ� �����ϸ� -1 �� �����Ѵ�.
 */
int CAsnInt::ParsePacket( const char * pszPacket, int iPacketLen )
{
	int		iPos = 0;
	char	cLength;

	m_cType = pszPacket[iPos++];
	cLength = pszPacket[iPos++];

	int n = ParseInt( pszPacket + iPos, iPacketLen - iPos, cLength, m_iValue );
	if( n == -1 ) return -1;
	iPos += n;

	return iPos;
}

/**
 * @ingroup SnmpParser
 * @brief ���� ������ ��Ŷ�� �����Ѵ�.
 * @param pszPacket		��Ŷ
 * @param iPacketSize ��Ŷ ũ��
 * @returns �����ϸ� ����� ��Ŷ ���̸� �����ϰ� �����ϸ� -1 �� �����Ѵ�.
 */
int CAsnInt::MakePacket( char * pszPacket, int iPacketSize )
{
	int iPos = 0;

	pszPacket[iPos++] = m_cType;

	if( m_iValue <= 0x7F )
	{
		pszPacket[iPos++] = 1;
		pszPacket[iPos++] = m_iValue;
	}
	else if( m_iValue <= 0x7FFF )
	{
		pszPacket[iPos++] = 2;

		int16_t sValue = htons( m_iValue );
		memcpy( pszPacket + iPos, &sValue, 2 );
		iPos += 2;
	}
	else if( m_iValue <= 0x7FFFFF )
	{
		pszPacket[iPos++] = 3;

		uint32_t iValue = htonl( m_iValue );
		memcpy( pszPacket + iPos, ((char *)&iValue) + 1, 3 );
		iPos += 3;
	}
	else if( m_iValue <= 0x7FFFFFFF )
	{
		pszPacket[iPos++] = 4;

		uint32_t iValue = htonl( m_iValue );
		memcpy( pszPacket + iPos, &iValue, 4 );
		iPos += 4;
	}
	else
	{
		pszPacket[iPos++] = 5;
		pszPacket[iPos++] = 0;

		uint32_t iValue = htonl( m_iValue );
		memcpy( pszPacket + iPos, &iValue, 4 );
		iPos += 4;
	}

	return iPos;
}

/**
 * @ingroup SnmpParser
 * @brief ������ ��ü�� �����Ѵ�.
 * @returns ������ ��ü�� �����Ѵ�.
 */
CAsnType * CAsnInt::Copy( )
{
	CAsnInt * pclsValue = new CAsnInt();
	if( pclsValue == NULL ) return NULL;

	pclsValue->m_iValue = m_iValue;
	return pclsValue;
}

/**
 * @ingroup SnmpParser
 * @brief �������� �����´�.
 * @param iValue ������ ������ ����
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
 */
bool CAsnInt::GetInt( uint32_t & iValue )
{
	iValue = m_iValue;

	return true;
}
