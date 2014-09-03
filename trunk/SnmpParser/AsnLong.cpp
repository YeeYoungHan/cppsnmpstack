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

#include "AsnLong.h"
#include "SnmpUdp.h"
#include "MemoryDebug.h"

CAsnLong::CAsnLong()
{
	m_cType = ASN_TYPE_COUNTER_64;
}

CAsnLong::CAsnLong( uint8_t cType ) : m_iValue(0)
{
	m_cType = cType;
}

CAsnLong::~CAsnLong()
{
}

/**
 * @ingroup SnmpParser
 * @brief ��Ŷ�� �Ľ��Ͽ��� ���� ������ ��Ŷ �����͸� �����Ѵ�.
 * @param pszPacket		��Ŷ
 * @param iPacketLen	��Ŷ ����
 * @returns �����ϸ� �Ľ��� ��Ŷ ���̸� �����ϰ� �����ϸ� -1 �� �����Ѵ�.
 */
int CAsnLong::ParsePacket( const char * pszPacket, int iPacketLen )
{
	int		iPos = 0;
	char	cLength;

	m_cType = pszPacket[iPos++];
	cLength = pszPacket[iPos++];

	int n = ParseLong( pszPacket + iPos, iPacketLen - iPos, cLength, m_iValue );
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
int CAsnLong::MakePacket( char * pszPacket, int iPacketSize )
{
	int iPos = 0;

	pszPacket[iPos++] = m_cType;

	if( m_iValue <= 0x7F )
	{
		pszPacket[iPos++] = 1;
		pszPacket[iPos++] = (uint8_t)m_iValue;
	}
	else if( m_iValue <= 0x7FFF )
	{
		pszPacket[iPos++] = 2;

		int16_t sValue = htons( (uint16_t)m_iValue );
		memcpy( pszPacket + iPos, &sValue, 2 );
		iPos += 2;
	}
	else if( m_iValue <= 0x7FFFFF )
	{
		pszPacket[iPos++] = 3;

		uint32_t iValue = htonl( (uint32_t)m_iValue );
		memcpy( pszPacket + iPos, ((char *)&iValue) + 1, 3 );
		iPos += 3;
	}
	else if( m_iValue <= 0x7FFFFFFF )
	{
		pszPacket[iPos++] = 4;

		uint32_t iValue = htonl( (uint32_t)m_iValue );
		memcpy( pszPacket + iPos, &iValue, 4 );
		iPos += 4;
	}
	else if( m_iValue <= 0x7FFFFFFFFFULL )
	{
		pszPacket[iPos++] = 5;

		uint64_t iValue = htonll( m_iValue );
		memcpy( pszPacket + iPos, ((char *)&iValue) + 3, 5 );
		iPos += 5;
	}
	else if( m_iValue <= 0x7FFFFFFFFFFFULL )
	{
		pszPacket[iPos++] = 6;

		uint64_t iValue = htonll( m_iValue );
		memcpy( pszPacket + iPos, ((char *)&iValue) + 2, 6 );
		iPos += 6;
	}
	else if( m_iValue <= 0x7FFFFFFFFFFFFFULL )
	{
		pszPacket[iPos++] = 7;

		uint64_t iValue = htonll( m_iValue );
		memcpy( pszPacket + iPos, ((char *)&iValue) + 1, 7 );
		iPos += 7;
	}
	else if( m_iValue <= 0x7FFFFFFFFFFFFFFFULL )
	{
		pszPacket[iPos++] = 8;

		uint64_t iValue = htonll( m_iValue );
		memcpy( pszPacket + iPos, ((char *)&iValue), 8 );
		iPos += 8;
	}
	else
	{
		pszPacket[iPos++] = 9;
		pszPacket[iPos++] = 0;

		uint64_t iValue = htonll( m_iValue );
		memcpy( pszPacket + iPos, ((char *)&iValue), 8 );
		iPos += 8;
	}

	return iPos;
}

/**
 * @ingroup SnmpParser
 * @brief ������ ��ü�� �����Ѵ�.
 * @returns ������ ��ü�� �����Ѵ�.
 */
CAsnType * CAsnLong::Copy( )
{
	CAsnLong * pclsValue = new CAsnLong();
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
bool CAsnLong::GetLong( uint64_t & iValue )
{
	iValue = m_iValue;

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief ��Ŷ���� ������ �Ľ��Ѵ�.
 * @param pszPacket		��Ŷ
 * @param iPacketLen	��Ŷ ����
 * @param cLength			��Ŷ�� ����� ������ ����
 * @param iValue			������ ���� ����
 * @returns �����ϸ� �Ľ��� ��Ŷ ���̸� �����ϰ� �׷��� ������ -1 �� �����Ѵ�.
 */
int CAsnLong::ParseLong( const char * pszPacket, int iPacketLen, uint8_t cLength, uint64_t & iValue )
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

	if( cLength == 5 )
	{
		int64_t iTemp = 0;

		memcpy( ((char *)&iTemp) + 3, pszPacket, cLength );
		iValue = ntohll( iTemp );
		return 5;
	}

	if( cLength == 6 )
	{
		int64_t iTemp = 0;

		memcpy( ((char *)&iTemp) + 2, pszPacket, cLength );
		iValue = ntohll( iTemp );
		return 6;
	}

	if( cLength == 7 )
	{
		int64_t iTemp = 0;

		memcpy( ((char *)&iTemp) + 1, pszPacket, cLength );
		iValue = ntohll( iTemp );
		return 7;
	}

	if( cLength == 8 )
	{
		int64_t iTemp = 0;

		memcpy( &iTemp, pszPacket, cLength );
		iValue = ntohll( iTemp );
		return 8;
	}

	if( cLength == 9 )
	{
		int64_t iTemp = 0;

		memcpy( &iTemp, pszPacket + 1, 8 );
		iValue = ntohll( iTemp );
		return 8;
	}

	return -1;
}
