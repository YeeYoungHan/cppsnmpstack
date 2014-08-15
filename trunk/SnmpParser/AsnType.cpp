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
#include "SnmpUdp.h"
#include <stdlib.h>
#include "MemoryDebug.h"

/**
 * @ingroup SnmpParser
 * @brief ASN ������ ������ ����Ǿ� ������ �������� �����´�.
 * @param iValue ������ ������ ����
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
 */
bool CAsnType::GetInt( uint32_t & iValue )
{
	return false;
}

/**
 * @ingroup SnmpParser
 * @brief ASN ������ ���ڿ��� ����Ǿ� ������ ���ڿ��� �����´�.
 * @param strValue ���ڿ��� ������ ����
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
 */
bool CAsnType::GetString( std::string & strValue )
{
	return false;
}

/**
 * @ingroup SnmpParser
 * @brief ��Ŷ�� �Ľ��Ͽ��� ASN.1 Ÿ�� �� body ���̸� �����Ѵ�.
 * @param pszPacket		��Ŷ
 * @param iPacketLen	��Ŷ ����
 * @returns �����ϸ� �Ľ��� ��Ŷ ���̸� �����ϰ� �׷��� ������ -1 �� �����Ѵ�.
 */
int CAsnType::ParseHeader( const char * pszPacket, int iPacketLen )
{
	int iPos = 0;

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

/**
 * @ingroup SnmpParser
 * @brief ��Ŷ�� body ���̸� �����Ѵ�. body ���̰� 127 ���� ũ�ٸ� ��Ŷ�� body ���̸� ������ ��ŭ �ڷ� �����Ѵ�.
 * @param pszPacket		��Ŷ�� body ���� ���� ��ġ
 * @param iPacketSize	��Ŷ ũ��
 * @param iLength			body ����
 * @returns �����ϸ� ����� ��Ŷ ���̸� �����ϰ� �׷��� ������ -1 �� �����Ѵ�.
 */
int CAsnType::SetHeaderLength( char * pszPacket, int iPacketSize, int iLength )
{
	if( iLength <= 127 )
	{
		pszPacket[1] = iLength;
		return iLength + 2;
	}

	uint8_t szLen[5];
	int iLenSize;

	iLenSize = SetInt( szLen, sizeof(szLen), iLength );
	if( iLenSize == -1 ) return -1;

	if( iPacketSize < ( iLength + iLenSize + 1 ) ) return -1;

	char * pszCopy = (char *)malloc( iPacketSize );
	if( pszCopy == NULL ) return -1;

	memcpy( pszCopy, pszPacket, iPacketSize );

	memcpy( pszPacket + 1, szLen, iLenSize );
	memcpy( pszPacket + 1 + iLenSize, pszCopy + 2, iLength );

	free( pszCopy );

	return 1 + iLenSize + iLength;
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

/**
 * @ingroup SnmpParser
 * @brief ASN.1 header �� body ���̸� �����Ѵ�.
 * @param pszPacket		��Ŷ�� body ���� ��ġ
 * @param iPacketLen	��Ŷ�� ����
 * @param iValue			body ����
 * @returns �����ϸ� ����� ��Ŷ ���̸� �����Ѵ�.
 */
int CAsnType::SetInt( uint8_t * pszPacket, int iPacketLen, uint32_t iValue )
{
	if( iValue <= 0xFF )
	{
		pszPacket[0] = 0x81;
		pszPacket[1] = iValue;
		return 2;
	}

	if( iValue <= 0xFFFF )
	{
		pszPacket[0] = 0x82;

		int16_t sTemp = htons( iValue );
		memcpy( pszPacket + 1, &sTemp, 2 );
		return 3;
	}

	if( iValue <= 0xFFFFFF )
	{
		pszPacket[0] = 0x83;

		uint32_t iTemp = htonl( iValue );
		memcpy( pszPacket + 1, ((char *)&iTemp) + 1, 3 );
		return 4;
	}

	pszPacket[0] = 0x84;

	uint32_t iTemp = htons( iValue );
	memcpy( pszPacket + 1, &iTemp, 4 );

	return 5;
}