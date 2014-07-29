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

#include "AsnOid.h"

CAsnOid::CAsnOid(void)
{
	m_cType = ASN_TYPE_OID;
}

CAsnOid::~CAsnOid(void)
{
}

/**
 * @ingroup SnmpParser
 * @brief ��Ŷ�� �Ľ��Ͽ��� ���� ������ ��Ŷ �����͸� �����Ѵ�.
 * @param pszPacket		��Ŷ
 * @param iPacketLen	��Ŷ ����
 * @returns �����ϸ� �Ľ��� ��Ŷ ���̸� �����ϰ� �����ϸ� -1 �� �����Ѵ�.
 */
int CAsnOid::ParsePacket( const char * pszPacket, int iPacketLen )
{
	int			iPos = 0;
	uint8_t	cLength;
	char	szValue[512];
	int	iValueLen = 0;

	m_cType = pszPacket[iPos++];
	cLength = pszPacket[iPos++];

	memset( szValue, 0, sizeof(szValue) );
	
	iValueLen = snprintf( szValue, sizeof(szValue), "%d.%d", pszPacket[iPos] / 40, pszPacket[iPos] % 40 );
	++iPos;

	for( int i = 1; i < cLength; ++i )
	{
		iValueLen += snprintf( szValue + iValueLen, sizeof(szValue) - iValueLen, ".%d", pszPacket[iPos++] );
	}

	m_strValue = szValue;

	return iPos;
}

/**
 * @ingroup SnmpParser
 * @brief ���� ������ ��Ŷ�� �����Ѵ�.
 * @param pszPacket		��Ŷ
 * @param iPacketSize ��Ŷ ũ��
 * @returns �����ϸ� ����� ��Ŷ ���̸� �����ϰ� �����ϸ� -1 �� �����Ѵ�.
 */
int CAsnOid::MakePacket( char * pszPacket, int iPacketSize )
{
	int iPos = 0;
	const char * pszValue = m_strValue.c_str();
	char szValue[11];
	int	 iValuePos = 0, iNumPos = 0;
	uint8_t cValue, cLength = m_strValue.length();

	pszPacket[iPos++] = m_cType;

	++iPos;
	memset( szValue, 0, sizeof(szValue) );

	for( int i = 0; i < cLength; ++i )
	{
		if( pszValue[i] == '.' )
		{
			cValue = atoi( szValue );

			++iNumPos;

			if( iNumPos == 1 )
			{
				pszPacket[iPos] = cValue * 40;
			}
			else if( iNumPos == 2 )
			{
				pszPacket[iPos] |= cValue;
				++iPos;
			}
			else
			{
				pszPacket[iPos] = cValue;
				++iPos;
			}

			iValuePos = 0;
			memset( szValue, 0, sizeof(szValue) );
		}
		else
		{
			szValue[iValuePos++] = pszValue[i];
		}
	}

	if( szValue[0] != '\0' )
	{
		cValue = atoi( szValue );
		pszPacket[iPos] = cValue;
		++iPos;
	}

	pszPacket[1] = iPos - 2;

	return iPos;
}

/**
 * @ingroup SnmpParser
 * @brief ������ ��ü�� �����Ѵ�.
 * @returns ������ ��ü�� �����Ѵ�.
 */
CAsnType * CAsnOid::Copy( )
{
	CAsnOid * pclsValue = new CAsnOid();
	if( pclsValue == NULL ) return NULL;

	pclsValue->m_strValue = m_strValue;
	return pclsValue;

}
