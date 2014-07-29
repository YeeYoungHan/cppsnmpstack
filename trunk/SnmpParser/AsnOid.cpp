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
#include <list>

typedef std::list< int > INT_LIST;

CAsnOid::CAsnOid(void)
{
	m_cType = ASN_TYPE_OID;
}

CAsnOid::~CAsnOid(void)
{
}

/**
 * @ingroup SnmpParser
 * @brief 패킷을 파싱하여서 내부 변수에 패킷 데이터를 저장한다.
 * @param pszPacket		패킷
 * @param iPacketLen	패킷 길이
 * @returns 성공하면 파싱한 패킷 길이를 리턴하고 실패하면 -1 을 리턴한다.
 */
int CAsnOid::ParsePacket( const char * pszPacket, int iPacketLen )
{
	int			iPos = 0;
	uint8_t	cLength;
	char	szValue[512];
	int		iValueLen = 0, iNum;

	m_cType = pszPacket[iPos++];
	cLength = pszPacket[iPos++];

	memset( szValue, 0, sizeof(szValue) );
	
	iValueLen = snprintf( szValue, sizeof(szValue), "%d.%d", pszPacket[iPos] / 40, pszPacket[iPos] % 40 );

	for( int i = 1; i < cLength; ++i )
	{
		iNum = 0;
		for( int j = 0; j < 4; ++j, ++i )
		{
			iNum = ( iNum << ( j * 7 ) ) | ( pszPacket[i+2] & 0x7F );
			if( ( pszPacket[i+2] & 0x80 ) == 0 ) break;
		}

		iValueLen += snprintf( szValue + iValueLen, sizeof(szValue) - iValueLen, ".%d", iNum );
	}

	m_strValue = szValue;

	return 2 + cLength;
}

/**
 * @ingroup SnmpParser
 * @brief 내부 변수를 패킷에 저장한다.
 * @param pszPacket		패킷
 * @param iPacketSize 패킷 크기
 * @returns 성공하면 저장된 패킷 길이를 리턴하고 실패하면 -1 을 리턴한다.
 */
int CAsnOid::MakePacket( char * pszPacket, int iPacketSize )
{
	int iPos = 0;
	const char * pszValue = m_strValue.c_str();
	char szValue[11];
	int	 iValuePos = 0, iNumPos = 0, iValue;
	uint8_t cLength = m_strValue.length();

	pszPacket[iPos++] = m_cType;

	++iPos;
	memset( szValue, 0, sizeof(szValue) );

	for( int i = 0; i < cLength; ++i )
	{
		if( pszValue[i] == '.' )
		{
			iValue = atoi( szValue );

			++iNumPos;

			if( iNumPos == 1 )
			{
				pszPacket[iPos] = iValue * 40;
			}
			else if( iNumPos == 2 )
			{
				pszPacket[iPos] |= iValue;
				++iPos;
			}
			else
			{
				SetOidEntry( pszPacket, iPacketSize, iValue, iPos );
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
		iValue = atoi( szValue );
		SetOidEntry( pszPacket, iPacketSize, iValue, iPos );
	}

	pszPacket[1] = iPos - 2;

	return iPos;
}

/**
 * @ingroup SnmpParser
 * @brief 복사한 객체를 리턴한다.
 * @returns 복사한 객체를 리턴한다.
 */
CAsnType * CAsnOid::Copy( )
{
	CAsnOid * pclsValue = new CAsnOid();
	if( pclsValue == NULL ) return NULL;

	pclsValue->m_strValue = m_strValue;
	return pclsValue;
}

bool CAsnOid::GetString( std::string & strValue )
{
	strValue = m_strValue;

	return true;
}

void CAsnOid::SetOidEntry( char * pszPacket, int iPacketSize, int iValue, int & iPos )
{
	if( iValue < 0x80 )
	{
		pszPacket[iPos++] = iValue;
	}
	else
	{
		INT_LIST	clsList;
		INT_LIST::reverse_iterator itList;

		while( iValue > 0 )
		{
			if( clsList.size() > 0 )
			{
				clsList.push_back( ( iValue % 0x80 ) | 0x80 );
			}
			else
			{
				clsList.push_back( iValue % 0x80 );
			}
			iValue = iValue / 0x80;
		}

		for( itList = clsList.rbegin(); itList != clsList.rend(); ++itList )
		{
			pszPacket[iPos++] = *itList;
		}
	}
}
