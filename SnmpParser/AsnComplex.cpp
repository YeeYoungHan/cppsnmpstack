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

#include "AsnComplex.h"
#include "AsnInt.h"
#include "AsnString.h"
#include "AsnOid.h"
#include "AsnNull.h"
#include "SnmpDefine.h"
#include "Log.h"
#include "MemoryDebug.h"

CAsnComplex::CAsnComplex()
{
	m_cType = ASN_TYPE_COMPLEX;
}

CAsnComplex::~CAsnComplex()
{
	Clear();
}

/**
 * @ingroup SnmpParser
 * @brief 패킷을 파싱하여서 내부 변수에 패킷 데이터를 저장한다.
 * @param pszPacket		패킷
 * @param iPacketLen	패킷 길이
 * @returns 성공하면 파싱한 패킷 길이를 리턴하고 실패하면 -1 을 리턴한다.
 */
int CAsnComplex::ParsePacket( const char * pszPacket, int iPacketLen )
{
	int			iPos = 0, n;
	uint8_t	cType;
	CAsnType	* pclsValue = NULL;

	Clear();

	iPos = ParseHeader( pszPacket, iPacketLen );
	if( iPos == -1 ) return -1;

	for( uint8_t i = 0; i < m_iLen; )
	{
		cType = pszPacket[iPos];

		switch( cType )
		{
		case ASN_TYPE_INT:
		case ASN_TYPE_COUNTER_32:
			pclsValue = new CAsnInt( cType );
			break;
		case ASN_TYPE_OCTET_STR:
			pclsValue = new CAsnString();
			break;
		case ASN_TYPE_OID:
			pclsValue = new CAsnOid();
			break;
		case ASN_TYPE_NULL:
		case ASN_TYPE_NO_SUCH_OBJECT:
			pclsValue = new CAsnNull();
			break;
		case ASN_TYPE_COMPLEX:
		case SNMP_CMD_GET:
		case SNMP_CMD_GET_NEXT:
		case SNMP_CMD_RESPONSE:
		case SNMP_CMD_REPORT:
			pclsValue = new CAsnComplex();
			break;
		default:
			CLog::Print( LOG_ERROR, "%s type(%02x) is not defined", __FUNCTION__, cType );
			return -1;
		}

		if( pclsValue == NULL ) return -1;
		n = pclsValue->ParsePacket( pszPacket + iPos, iPacketLen - iPos );
		if( n == -1 ) 
		{
			delete pclsValue;
			return -1;
		}
		iPos += n;
		i += n;

		m_clsList.push_back( pclsValue );
	}

	return iPos;
}

/**
 * @ingroup SnmpParser
 * @brief 내부 변수를 패킷에 저장한다.
 * @param pszPacket		패킷
 * @param iPacketSize 패킷 크기
 * @returns 성공하면 저장된 패킷 길이를 리턴하고 실패하면 -1 을 리턴한다.
 */
int CAsnComplex::MakePacket( char * pszPacket, int iPacketSize )
{
	int iPos = 0, n;
	ASN_TYPE_LIST::iterator	itList;
	
	pszPacket[iPos++] = m_cType;
	++iPos;

	for( itList = m_clsList.begin(); itList != m_clsList.end(); ++itList )
	{
		n = (*itList)->MakePacket( pszPacket + iPos, iPacketSize - iPos );
		if( n == -1 ) return -1;
		iPos += n;
	}

	SetHeaderLength( pszPacket, iPacketSize, iPos - 2 );

	return iPos;
}

/**
 * @ingroup SnmpParser
 * @brief 복사한 객체를 리턴한다.
 * @returns 복사한 객체를 리턴한다.
 */
CAsnType * CAsnComplex::Copy( )
{
	CAsnComplex * pclsValue = new CAsnComplex();
	if( pclsValue == NULL ) return NULL;

	pclsValue->m_cType = m_cType;

	ASN_TYPE_LIST::iterator	itList;

	for( itList = m_clsList.begin(); itList != m_clsList.end(); ++itList )
	{
		CAsnType * pclsEntry = (*itList)->Copy();
		if( pclsEntry == NULL )
		{
			delete pclsValue;
			return NULL;
		}

		pclsValue->m_clsList.push_back( pclsEntry );
	}

	return pclsValue;
}

/**
 * @ingroup SnmpParser
 * @brief CAsnInt 변수를 리스트에 추가한다.
 * @param iValue 정수
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CAsnComplex::AddInt( uint32_t iValue )
{
	CAsnInt * pclsValue = new CAsnInt();
	if( pclsValue == NULL ) return false;

	pclsValue->m_iValue = iValue;
	m_clsList.push_back( pclsValue );

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief CAsnString 변수를 리스트에 추가한다.
 * @param pszValue 문자열
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CAsnComplex::AddString( const char * pszValue )
{
	if( pszValue == NULL ) return false;

	CAsnString * pclsValue = new CAsnString();
	if( pclsValue == NULL ) return false;

	pclsValue->m_strValue = pszValue;
	m_clsList.push_back( pclsValue );

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief CAsnString 변수를 리스트에 추가한다.
 * @param strValue 문자열
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CAsnComplex::AddString( std::string & strValue )
{
	CAsnString * pclsValue = new CAsnString();
	if( pclsValue == NULL ) return false;

	pclsValue->m_strValue = strValue;
	m_clsList.push_back( pclsValue );

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief 1 문자로 구성된 CAsnString 변수를 리스트에 추가한다.
 * @param cValue 1 문자
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CAsnComplex::AddString( uint8_t cValue )
{
	CAsnString * pclsValue = new CAsnString();
	if( pclsValue == NULL ) return false;

	pclsValue->m_strValue.append(" ");
	pclsValue->m_strValue.at(0) = cValue;
	m_clsList.push_back( pclsValue );

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief CAsnOid 변수를 리스트에 추가한다.
 * @param pszValue OID 문자열
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CAsnComplex::AddOid( const char * pszValue )
{
	if( pszValue == NULL ) return false;

	CAsnOid * pclsValue = new CAsnOid();
	if( pclsValue == NULL ) return false;

	pclsValue->m_strValue = pszValue;
	m_clsList.push_back( pclsValue );

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief CAsnNull 변수를 리스트에 추가한다.
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CAsnComplex::AddNull( )
{
	CAsnNull * pclsValue = new CAsnNull();
	if( pclsValue == NULL ) return false;

	m_clsList.push_back( pclsValue );

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief CAsnComplex 변수를 리스트에 추가한다.
 * @param pclsValue CAsnComplex 변수
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CAsnComplex::AddComplex( CAsnComplex * pclsValue )
{
	if( pclsValue == NULL ) return false;

	m_clsList.push_back( pclsValue );

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief CAsnType 변수를 리스트에 추가한다.
 * @param pclsValue CAsnType 변수
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CAsnComplex::AddValue( CAsnType * pclsValue )
{
	if( pclsValue == NULL ) return false;

	m_clsList.push_back( pclsValue );

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief 자료구조에 저장된 데이터를 삭제한다.
 */
void CAsnComplex::Clear()
{
	ASN_TYPE_LIST::iterator	itList;

	for( itList = m_clsList.begin(); itList != m_clsList.end(); ++itList )
	{
		delete *itList;
	}

	m_clsList.clear();
}
