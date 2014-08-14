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
 * @brief ��Ŷ�� �Ľ��Ͽ��� ���� ������ ��Ŷ �����͸� �����Ѵ�.
 * @param pszPacket		��Ŷ
 * @param iPacketLen	��Ŷ ����
 * @returns �����ϸ� �Ľ��� ��Ŷ ���̸� �����ϰ� �����ϸ� -1 �� �����Ѵ�.
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
 * @brief ���� ������ ��Ŷ�� �����Ѵ�.
 * @param pszPacket		��Ŷ
 * @param iPacketSize ��Ŷ ũ��
 * @returns �����ϸ� ����� ��Ŷ ���̸� �����ϰ� �����ϸ� -1 �� �����Ѵ�.
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
 * @brief ������ ��ü�� �����Ѵ�.
 * @returns ������ ��ü�� �����Ѵ�.
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
 * @brief CAsnInt ������ ����Ʈ�� �߰��Ѵ�.
 * @param iValue ����
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
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
 * @brief CAsnString ������ ����Ʈ�� �߰��Ѵ�.
 * @param pszValue ���ڿ�
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
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
 * @brief CAsnString ������ ����Ʈ�� �߰��Ѵ�.
 * @param strValue ���ڿ�
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
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
 * @brief 1 ���ڷ� ������ CAsnString ������ ����Ʈ�� �߰��Ѵ�.
 * @param cValue 1 ����
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
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
 * @brief CAsnOid ������ ����Ʈ�� �߰��Ѵ�.
 * @param pszValue OID ���ڿ�
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
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
 * @brief CAsnNull ������ ����Ʈ�� �߰��Ѵ�.
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
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
 * @brief CAsnComplex ������ ����Ʈ�� �߰��Ѵ�.
 * @param pclsValue CAsnComplex ����
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
 */
bool CAsnComplex::AddComplex( CAsnComplex * pclsValue )
{
	if( pclsValue == NULL ) return false;

	m_clsList.push_back( pclsValue );

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief CAsnType ������ ����Ʈ�� �߰��Ѵ�.
 * @param pclsValue CAsnType ����
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
 */
bool CAsnComplex::AddValue( CAsnType * pclsValue )
{
	if( pclsValue == NULL ) return false;

	m_clsList.push_back( pclsValue );

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief �ڷᱸ���� ����� �����͸� �����Ѵ�.
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
