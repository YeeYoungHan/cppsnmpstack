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

CAsnComplex::CAsnComplex()
{
	m_cType = ASN_TYPE_COMPLEX;
}

CAsnComplex::~CAsnComplex()
{
	Clear();
}

int CAsnComplex::ParsePacket( const char * pszPacket, int iPacketLen )
{
	int			iPos = 0, n;
	uint8_t	cType, cLength;
	CAsnType	* pclsValue = NULL;

	Clear();

	m_cType = pszPacket[iPos++];
	cLength = pszPacket[iPos++];

	for( uint8_t i = 0; i < cLength; )
	{
		cType = pszPacket[iPos];

		switch( cType )
		{
		case ASN_TYPE_INT:
			pclsValue = new CAsnInt();
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

	pszPacket[1] = iPos - 2;

	return iPos;
}

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

bool CAsnComplex::AddInt( uint32_t iValue )
{
	CAsnInt * pclsValue = new CAsnInt();
	if( pclsValue == NULL ) return false;

	pclsValue->m_iValue = iValue;
	m_clsList.push_back( pclsValue );

	return true;
}

bool CAsnComplex::AddString( const char * pszValue )
{
	if( pszValue == NULL ) return false;

	CAsnString * pclsValue = new CAsnString();
	if( pclsValue == NULL ) return false;

	pclsValue->m_strValue = pszValue;
	m_clsList.push_back( pclsValue );

	return true;
}

bool CAsnComplex::AddOid( const char * pszValue )
{
	if( pszValue == NULL ) return false;

	CAsnOid * pclsValue = new CAsnOid();
	if( pclsValue == NULL ) return false;

	pclsValue->m_strValue = pszValue;
	m_clsList.push_back( pclsValue );

	return true;
}

bool CAsnComplex::AddNull( )
{
	CAsnNull * pclsValue = new CAsnNull();
	if( pclsValue == NULL ) return false;

	m_clsList.push_back( pclsValue );

	return true;
}

bool CAsnComplex::AddComplex( CAsnComplex * pclsValue )
{
	if( pclsValue == NULL ) return false;

	m_clsList.push_back( pclsValue );

	return true;
}

bool CAsnComplex::AddValue( CAsnType * pclsValue )
{
	if( pclsValue == NULL ) return false;

	m_clsList.push_back( pclsValue );

	return true;
}

void CAsnComplex::Clear()
{
	ASN_TYPE_LIST::iterator	itList;

	for( itList = m_clsList.begin(); itList != m_clsList.end(); ++itList )
	{
		delete *itList;
	}

	m_clsList.clear();
}
