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

#include "AsnVariable.h"
#include "AsnInt.h"
#include "AsnString.h"
#include "AsnOid.h"
#include "Log.h"

CAsnVariable::CAsnVariable() : m_pclsValue(NULL)
{
	m_cType = 0;
}

CAsnVariable::~CAsnVariable()
{
	
}

int CAsnVariable::ParsePacket( const char * pszPacket, int iPacketLen )
{
	int	 iPos = 0;
	bool bParseBody = true;

	Clear();

	m_cType = pszPacket[iPos];
	iPos += 2;

	switch( m_cType )
	{
	case ASN_TYPE_INT:
		m_pclsValue = new CAsnInt();
		if( m_pclsValue == NULL ) return -1;
		break;
	case ASN_TYPE_OCTET_STR:
		m_pclsValue = new CAsnString();
		if( m_pclsValue == NULL ) return -1;
		break;
	case ASN_TYPE_OID:
		m_pclsValue = new CAsnOid();
		if( m_pclsValue == NULL ) return -1;
		break;
	case ASN_TYPE_NULL:
	case ASN_TYPE_NO_SUCH_OBJECT:
		bParseBody = false;
		break;
	default:
		CLog::Print( LOG_ERROR, "%s type(%d) is not defined", __FUNCTION__, m_cType );
		break;
	}

	if( bParseBody )
	{
		int n = m_pclsValue->ParsePacket( pszPacket, iPacketLen );
		if( n == -1 ) return -1;
		iPos = n;
	}

	return iPos;
}

bool CAsnVariable::GetInt( uint32_t & iValue )
{
	if( m_pclsValue == NULL || m_pclsValue->m_cType != ASN_TYPE_INT ) return false;

	iValue = ((CAsnInt *)m_pclsValue)->m_iValue;

	return true;
}

bool CAsnVariable::GetString( std::string & strValue )
{
	if( m_pclsValue == NULL || m_pclsValue->m_cType != ASN_TYPE_OCTET_STR ) return false;

	strValue = ((CAsnString *)m_pclsValue)->m_strValue;

	return true;
}

bool CAsnVariable::GetOid( std::string & strValue )
{
	if( m_pclsValue == NULL || m_pclsValue->m_cType != ASN_TYPE_OID ) return false;

	strValue = ((CAsnOid *)m_pclsValue)->m_strValue;

	return true;
}

int CAsnVariable::MakePacket( char * pszPacket, int iPacketSize )
{
	if( m_cType == ASN_TYPE_NULL || m_cType == ASN_TYPE_NO_SUCH_OBJECT )
	{
		int iPos = 0;

		pszPacket[iPos++] = m_cType;
		pszPacket[iPos++] = 0;

		return iPos;
	}

	if( m_pclsValue == NULL ) return -1;
	return m_pclsValue->MakePacket( pszPacket, iPacketSize );
}

bool CAsnVariable::SetInt( uint32_t iValue )
{
	Clear( );

	CAsnInt * pclsValue = new CAsnInt();
	if( pclsValue == NULL ) return false;

	pclsValue->m_iValue = iValue;
	m_pclsValue = pclsValue;

	return true;
}

bool CAsnVariable::SetString( const char * pszValue )
{
	if( pszValue == NULL ) return false;

	Clear( );

	CAsnString * pclsValue = new CAsnString();
	if( pclsValue == NULL ) return false;

	pclsValue->m_strValue = pszValue;
	m_pclsValue = pclsValue;

	return true;
}

bool CAsnVariable::SetOid( const char * pszValue )
{
	if( pszValue == NULL ) return false;

	Clear( );

	CAsnOid * pclsValue = new CAsnOid();
	if( pclsValue == NULL ) return false;

	pclsValue->m_strValue = pszValue;
	m_pclsValue = pclsValue;

	return true;
}

void CAsnVariable::SetNull( )
{
	Clear( );

	m_cType = ASN_TYPE_NULL;
}

void CAsnVariable::Clear( )
{
	if( m_pclsValue ) 
	{
		delete m_pclsValue;
		m_pclsValue = NULL;
	}
}
