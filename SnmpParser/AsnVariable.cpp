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
#include "Log.h"

CAsnVariable::CAsnVariable() : m_cType(0), m_cLength(0), m_pValue(NULL)
{
}

CAsnVariable::~CAsnVariable()
{
	
}

int CAsnVariable::ParsePacket( const char * pszPacket, int iPacketLen )
{
	int iPos = 0;

	Clear( );

	m_cType = pszPacket[iPos++];
	m_cLength = pszPacket[iPos++];

	switch( m_cType )
	{
	case ASN_TYPE_INT:
		{
			m_pValue = malloc( sizeof(int) );
			if( m_pValue == NULL ) return -1;
			int * piValue = (int *)m_pValue;

			if( m_cLength == 1 )
			{
				*piValue = pszPacket[iPos++];
			}
			else if( m_cLength == 2 )
			{
				int16_t sValue;

				memcpy( &sValue, pszPacket + iPos, 2 );
				*piValue = ntohs( sValue );
				iPos += 2;
			}
			else if( m_cLength == 4 )
			{
				int32_t iValue;

				memcpy( &iValue, pszPacket + iPos, 2 );
				*piValue = ntohl( iValue );
				iPos += 4;
			}
		}
		break;
	case ASN_TYPE_OCTET_STR:
		{
			m_pValue = malloc( m_cLength + 1 );
			if( m_pValue == NULL ) return -1;
			char * pszValue = (char *)m_pValue;

			memcpy( pszValue, pszPacket + iPos, m_cLength );
			pszValue[m_cLength] = '\0';
			iPos += m_cLength;
		}
		break;
	case ASN_TYPE_OID:
		{
			char	szValue[512];
			int	iValueLen = 0;

			memset( szValue, 0, sizeof(szValue) );
			
			iValueLen = snprintf( szValue, sizeof(szValue), "%d.%d", pszPacket[iPos] / 40, pszPacket[iPos] % 40 );
			++iPos;

			for( int i = 1; i < m_cLength; ++i )
			{
				iValueLen += snprintf( szValue + iValueLen, sizeof(szValue) - iValueLen, ".%d", pszPacket[iPos++] );
			}

			m_pValue = malloc( iValueLen + 1 );
			if( m_pValue == NULL ) return -1;
			char * pszValue = (char *)m_pValue;

			memcpy( pszValue, szValue, iValueLen );
			pszValue[iValueLen] = '\0';
			m_cLength = iValueLen;
		}
		break;
	case ASN_TYPE_NULL:
	case ASN_TYPE_NO_SUCH_OBJECT:
		break;
	default:
		CLog::Print( LOG_ERROR, "%s type(%d) is not defined", __FUNCTION__, m_cType );
		break;
	}

	return iPos;
}

bool CAsnVariable::GetString( std::string & strValue )
{
	if( m_cType != ASN_TYPE_OCTET_STR ) return false;

	strValue = (char * )m_pValue;

	return true;
}

bool CAsnVariable::GetOid( std::string & strValue )
{
	if( m_cType != ASN_TYPE_OID ) return false;

	strValue = (char * )m_pValue;

	return true;
}

int CAsnVariable::MakePacket( char * pszPacket, int iPacketSize )
{
	int iPos = 0;

	pszPacket[iPos++] = m_cType;

	switch( m_cType )
	{
	case ASN_TYPE_INT:
		{
			if( m_pValue == NULL ) return -1;
			int iValue = *(int *)(m_pValue);

			if( iValue <= 0xFF )
			{
				pszPacket[iPos++] = 1;
				pszPacket[iPos++] = iValue;
			}
			else if( iValue <= 0xFFFF )
			{
				pszPacket[iPos++] = 2;

				int16_t sValue = htons( iValue );
				memcpy( pszPacket + iPos, &sValue, 2 );
				iPos += 2;
			}
			else
			{
				pszPacket[iPos++] = 4;

				iValue = htons( iValue );
				memcpy( pszPacket + iPos, &iValue, 2 );
				iPos += 4;
			}
		}
		break;
	case ASN_TYPE_OCTET_STR:
		if( m_pValue == NULL ) return -1;
		pszPacket[iPos++] = m_cLength;
		memcpy( pszPacket + iPos, m_pValue, m_cLength );
		iPos += m_cLength;
		break;
	case ASN_TYPE_OID:
		{
			if( m_pValue == NULL ) return -1;

			char * pszValue = (char *)m_pValue;
			char szValue[11];
			int	 iValuePos = 0, iNumPos = 0;
			uint8_t cValue;

			++iPos;
			memset( szValue, 0, sizeof(szValue) );

			for( int i = 0; i < m_cLength; ++i )
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
		}
		break;
	case ASN_TYPE_NULL:
	case ASN_TYPE_NO_SUCH_OBJECT:
		pszPacket[iPos++] = 0;
		break;
	default:
		CLog::Print( LOG_ERROR, "%s type(%d) is not defined", __FUNCTION__, m_cType );
		break;
	}

	return iPos;
}

bool CAsnVariable::SetString( const char * pszValue )
{
	if( pszValue == NULL ) return false;

	Clear( );

	m_cType = ASN_TYPE_OCTET_STR;

	int iLen = strlen( pszValue );

	m_pValue = malloc( iLen + 1 );
	if( m_pValue == NULL ) return false;
	char * pszTemp = (char *)m_pValue;

	memcpy( pszTemp, pszValue, iLen );
	pszTemp[iLen] = '\0';
	m_cLength = iLen;

	return true;
}

bool CAsnVariable::SetOid( const char * pszValue )
{
	if( pszValue == NULL ) return false;

	Clear( );

	m_cType = ASN_TYPE_OID;

	int iLen = strlen( pszValue );

	m_pValue = malloc( iLen + 1 );
	if( m_pValue == NULL ) return false;
	char * pszTemp = (char *)m_pValue;

	memcpy( pszTemp, pszValue, iLen );
	pszTemp[iLen] = '\0';
	m_cLength = iLen;

	return true;
}

void CAsnVariable::SetNull( )
{
	Clear( );

	m_cType = ASN_TYPE_NULL;
	m_cLength = 0;
}

void CAsnVariable::Clear( )
{
	if( m_pValue ) 
	{
		free( m_pValue );
		m_pValue = NULL;
	}
}
