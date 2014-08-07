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

#include "SnmpMessage.h"
#include "AsnInt.h"
#include "AsnString.h"
#include "AsnOid.h"
#include "AsnNull.h"
#include "AsnComplex.h"
#include "MemoryDebug.h"

CSnmpMessage::CSnmpMessage() : m_pclsValue(NULL), m_pszPacket(NULL), m_iPacketLen(0)
{
}

CSnmpMessage::~CSnmpMessage()
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
int CSnmpMessage::ParsePacket( const char * pszPacket, int iPacketLen )
{
	CAsnComplex clsComplex;
	ASN_TYPE_LIST::iterator	itRoot;
	uint8_t cType = 0;
	int n;

	n = clsComplex.ParsePacket( pszPacket, iPacketLen );
	if( n == -1 ) return -1;

	for( itRoot = clsComplex.m_clsList.begin(); itRoot != clsComplex.m_clsList.end(); ++itRoot )
	{
		++cType;

		if( cType == 1 )
		{
			if( (*itRoot)->m_cType == ASN_TYPE_INT )
			{
				CAsnInt * pclsValue = (CAsnInt *)(*itRoot);
				m_cVersion = pclsValue->m_iValue;
			}
		}
		else if( cType == 2 )
		{
			if( (*itRoot)->m_cType == ASN_TYPE_OCTET_STR )
			{
				CAsnString * pclsValue = (CAsnString *)(*itRoot);
				m_strCommunity = pclsValue->m_strValue;
			}
		}
		else if( cType == 3 )
		{
			break;
		}
	}

	if( cType == 3 )
	{
		m_cCommand = (*itRoot)->m_cType;
		CAsnComplex * pclsCmd = (CAsnComplex *)(*itRoot);
		ASN_TYPE_LIST::iterator	itCmd;
		cType = 0;

		for( itCmd = pclsCmd->m_clsList.begin(); itCmd != pclsCmd->m_clsList.end(); ++itCmd )
		{
			++cType;

			if( cType == 1 )
			{
				if( (*itCmd)->m_cType == ASN_TYPE_INT )
				{
					CAsnInt * pclsValue = (CAsnInt *)(*itCmd);
					m_iRequestId = pclsValue->m_iValue;
				}
			}
			else if( cType == 2 )
			{
				if( (*itCmd)->m_cType == ASN_TYPE_INT )
				{
					CAsnInt * pclsValue = (CAsnInt *)(*itCmd);
					m_iErrorStatus = pclsValue->m_iValue;
				}
			}
			else if( cType == 3 )
			{
				if( (*itCmd)->m_cType == ASN_TYPE_INT )
				{
					CAsnInt * pclsValue = (CAsnInt *)(*itCmd);
					m_iErrorIndex = pclsValue->m_iValue;
				}
			}
			else if( cType == 4 )
			{
				break;
			}
		}

		if( cType == 4 )
		{
			CAsnComplex * pclsBodyFrame = (CAsnComplex *)(*itCmd);
			CAsnComplex * pclsBody = (CAsnComplex *)(*pclsBodyFrame->m_clsList.begin());
			ASN_TYPE_LIST::iterator	itBody;
			cType = 0;

			for( itBody = pclsBody->m_clsList.begin(); itBody != pclsBody->m_clsList.end(); ++itBody )
			{
				++cType;

				if( cType == 1 )
				{
					CAsnOid * pclsValue = (CAsnOid *)(*itBody);
					m_strOid = pclsValue->m_strValue;
				}
				else if( cType == 2 )
				{
					m_pclsValue = (*itBody)->Copy();
				}
			}
		}
	}

	return n;
}

/**
 * @ingroup SnmpParser
 * @brief 내부 변수를 패킷에 저장한다.
 * @param pszPacket		패킷
 * @param iPacketSize 패킷 크기
 * @returns 성공하면 저장된 패킷 길이를 리턴하고 실패하면 -1 을 리턴한다.
 */
int CSnmpMessage::MakePacket( char * pszPacket, int iPacketSize )
{
	CAsnComplex clsComplex;
	CAsnComplex *pclsCommand = NULL, *pclsBodyFrame = NULL, *pclsBody = NULL;

	if( clsComplex.AddInt( m_cVersion ) == false ) return -1;
	if( clsComplex.AddString( m_strCommunity.c_str() ) == false ) return -1;

	pclsCommand = new CAsnComplex();
	if( pclsCommand == NULL ) return -1;

	pclsCommand->m_cType = m_cCommand;
	if( pclsCommand->AddInt( m_iRequestId ) == false ) goto FUNC_ERROR;
	if( pclsCommand->AddInt( m_iErrorStatus ) == false ) goto FUNC_ERROR;
	if( pclsCommand->AddInt( m_iErrorIndex ) == false ) goto FUNC_ERROR;

	pclsBodyFrame = new CAsnComplex();
	if( pclsBodyFrame == NULL ) goto FUNC_ERROR;

	pclsBody = new CAsnComplex();
	if( pclsBody == NULL ) goto FUNC_ERROR;

	if( pclsBody->AddOid( m_strOid.c_str() ) == false ) goto FUNC_ERROR;

	{
		CAsnType * pclsValue = m_pclsValue->Copy();
		if( pclsValue == NULL ) goto FUNC_ERROR;
		if( pclsBody->AddValue( pclsValue ) == false ) goto FUNC_ERROR;
	}

	pclsBodyFrame->AddComplex( pclsBody );
	pclsCommand->AddComplex( pclsBodyFrame );
	clsComplex.AddComplex( pclsCommand );

	return clsComplex.MakePacket( pszPacket, iPacketSize );

FUNC_ERROR:
	if( pclsCommand ) delete pclsCommand;
	if( pclsBodyFrame ) delete pclsBodyFrame;
	if( pclsBody ) delete pclsBody;

	return -1;
}

bool CSnmpMessage::MakePacket( )
{
	if( m_pszPacket == NULL )
	{
		m_pszPacket = (char *)malloc( SNMP_MAX_PACKET_SIZE );
		if( m_pszPacket == NULL ) return false;
	}

	m_iPacketLen = MakePacket( m_pszPacket, SNMP_MAX_PACKET_SIZE );
	if( m_iPacketLen == -1 ) 
	{
		free( m_pszPacket );
		m_pszPacket = NULL;
		return false;
	}

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief 내부 변수를 초기화시킨다.
 */
void CSnmpMessage::Clear()
{
	m_iErrorStatus = 0;
	m_iErrorIndex = 0;

	if( m_pclsValue )
	{
		delete m_pclsValue;
		m_pclsValue = NULL;
	}

	if( m_pszPacket )
	{
		free( m_pszPacket );
		m_pszPacket = NULL;
	}
}

/**
 * @ingroup SnmpParser
 * @brief SNMP GET 요청 메시지를 생성한다.
 * @param pszCommunity	community 문자열
 * @param iRequestId		요청 아이디
 * @param pszOid				OID 문자열
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CSnmpMessage::MakeGetRequest( const char * pszCommunity, uint32_t iRequestId, const char * pszOid )
{
	if( pszCommunity == NULL || pszOid == NULL ) return false;

	Clear();

	m_cVersion = SNMP_VERSION_2C;
	m_strCommunity = pszCommunity;
	m_cCommand = SNMP_CMD_GET;
	m_iRequestId = iRequestId;
	m_strOid = pszOid;
	m_pclsValue = new CAsnNull();
	if( m_pclsValue == NULL ) return false;

	return true;
}
