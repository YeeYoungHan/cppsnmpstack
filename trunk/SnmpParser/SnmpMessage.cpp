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
#include "SnmpAuth.h"
#include "AsnInt.h"
#include "AsnOid.h"
#include "AsnNull.h"
#include "Log.h"
#include "MemoryDebug.h"

#include "SnmpMessageMake.hpp"
#include "SnmpMessageParse.hpp"

CSnmpMessage::CSnmpMessage() : m_cVersion(SNMP_VERSION_2C), m_cCommand(SNMP_CMD_GET)
	, m_iRequestId(0), m_iErrorStatus(0), m_iErrorIndex(0)
	, m_iMsgId(0), m_iMsgMaxSize(0), m_cMsgFlags(0), m_iMsgSecurityModel(0)
	, m_iMsgAuthEngineBoots(0), m_iMsgAuthEngineTime(0)
	, m_pclsValue(NULL), m_pszPacket(NULL), m_iPacketLen(0)
{
}

CSnmpMessage::~CSnmpMessage()
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
int CSnmpMessage::ParsePacket( const char * pszPacket, int iPacketLen )
{
	CAsnComplex clsComplex;
	ASN_TYPE_LIST::iterator	itList;
	uint8_t cType = 0;
	int n;

	n = clsComplex.ParsePacket( pszPacket, iPacketLen );
	if( n == -1 ) return -1;

	for( itList = clsComplex.m_clsList.begin(); itList != clsComplex.m_clsList.end(); ++itList )
	{
		++cType;

		if( cType == 1 )
		{
			if( (*itList)->m_cType == ASN_TYPE_INT )
			{
				CAsnInt * pclsValue = (CAsnInt *)(*itList);
				m_cVersion = pclsValue->m_iValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s version type(%d) is not int", __FUNCTION__, (*itList)->m_cType );
				return -1;
			}
		}
		else if( cType == 2 )
		{
			if( m_cVersion != SNMP_VERSION_3 )
			{
				if( (*itList)->m_cType == ASN_TYPE_OCTET_STR )
				{
					CAsnString * pclsValue = (CAsnString *)(*itList);
					m_strCommunity = pclsValue->m_strValue;
				}
				else
				{
					CLog::Print( LOG_ERROR, "%s community type(%d) is not octet string", __FUNCTION__, (*itList)->m_cType );
					return -1;
				}
			}
			else
			{
				if( (*itList)->m_cType == ASN_TYPE_COMPLEX )
				{
					// msgGlobalData
					if( SetMsgGlobalData( (CAsnComplex *)*itList ) == false )
					{
						return -1;
					}
				}
				else
				{
					CLog::Print( LOG_ERROR, "%s msgGlobalData type(%d) is not complex", __FUNCTION__, (*itList)->m_cType );
					return -1;
				}
			}
		}
		else if( cType == 3 )
		{
			if( m_cVersion != SNMP_VERSION_3 )
			{
				if( SetCommand( (CAsnComplex *)(*itList) ) == false )
				{
					return -1;
				}

				break;
			}

			// msgSecurityParameters
			if( (*itList)->m_cType == ASN_TYPE_OCTET_STR )
			{
				CAsnString * pclsValue = (CAsnString *)(*itList);
				CAsnComplex clsData;

				if( clsData.ParsePacket( pclsValue->m_strValue.c_str(), pclsValue->m_strValue.length() ) == -1 )
				{
					return -1;
				}

				if( SetMsgSecurityParameters( &clsData ) == false )
				{
					return -1;
				}
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s msgSecurityParameters type(%d) is not octet string", __FUNCTION__, (*itList)->m_cType );
				return -1;
			}
		}
		else if( cType == 4 )
		{
			// msgData
			if( SetMsgData( (CAsnComplex *)(*itList) ) == false )
			{
				return -1;
			}
		}
	}

	return n;
}

/**
 * @ingroup SnmpParser
 * @brief ���� ������ ��Ŷ�� �����Ѵ�.
 * @param pszPacket		��Ŷ
 * @param iPacketSize ��Ŷ ũ��
 * @returns �����ϸ� ����� ��Ŷ ���̸� �����ϰ� �����ϸ� -1 �� �����Ѵ�.
 */
int CSnmpMessage::MakePacket( char * pszPacket, int iPacketSize )
{
	if( m_cVersion != SNMP_VERSION_3 )
	{
		return MakePacketV2( pszPacket, iPacketSize );
	}

	return MakePacketV3( pszPacket, iPacketSize );
}

/**
 * @ingroup SnmpParser
 * @brief ��Ŷ�� �����Ͽ��� ���� ������ �����Ѵ�.
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
 */
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
 * @brief ���� ������ �ʱ�ȭ��Ų��.
 */
void CSnmpMessage::Clear()
{
	m_iErrorStatus = 0;
	m_iErrorIndex = 0;

	m_iMsgId = 0;
	m_iMsgMaxSize = SNMP_MAX_PACKET_SIZE;
	m_cMsgFlags = 0;
	m_iMsgSecurityModel = SNMP_SECURITY_MODEL_USM;

	m_iMsgAuthEngineBoots = 0;
	m_iMsgAuthEngineTime = 0;

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
 * @brief SNMPv2 GET ��û �޽����� �����Ѵ�.
 * @param pszCommunity	community ���ڿ�
 * @param iRequestId		��û ���̵�
 * @param pszOid				OID ���ڿ�
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
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

/**
 * @ingroup SnmpParser
 * @brief SNMPv3 GET ��û �޽����� �����Ѵ�.
 * @param pszUserName	����� ���̵�
 * @param pszAuthPassWord	msgAuthenticationParameters ������ ���� ��й�ȣ
 * @param pszPrivPassWord msgPrivacyParameters ������ ���� ��й�ȣ
 * @param iRequestId	��û ���̵�
 * @param pszOid			OID ���ڿ�
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
 */
bool CSnmpMessage::MakeGetRequest( const char * pszUserName, const char * pszAuthPassWord, const char * pszPrivPassWord, uint32_t iRequestId, const char * pszOid )
{
	if( pszUserName == NULL || pszOid == NULL ) return false;

	Clear();

	m_cVersion = SNMP_VERSION_3;
	
	m_iMsgId = iRequestId;

	m_cCommand = SNMP_CMD_GET;
	m_iRequestId = iRequestId;

	m_cMsgFlags = SNMP_MSG_FLAG_REPORT;

	// �ι�° SNMP �޽��� ������ ���ؼ� �����Ѵ�.
	m_strReqOid = pszOid;

	if( pszUserName )
	{
		m_strUserId = pszUserName;
	}

	if( pszAuthPassWord )
	{
		m_strAuthPassWord = pszAuthPassWord;
	}

	if( pszPrivPassWord )
	{
		m_strPrivPassWord = pszPrivPassWord;
	}

	return true;
}

bool CSnmpMessage::SetAuthParams( )
{
	int		iPacketLen;
	char	szPacket[SNMP_MAX_PACKET_SIZE];

	m_strMsgAuthParams.clear();

	for( int i = 0; i < 12; ++i )
	{
		m_strMsgAuthParams.append( " " );
		m_strMsgAuthParams.at(i) = '\0';
	}

	iPacketLen = MakePacket( szPacket, sizeof(szPacket) );
	if( iPacketLen == -1 ) return false;

	if( SnmpMakeHmac( szPacket, iPacketLen, m_strAuthPassWord.c_str(), m_strMsgAuthEngineId.c_str(), m_strMsgAuthEngineId.length(), m_strMsgAuthParams ) == false )
	{
		return false;
	}

	return true;
}

CSnmpMessage * CSnmpMessage::Create( CSnmpMessage * pclsMessage )
{
	CSnmpMessage * pclsCopy = new CSnmpMessage();
	if( pclsCopy == NULL ) return NULL;

	*pclsCopy = *pclsMessage;

	pclsCopy->m_pclsValue = NULL;

	pclsCopy->m_pszPacket = NULL;
	pclsCopy->m_iPacketLen = 0;

	return pclsCopy;
}
