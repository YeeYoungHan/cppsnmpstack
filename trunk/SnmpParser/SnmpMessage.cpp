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
#include "TimeUtility.h"
#include <stdlib.h>
#include "MemoryDebug.h"

#include "SnmpMessageMake.hpp"
#include "SnmpMessageParse.hpp"
#include "SnmpMessagev3.hpp"

CSnmpMessage::CSnmpMessage() : m_cVersion(SNMP_VERSION_2C), m_cCommand(SNMP_CMD_GET)
	, m_iRequestId(0), m_iErrorStatus(0), m_iErrorIndex(0), m_pclsValue(NULL)
	, m_iMsgId(0), m_iMsgMaxSize(0), m_cMsgFlags(0), m_iMsgSecurityModel(0)
	, m_iMsgAuthEngineBoots(0), m_iMsgAuthEngineTime(0)
	, m_pszPacket(NULL), m_iPacketLen(0)
	, m_iDestPort(0)
{
}

CSnmpMessage::~CSnmpMessage()
{
	Clear();
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
 * @brief SNMPv2 GET NEXT ��û �޽����� �����Ѵ�.
 * @param pszCommunity	community ���ڿ�
 * @param iRequestId		��û ���̵�
 * @param pszOid				OID ���ڿ�
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
 */
bool CSnmpMessage::MakeGetNextRequest( const char * pszCommunity, uint32_t iRequestId, const char * pszOid )
{
	if( MakeGetRequest( pszCommunity, iRequestId, pszOid ) == false ) return false;

	m_cCommand = SNMP_CMD_GET_NEXT;

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
bool CSnmpMessage::MakeGetNextRequest( const char * pszUserName, const char * pszAuthPassWord, const char * pszPrivPassWord, uint32_t iRequestId, const char * pszOid )
{
	if( MakeGetRequest( pszUserName, pszAuthPassWord, pszPrivPassWord, iRequestId, pszOid ) == false ) return false;

	m_cCommand = SNMP_CMD_GET_NEXT;

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief SNMP �޽����� ������ ��, �Էµ� SNMP �޽����� �����Ѵ�.
 * @param pclsMessage SNMP �޽���
 * @returns �����ϸ� ����� SNMP �޽����� �����ϰ� �׷��� ������ NULL �� �����Ѵ�.
 */
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
