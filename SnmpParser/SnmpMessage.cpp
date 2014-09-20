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
 * @brief 내부 변수를 초기화시킨다.
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
 * @brief SNMPv2 GET 요청 메시지를 생성한다.
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

/**
 * @ingroup SnmpParser
 * @brief SNMPv2 GET NEXT 요청 메시지를 생성한다.
 * @param pszCommunity	community 문자열
 * @param iRequestId		요청 아이디
 * @param pszOid				OID 문자열
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CSnmpMessage::MakeGetNextRequest( const char * pszCommunity, uint32_t iRequestId, const char * pszOid )
{
	if( MakeGetRequest( pszCommunity, iRequestId, pszOid ) == false ) return false;

	m_cCommand = SNMP_CMD_GET_NEXT;

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief SNMPv3 GET 요청 메시지를 생성한다.
 * @param pszUserName	사용자 아이디
 * @param pszAuthPassWord	msgAuthenticationParameters 생성을 위한 비밀번호
 * @param pszPrivPassWord msgPrivacyParameters 생성을 위한 비밀번호
 * @param iRequestId	요청 아이디
 * @param pszOid			OID 문자열
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
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

	// 두번째 SNMP 메시지 전송을 위해서 저장한다.
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
 * @brief SNMPv3 GET 요청 메시지를 생성한다.
 * @param pszUserName	사용자 아이디
 * @param pszAuthPassWord	msgAuthenticationParameters 생성을 위한 비밀번호
 * @param pszPrivPassWord msgPrivacyParameters 생성을 위한 비밀번호
 * @param iRequestId	요청 아이디
 * @param pszOid			OID 문자열
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CSnmpMessage::MakeGetNextRequest( const char * pszUserName, const char * pszAuthPassWord, const char * pszPrivPassWord, uint32_t iRequestId, const char * pszOid )
{
	if( MakeGetRequest( pszUserName, pszAuthPassWord, pszPrivPassWord, iRequestId, pszOid ) == false ) return false;

	m_cCommand = SNMP_CMD_GET_NEXT;

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief SNMP 메시지를 생성한 후, 입력된 SNMP 메시지를 복사한다.
 * @param pclsMessage SNMP 메시지
 * @returns 성공하면 복사된 SNMP 메시지를 리턴하고 그렇지 않으면 NULL 을 리턴한다.
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
