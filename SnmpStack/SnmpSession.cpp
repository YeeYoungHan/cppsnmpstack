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

#include "SnmpSession.h"
#include "AsnNull.h"
#include "Log.h"
#include "SnmpDebug.h"
#include "MemoryDebug.h"

#include "SnmpSessionComm.hpp"

CSnmpSession::CSnmpSession() : m_iPort(161), m_iIp(0), m_sPort(0)
	, m_iMiliTimeout(1000), m_iReSendCount(5), m_iRequestId(0)
	, m_hSocket(INVALID_SOCKET)
	, m_bDebug(false)
{
}

CSnmpSession::~CSnmpSession()
{
	Close();
}

/**
 * @ingroup SnmpStack
 * @brief SNMP 요청 메시지를 전송할 SNMP Agent 주소를 설정한다.
 * @param pszIp	IP 주소
 * @param iPort 포트 번호
 * @returns 성공하면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool CSnmpSession::SetDestination( const char * pszIp, int iPort )
{
	if( pszIp == NULL || strlen(pszIp) == 0 ) return false;
	if( iPort <= 0 || iPort > 65535 ) return false;

	m_strIp = pszIp;
	m_iPort = iPort;

	m_iIp = inet_addr( pszIp );
	m_sPort = htons( m_iPort );

	return true;
}

/**
 * @ingroup SnmpStack
 * @brief SNMPv2 를 위한 SNMP community 문자열을 설정한다.
 * @param pszCommunity SNMP community 문자열
 * @returns 성공하면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool CSnmpSession::SetSnmpv2( const char * pszCommunity )
{
	if( pszCommunity == NULL ) return false;

	m_strCommunity = pszCommunity;

	return true;
}

/**
 * @ingroup SnmpStack
 * @brief SNMPv3 를 위한 사용자 아이디 및 비밀번호를 설정한다.
 * @param pszUserName			사용자 아이디
 * @param pszAuthPassWord 인증 비밀번호
 * @param pszPrivPassWord 암호화 비밀번호
 * @returns 성공하면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool CSnmpSession::SetSnmpv3( const char * pszUserName, const char * pszAuthPassWord, const char * pszPrivPassWord )
{
	if( pszUserName == NULL ) return false;
	if( pszAuthPassWord == NULL ) return false;

	m_strUserName = pszUserName;
	m_strAuthPassWord = pszAuthPassWord;

	if( pszPrivPassWord )
	{
		m_strPrivPassWord = pszPrivPassWord;
	}

	return true;
}

/**
 * @ingroup SnmpStack
 * @brief 재전송을 위한 수신 대기 timeout 시간을 설정한다.
 * @param iMiliSecond milisecond timeout 시간
 * @returns 성공하면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool CSnmpSession::SetTimeout( int iMiliSecond )
{
	if( iMiliSecond <= 0 ) return false;

	m_iMiliTimeout = iMiliSecond;

	return true;
}

/**
 * @ingroup SnmpStack
 * @brief timeout 되었을 때에 재전송하는 개수를 설정한다.
 * @param iReSendCount timeout 되었을 때에 재전송하는 개수
 * @returns 성공하면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool CSnmpSession::SetReSendCount( int iReSendCount )
{
	if( iReSendCount < 0 ) return false;

	m_iReSendCount = iReSendCount;

	return true;
}

void CSnmpSession::SetDebug( bool bDebug )
{
	m_bDebug = bDebug;
}

/**
 * @ingroup SnmpStack
 * @brief SNMP 통신을 위한 UDP 소켓을 생성한다.
 * @returns 성공하면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool CSnmpSession::Open()
{
	if( m_hSocket != INVALID_SOCKET ) return false;

	m_hSocket = UdpSocket();
	if( m_hSocket == INVALID_SOCKET ) return false;

	return true;
}

/**
 * @ingroup SnmpStack
 * @brief SNMP 통신을 위한 UDP 소켓을 종료한다.
 */
void CSnmpSession::Close()
{
	if( m_hSocket != INVALID_SOCKET )
	{
		closesocket( m_hSocket );
		m_hSocket = INVALID_SOCKET;
	}
}

/**
 * @ingroup SnmpStack
 * @brief SNMP GET 메시지를 전송하여서 이에 대한 응답을 수신한다.
 * @param pszOid				MIB
 * @param ppclsAsnType	응답 메시지의 ASN 타입 저장 변수
 * @returns 성공하면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool CSnmpSession::SendGetRequest( const char * pszOid, CAsnType ** ppclsAsnType )
{
	CSnmpMessage clsRequest;
	uint32_t iRequestId = ++m_iRequestId;

	if( m_strUserName.empty() )
	{
		// SNMPv2
		if( clsRequest.MakeGetRequest( m_strCommunity.c_str(), iRequestId, pszOid ) == false )
		{
			CLog::Print( LOG_ERROR, "%s MakeGetRequest SNMPv2 error", __FUNCTION__ );
			return false;
		}
	}
	else
	{
		// SNMPv3
		if( clsRequest.MakeGetRequest( m_strUserName.c_str(), m_strAuthPassWord.c_str(), m_strPrivPassWord.c_str(), iRequestId, pszOid ) == false )
		{
			CLog::Print( LOG_ERROR, "%s MakeGetRequest SNMPv2 error", __FUNCTION__ );
			return false;
		}
	}

	if( SendRequest( &clsRequest, &m_clsResponse ) == false ) return false;

	*ppclsAsnType = m_clsResponse.m_pclsValue;

	return true;
}

/**
 * @ingroup SnmpStack
 * @brief SNMP GET NEXT 메시지를 전송하여서 이에 대한 응답을 수신한다.
 * @param pszOid						MIB
 * @param ppstrResponseOid	응답 메시지의 OID 저장 변수
 * @param ppclsAsnType			응답 메시지의 ASN 타입 저장 변수
 * @returns 성공하면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool CSnmpSession::SendGetNextRequest( const char * pszOid, std::string ** ppstrResponseOid, CAsnType ** ppclsAsnType )
{
	CSnmpMessage clsRequest;
	uint32_t iRequestId = ++m_iRequestId;

	if( m_strUserName.empty() )
	{
		// SNMPv2
		if( clsRequest.MakeGetNextRequest( m_strCommunity.c_str(), iRequestId, pszOid ) == false )
		{
			CLog::Print( LOG_ERROR, "%s MakeGetRequest SNMPv2 error", __FUNCTION__ );
			return false;
		}
	}
	else
	{
		// SNMPv3
		if( clsRequest.MakeGetNextRequest( m_strUserName.c_str(), m_strAuthPassWord.c_str(), m_strPrivPassWord.c_str(), iRequestId, pszOid ) == false )
		{
			CLog::Print( LOG_ERROR, "%s MakeGetRequest SNMPv2 error", __FUNCTION__ );
			return false;
		}
	}

	if( SendRequest( &clsRequest, &m_clsResponse ) == false ) return false;

	*ppstrResponseOid = &m_clsResponse.m_strOid;
	*ppclsAsnType = m_clsResponse.m_pclsValue;

	return true;
}
