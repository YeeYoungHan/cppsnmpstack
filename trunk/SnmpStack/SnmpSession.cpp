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
#include "MemoryDebug.h"

#include "SnmpSessionPrivate.hpp"

CSnmpSession::CSnmpSession() : m_iPort(161), m_iIp(0), m_sPort(0)
	, m_iMiliTimeout(1000), m_iReSendCount(5), m_iRequestId(0)
	, m_hSocket(INVALID_SOCKET)
{
}

CSnmpSession::~CSnmpSession()
{
	Close();
}

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

bool CSnmpSession::SetSnmpv2( const char * pszCommunity )
{
	if( pszCommunity == NULL ) return false;

	m_strCommunity = pszCommunity;

	return true;
}

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

bool CSnmpSession::SetTimeout( int iMiliSecond )
{
	if( iMiliSecond <= 0 ) return false;

	m_iMiliTimeout = iMiliSecond;

	return true;
}

bool CSnmpSession::SetReSendCount( int iReSendCount )
{
	if( iReSendCount < 0 ) return false;

	m_iReSendCount = iReSendCount;

	return true;
}

bool CSnmpSession::Open()
{
	if( m_hSocket != INVALID_SOCKET ) return false;

	m_hSocket = UdpSocket();
	if( m_hSocket == INVALID_SOCKET ) return false;

	return true;
}

bool CSnmpSession::Close()
{
	if( m_hSocket != INVALID_SOCKET )
	{
		closesocket( m_hSocket );
		m_hSocket = INVALID_SOCKET;
	}

	return true;
}

bool CSnmpSession::SendRequest( CSnmpMessage * pclsRequest, CSnmpMessage * pclsResponse )
{
	if( SendRecv( pclsRequest, pclsResponse ) == false ) return false;

	if( pclsRequest->m_cMsgFlags == SNMP_MSG_FLAG_REPORT )
	{
		CSnmpMessage * pclsSecondRequest = CSnmpMessage::Create( pclsRequest );
		if( pclsSecondRequest )
		{
			pclsSecondRequest->m_iMsgId = ++m_iRequestId;
			pclsSecondRequest->m_iRequestId = pclsSecondRequest->m_iMsgId;
			pclsSecondRequest->m_strOid = pclsSecondRequest->m_strReqOid;

			pclsSecondRequest->m_strMsgAuthEngineId = pclsResponse->m_strMsgAuthEngineId;
			pclsSecondRequest->m_iMsgAuthEngineBoots = pclsResponse->m_iMsgAuthEngineBoots;
			pclsSecondRequest->m_iMsgAuthEngineTime = pclsResponse->m_iMsgAuthEngineTime;
			pclsSecondRequest->m_strMsgUserName = pclsSecondRequest->m_strUserId;

			pclsSecondRequest->m_strContextEngineId = pclsResponse->m_strContextEngineId;
			pclsSecondRequest->m_pclsValue = new CAsnNull();

			pclsSecondRequest->SetPrivParams( );
			pclsSecondRequest->SetAuthParams( );

			bool bRes = SendRecv( pclsSecondRequest, pclsResponse );
			delete pclsSecondRequest;

			if( bRes == false ) return false;

			if( pclsResponse->m_strEncryptedPdu.empty() == false )
			{
				pclsResponse->m_strPrivPassWord = pclsRequest->m_strPrivPassWord;
				pclsResponse->ParseEncryptedPdu( );
			}
		}
	}

	return true;
}

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
