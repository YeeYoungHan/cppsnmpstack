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

#include "SnmpDefine.h"
#include "SnmpTcpAgent.h"
#include "TimeUtility.h"
#include "Log.h"
#include "ServerUtility.h"
#include "MemoryDebug.h"

#include "SnmpTcpAgentThread.hpp"

CSnmpTcpAgent::CSnmpTcpAgent() : m_bStop(false), m_hSocket(INVALID_SOCKET), m_pclsCallBack(NULL)
{
}

CSnmpTcpAgent::~CSnmpTcpAgent()
{
}

bool CSnmpTcpAgent::Open( int iTcpPort, const char * pszCommunity
	, const char * pszUserName, const char * pszAuthPassWord, const char * pszPrivPassWord, ISnmpTcpAgentCallBack * pclsCallBack )
{
	if( pszCommunity == NULL && pszUserName == NULL )
	{
		CLog::Print( LOG_ERROR, "%s pszCommunity and pszUserName is NULL", __FUNCTION__ );
		return false;
	}

	if( m_hSocket != INVALID_SOCKET )
	{
		CLog::Print( LOG_ERROR, "%s already open", __FUNCTION__ );
		return false;
	}

	if( pszCommunity ) m_strCommunity = pszCommunity;
	if( pszUserName ) m_strUserName = pszUserName;
	if( pszAuthPassWord ) m_strAuthPassWord = pszAuthPassWord;
	if( pszPrivPassWord ) m_strPrivPassWord = pszPrivPassWord;
	m_pclsCallBack = pclsCallBack;

	m_hSocket = TcpListen( iTcpPort, 255 );
	if( m_hSocket == INVALID_SOCKET )
	{
		CLog::Print( LOG_ERROR, "%s TcpListen(%d) error(%d)", __FUNCTION__, iTcpPort, GetError() );
		return false;
	}

	m_bStop = false;

	if( StartThread( "SnmpTcpAgentListenThread", SnmpTcpAgentListenThread, this ) == false )
	{
		CLog::Print( LOG_ERROR, "%s start SnmpTcpAgentListenThread error(%d)", __FUNCTION__, GetError() );
		return false;
	}

	return true;
}

void CSnmpTcpAgent::Close()
{
	m_bStop = true;
}
