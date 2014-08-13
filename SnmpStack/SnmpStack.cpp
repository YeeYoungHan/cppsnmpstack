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

#include "SnmpPlatformDefine.h"
#include "SnmpStackDefine.h"
#include "SnmpStack.h"
#include "SnmpUdp.h"
#include "SnmpThread.h"
#include "TimeUtility.h"
#include "Log.h"
#include "MemoryDebug.h"

CSnmpStack::CSnmpStack()
{
	m_clsTransactionList.SetSnmpStack( this );
}

CSnmpStack::~CSnmpStack()
{
}

bool CSnmpStack::Start( CSnmpStackSetup & clsSetup, ISnmpStackCallBack * pclsCallBack )
{
	InitNetwork();

	m_clsSetup = clsSetup;

	if( m_clsSetup.m_iLocalPort == 0 )
	{
		m_hSocket = UdpSocket();
	}
	else
	{
		m_hSocket = UdpListen( m_clsSetup.m_iLocalPort, NULL );
	}

	if( m_hSocket == INVALID_SOCKET )
	{
		CLog::Print( LOG_ERROR, "%s udp socket create error(%d)", __FUNCTION__, GetError() );
		return false;
	}

	m_pclsCallBack = pclsCallBack;

	if( StartSnmpStackThread( this ) == false ||
			StartSnmpUdpThread( this ) == false )
	{
		goto FUNC_ERROR;
	}

	return true;

FUNC_ERROR:
	Stop();

	return false;
}

bool CSnmpStack::Stop( )
{
	StopSnmpStackThread();
	StopSnmpUdpThread();

	for( int i = 0; i < 500; ++i )
	{
		if( IsSnmpStackThreadRun() == false && IsSnmpUdpThreadRun() == false ) break;

		MiliSleep(20);
	}

	closesocket( m_hSocket );

	return true;
}

bool CSnmpStack::SendRequest( const char * pszIp, int iPort, CSnmpMessage * pclsRequest )
{
	if( pclsRequest->MakePacket() == false ) return false;
	pclsRequest->m_strDestIp = pszIp;
	pclsRequest->m_iDestPort = iPort;

	if( m_clsTransactionList.Insert( pclsRequest ) == false ) return false;

	UdpSend( m_hSocket, pclsRequest->m_pszPacket, pclsRequest->m_iPacketLen, pclsRequest->m_strDestIp.c_str(), pclsRequest->m_iDestPort );

	return true;
}
