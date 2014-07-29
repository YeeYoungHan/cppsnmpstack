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
#include "SnmpStack.h"
#include "SnmpUdp.h"
#include "Log.h"
#include "MemoryDebug.h"

CSnmpStack::CSnmpStack()
{
}

CSnmpStack::~CSnmpStack()
{
}

bool CSnmpStack::SendRequest( const char * pszDestIp, int iPort, CSnmpMessage & clsRequest, CSnmpMessage & clsResponse )
{
	char szPacket[1500], szIp[16];
	int  iPacketLen;
	uint16_t	sPort;
	bool bRes = false;
	Socket hSocket = UdpSocket();
	if( hSocket == INVALID_SOCKET )
	{
		CLog::Print( LOG_ERROR, "%s UdpSocket error", __FUNCTION__ );
		return false;
	}

	iPacketLen = clsRequest.MakePacket( szPacket, sizeof(szPacket) );
	if( iPacketLen == -1 )
	{
		CLog::Print( LOG_ERROR, "%s clsRequest.MakePacket error", __FUNCTION__ );
		goto FUNC_END;
	}

	if( UdpSend( hSocket, szPacket, iPacketLen, pszDestIp, iPort ) == false )
	{
		CLog::Print( LOG_ERROR, "%s UdpSend error(%d)", __FUNCTION__, GetError() );
		goto FUNC_END;
	}

	iPacketLen = sizeof(szPacket);
	if( UdpRecv( hSocket, (char *)szPacket, &iPacketLen, szIp, sizeof(szIp), &sPort ) == false )
	{
		CLog::Print( LOG_ERROR, "%s UdpRecv error(%d)", __FUNCTION__, GetError() );
		goto FUNC_END;
	}

	if( clsResponse.ParsePacket( szPacket, iPacketLen ) == -1 )
	{
		CLog::Print( LOG_ERROR, "%s clsResponse.ParsePacket error(%d)", __FUNCTION__, GetError() );
		goto FUNC_END;
	}

	bRes = true;

FUNC_END:
	closesocket( hSocket );

	return bRes;
}
