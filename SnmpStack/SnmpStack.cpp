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

/**
 * @ingroup SnmpStack
 * @brief SNMP 서버로 SNMP 요청 메시지를 전송한 후, 이에 대한 SNMP 응답 메시지를 수신한다.
 * @param pszDestIp		SNMP 서버 IP 주소
 * @param iPort				SNMP 서버 포트
 * @param clsRequest	SNMP 요청 메시지
 * @param clsResponse SNMP 응답 메시지 저장 변수
 * @param iTimeout		최대 수신 대기 시간 (초단위)
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CSnmpStack::SendRequest( const char * pszDestIp, int iPort, CSnmpMessage & clsRequest, CSnmpMessage & clsResponse, int iTimeout )
{
	char szPacket[1500], szIp[16];
	int  iPacketLen, n;
	uint16_t	sPort;
	pollfd sttPoll[1];
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

	sttPoll[0].fd = hSocket;
	sttPoll[0].events = POLLIN;
	sttPoll[0].revents = 0;

	n = poll( sttPoll, 1, 1000 * iTimeout );
	if( n <= 0 )
	{
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
