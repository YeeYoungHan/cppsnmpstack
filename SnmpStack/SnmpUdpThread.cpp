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
#include "SnmpThread.h"
#include "ServerUtility.h"
#include "Log.h"
#include "MemoryDebug.h"

static bool gbStop = false;
static bool gbRun = false;

static void SnmpRecvProcess( CSnmpStack * pclsSnmpStack, char * pszPacket, int iPacketSize, char * pszIp, uint16_t sPort )
{
	CSnmpMessage clsMessage;

	if( clsMessage.ParsePacket( pszPacket, iPacketSize ) == -1 )
	{
		CLog::Print( LOG_ERROR, "%s clsMessage.ParsePacket() error", __FUNCTION__ );
		return;
	}

	if( pclsSnmpStack->m_clsTransactionList.Delete( &clsMessage ) )
	{
		pclsSnmpStack->m_pclsCallBack->RecvResponse( NULL, &clsMessage );
	}
}

THREAD_API SnmpUdpThread( LPVOID lpParameter )
{
	CSnmpStack * pclsSnmpStack = (CSnmpStack *)lpParameter;
	struct pollfd arrPoll[1];
	int		n, iPacketSize;
	char	szPacket[SNMP_MAX_PACKET_SIZE], szIp[16];
	uint16_t sPort;

	gbRun = true;

	TcpSetPollIn( arrPoll[0], pclsSnmpStack->m_hSocket );

	while( gbStop == false )
	{
		n = poll( arrPoll, 1, 1000 );
		if( n > 0 )
		{
			iPacketSize = sizeof(szPacket);
			if( UdpRecv( pclsSnmpStack->m_hSocket, szPacket, &iPacketSize, szIp, sizeof(szIp), &sPort ) )
			{
				SnmpRecvProcess( pclsSnmpStack, szPacket, iPacketSize, szIp, sPort );
			}
		}
	}

	gbRun = false;

	return 0;
}

bool StartSnmpUdpThread( CSnmpStack * pclsSnmpStack )
{
	gbStop = false;

	return StartThread( "SnmpUdpThread", SnmpUdpThread, pclsSnmpStack );
}

void StopSnmpUdpThread( )
{
	gbStop = true;
}

bool IsSnmpUdpThreadRun( )
{
	return gbRun;
}
