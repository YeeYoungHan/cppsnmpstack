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

#include "TestSnmpParser.h"
#include "AsnInt.h"
#include "AsnLong.h"
#include "SnmpMessage.h"
#include "SipUdp.h"

static void SendInt( Socket hSocket, uint32_t iValue )
{
	CSnmpMessage clsMessage;
	CAsnInt	clsInt( ASN_TYPE_COUNTER_32 );
	char szPacket[1500];
	int iPacketLen;

	clsInt.m_iValue = iValue;

	clsMessage.MakeGetRequest( "public", 1, "1.3.6.1.2.1" );
	clsMessage.AddOidValue( "1.3.6.1.2.1", 0 );

	iPacketLen = clsMessage.MakePacket( szPacket, sizeof(szPacket) );

	UdpSend( hSocket, szPacket, iPacketLen, "192.168.0.1", 161 );
}

static void SendLong( Socket hSocket, uint64_t iValue )
{
	CSnmpMessage clsMessage;
	CAsnLong	clsLong( ASN_TYPE_COUNTER_64 );
	char szPacket[1500];
	int iPacketLen;

	clsLong.m_iValue = iValue;

	clsMessage.MakeGetRequest( "public", 1, "1.3.6.1.2.1" );

	iPacketLen = clsMessage.MakePacket( szPacket, sizeof(szPacket) );

	UdpSend( hSocket, szPacket, iPacketLen, "192.168.0.1", 161 );
}

bool SendAsnInt( )
{
	InitNetwork();

	Socket hSocket = UdpSocket();

/*
	SendInt( hSocket, 0x7F );
	SendInt( hSocket, 0x80 );
	SendInt( hSocket, 0x81 );

	SendInt( hSocket, 0x7FFF );
	SendInt( hSocket, 0x8000 );
	SendInt( hSocket, 0x8001 );

	SendInt( hSocket, 0x7FFFFF );
	SendInt( hSocket, 0x800000 );
	SendInt( hSocket, 0x800001 );

	SendInt( hSocket, 0x7FFFFFFF );
	SendInt( hSocket, 0x80000000 );
	SendInt( hSocket, 0x80000001 );

	SendInt( hSocket, 0xFFFFFFFF );
*/

	SendLong( hSocket, 0x7F );
	SendLong( hSocket, 0x80 );
	SendLong( hSocket, 0x81 );

	SendLong( hSocket, 0x7FFF );
	SendLong( hSocket, 0x8000 );
	SendLong( hSocket, 0x8001 );

	SendLong( hSocket, 0x7FFFFF );
	SendLong( hSocket, 0x800000 );
	SendLong( hSocket, 0x800001 );

	SendLong( hSocket, 0x7FFFFFFF );
	SendLong( hSocket, 0x80000000 );
	SendLong( hSocket, 0x80000001 );

	SendLong( hSocket, 0x7FFFFFFFFF );
	SendLong( hSocket, 0x8000000000 );
	SendLong( hSocket, 0x8000000001 );

	SendLong( hSocket, 0x7FFFFFFFFFFF );
	SendLong( hSocket, 0x800000000000 );
	SendLong( hSocket, 0x800000000001 );

	SendLong( hSocket, 0x7FFFFFFFFFFFFF );
	SendLong( hSocket, 0x80000000000000 );
	SendLong( hSocket, 0x80000000000001 );

	SendLong( hSocket, 0x7FFFFFFFFFFFFFFF );
	SendLong( hSocket, 0x8000000000000000 );
	SendLong( hSocket, 0x8000000000000001 );

	SendLong( hSocket, 0xFFFFFFFFFFFFFFFF );

	closesocket( hSocket );

	return true;
}
