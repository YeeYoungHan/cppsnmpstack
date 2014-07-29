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
#include "SnmpUdp.h"
#include "AsnInt.h"
#include "AsnString.h"
#include "AsnOid.h"
#include "AsnNull.h"

int main( int argc, char * argv[] )
{
	if( argc != 3 )
	{
		printf( "[Usage] %s {ip} {mib}\n", argv[0] );
		return -1;
	}

	InitNetwork();

	Socket hSocket = UdpSocket();
	CSnmpMessage clsRequest;
	char szPacket[1500], szIp[16];
	int  iPacketLen;
	uint16_t	sPort;

	clsRequest.m_cVersion = SNMP_VERSION_2C;
	clsRequest.m_strCommunity = "public";
	clsRequest.m_cCommand = SNMP_CMD_GET;

	clsRequest.m_iRequestId = 32594;
	clsRequest.m_iErrorStatus = 0;
	clsRequest.m_iErrorIndex = 0;
	clsRequest.m_strOid = argv[2];
	clsRequest.m_pclsValue = new CAsnNull();

	iPacketLen = clsRequest.MakePacket( szPacket, sizeof(szPacket) );
	if( iPacketLen == -1 )
	{
		printf( "clsRequest.MakePacket error\n" );
		return 0;
	}

	if( UdpSend( hSocket, szPacket, iPacketLen, argv[1], 161 ) == false )
	{
		printf( "UdpSend\n" );
		return 0;
	}

	iPacketLen = sizeof(szPacket);
	if( UdpRecv( hSocket, (char *)szPacket, &iPacketLen, szIp, sizeof(szIp), &sPort ) == false )
	{
		printf( "UdpRecv\n" );
		return 0;
	}

	CSnmpMessage clsResponse;

	if( clsResponse.ParsePacket( szPacket, iPacketLen ) == -1 )
	{
		printf( "clsResponse.ParsePacket error\n" );
		return 0;
	}

	if( clsResponse.m_pclsValue )
	{
		switch( clsResponse.m_pclsValue->m_cType )
		{
		case ASN_TYPE_INT:
			{
				CAsnInt * pclsValue = (CAsnInt *)clsResponse.m_pclsValue;
				uint32_t iValue = pclsValue->m_iValue;
				printf( "[%u] (type=int)\n", iValue );
			}
			break;
		case ASN_TYPE_OCTET_STR:
			{
				CAsnString * pclsValue = (CAsnString *)clsResponse.m_pclsValue;
				std::string	strValue = pclsValue->m_strValue;
				printf( "[%s] (type=octet_string)\n", strValue.c_str() );
			}
			break;
		case ASN_TYPE_NO_SUCH_OBJECT:
			printf( "(type=no_such_object)\n" );
			break;
		}
	}

	return 0;
}
