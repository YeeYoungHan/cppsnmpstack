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

#include "TestGetSwitchPortIp.h"
#include "MemoryDebug.h"

int main( int argc, char * argv[] )
{
	if( argc != 2 )
	{
		printf( "[Usage] %s {ip}\n", argv[0] );
		return -1;
	}

#ifdef WIN32
	_CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF );
#endif

	std::string strDestIp = argv[1];

	InitNetwork();

	CSnmpSession clsSession;

	if( clsSession.Open() == false )
	{
		printf( "SnmpSession open error\n" );
		return 0;
	}

	clsSession.SetDestination( strDestIp.c_str(), 161 );
	clsSession.SetSnmpv2( "public" );

	// 스위치 허브의 포트 번호에 연결된 MAC 주소 리스트를 가져온다.
	GetPortMac( clsSession );

	// 스위치 허브에 저장된 MAC 주소에 대한 IP 주소를 가져온다.
	GetIpMac( clsSession );

	// 스위치 허브 포트별로 연결된 IP 주소를 출력한다.
	gclsPortMap.PrintAll();

	return 0;
}
