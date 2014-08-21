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
#include "SnmpUdp.h"
#include "SnmpStack.h"
#include "CallBack.h"
#include "TimeUtility.h"
#include "MemoryDebug.h"

CSnmpMutexSignal gclsMutex;
CSnmpStack gclsStack;
std::string gstrDestIp;
std::string gstrOid;
std::string gstrUserId;
std::string gstrAuthPassWord;
uint32_t giRequestId;

int main( int argc, char * argv[] )
{
	if( argc != 3 && argc != 5 )
	{
		printf( "[Usage] %s {ip} {mib} {user id} {auth password}\n", argv[0] );
		return -1;
	}

#ifdef WIN32
	_CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF );
#endif

	gstrDestIp = argv[1];
	gstrOid = argv[2];

	if( argc == 5 )
	{
		gstrUserId = argv[3];
		gstrAuthPassWord = argv[4];
	}

	InitNetwork();

	CSnmpStackSetup clsSetup;
	CCallBack clsCallBack;

	if( gclsStack.Start( clsSetup, &clsCallBack ) == false )
	{
		printf( "clsStack.Start() error\n" );
	}

	struct timeval sttTime;

	gettimeofday( &sttTime, NULL );
	srand( ( sttTime.tv_sec << 4 ) + sttTime.tv_usec );

	giRequestId = rand();

	CSnmpMessage * pclsRequest = new CSnmpMessage();
	if( pclsRequest )
	{
		if( gstrUserId.empty() == false )
		{
			if( pclsRequest->MakeGetNextRequest( gstrUserId.c_str(), gstrAuthPassWord.c_str(), NULL, giRequestId, gstrOid.c_str() ) )
			{
				if( gclsStack.SendRequest( gstrDestIp.c_str(), 161, pclsRequest ) )
				{
					gclsMutex.wait();
				}
			}
		}
		else
		{
			if( pclsRequest->MakeGetNextRequest( "public", giRequestId, gstrOid.c_str() ) )
			{
				if( gclsStack.SendRequest( gstrDestIp.c_str(), 161, pclsRequest ) )
				{
					gclsMutex.wait();
				}
			}
		}
	}

	gclsStack.Stop();

	return 0;
}