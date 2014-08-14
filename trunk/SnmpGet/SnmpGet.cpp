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

#ifndef USE_BLOCKING_METHOD
CSnmpMutexSignal gclsMutex;
#endif

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

	const char * pszDestIp = argv[1];
	const char * pszMib = argv[2];
	const char * pszUserId = NULL;
	const char * pszAuthPassWord = NULL;
	CSnmpMessage clsRequest, clsResponse;

	if( argc == 5 )
	{
		pszUserId = argv[3];
		pszAuthPassWord = argv[4];
	}

	InitNetwork();

	CSnmpStack clsStack;
	CSnmpStackSetup clsSetup;
	CCallBack clsCallBack;
	uint32_t iRequestId;
	struct timeval sttTime;

	gettimeofday( &sttTime, NULL );
	srand( ( sttTime.tv_sec << 4 ) + sttTime.tv_usec );

	iRequestId = rand();

	if( clsStack.Start( clsSetup, &clsCallBack ) == false )
	{
		printf( "clsStack.Start() error\n" );
		return 0;
	}

	CSnmpMessage * pclsRequest = new CSnmpMessage();
	if( pclsRequest )
	{
		if( pszUserId )
		{
			if( pclsRequest->MakeGetRequest( pszUserId, pszAuthPassWord, NULL, iRequestId, pszMib ) )
			{
				if( clsStack.SendRequest( pszDestIp, 161, pclsRequest ) )
				{
					gclsMutex.wait();
				}
			}
		}
		else
		{
			if( pclsRequest->MakeGetRequest( "public", iRequestId, pszMib ) )
			{
				if( clsStack.SendRequest( pszDestIp, 161, pclsRequest ) )
				{
					gclsMutex.wait();
				}
			}
		}
	}

	clsStack.Stop();

	return 0;
}
