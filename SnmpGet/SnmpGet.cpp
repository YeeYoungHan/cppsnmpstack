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

#include "SnmpUdp.h"
#include "SnmpStack.h"
#include "CallBack.h"
#include "MemoryDebug.h"

#ifndef USE_BLOCKING_METHOD
CSnmpMutexSignal gclsMutex;
#endif

int main( int argc, char * argv[] )
{
	if( argc != 3 )
	{
		printf( "[Usage] %s {ip} {mib}\n", argv[0] );
		return -1;
	}

#ifdef WIN32
	_CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF );
#endif

	const char * pszDestIp = argv[1];
	const char * pszMib = argv[2];
	CSnmpMessage clsRequest, clsResponse;

	InitNetwork();

#ifdef USE_BLOCKING_METHOD
	clsRequest.MakeGetRequest( "public", 32594, pszMib );

	if( CSnmpStack::SendRequest( pszDestIp, 161, clsRequest, clsResponse ) == false )
	{
		printf( "CSnmpStack::SendRequest error\n" );
		return 0;
	}

	if( clsResponse.m_pclsValue )
	{
		uint32_t iValue;
		std::string strValue;

		if( clsResponse.m_pclsValue->GetInt( iValue ) )
		{
			printf( "[%u] (type=int)\n", iValue );
		}
		else if( clsResponse.m_pclsValue->GetString( strValue ) )
		{
			printf( "[%s] (type=string)\n", strValue.c_str() );
		}
		else
		{
			printf( "(type=no_such_object)\n" );
		}
	}
#else
	CSnmpStack clsStack;
	CSnmpStackSetup clsSetup;
	CCallBack clsCallBack;

	if( clsStack.Start( clsSetup, &clsCallBack ) == false )
	{
		printf( "clsStack.Start() error\n" );
	}

	CSnmpMessage * pclsRequest = new CSnmpMessage();
	if( pclsRequest )
	{
		if( pclsRequest->MakeGetRequest( "public", 32594, pszMib ) )
		{
			if( clsStack.SendRequest( pszDestIp, 161, pclsRequest ) )
			{
				gclsMutex.wait();
			}
		}
	}

	clsStack.Stop();
#endif

	return 0;
}
