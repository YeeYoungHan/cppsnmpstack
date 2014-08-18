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
#include "CallBack.h"
#include "SnmpStack.h"
#include "MemoryDebug.h"

extern CSnmpMutexSignal gclsMutex;
extern CSnmpStack gclsStack;
extern std::string gstrDestIp;
extern std::string gstrOid;
extern uint32_t giRequestId;

CCallBack::CCallBack()
{
}

CCallBack::~CCallBack()
{
}

void CCallBack::RecvResponse( CSnmpMessage * pclsRequest, CSnmpMessage * pclsResponse )
{
	if( pclsResponse == NULL )
	{
		printf( "timeout\n" );
		gclsMutex.signal();
		return;
	}
	
	if( pclsResponse->m_pclsValue == NULL )
	{
		printf( "respose error\n" );
		gclsMutex.signal();
		return;
	}

	uint32_t iValue;
	std::string strValue;

	printf( "[%s] ", pclsRequest->m_strOid.c_str() );

	if( pclsResponse->m_pclsValue->GetInt( iValue ) )
	{
		printf( "[%u] (type=int)\n", iValue );
	}
	else if( pclsResponse->m_pclsValue->GetString( strValue ) )
	{
		printf( "[%s] (type=string)\n", strValue.c_str() );
	}
	else
	{
		printf( "(type=no_such_object)\n" );
	}

	if( strncmp( gstrOid.c_str(), pclsResponse->m_strOid.c_str(), gstrOid.length() ) )
	{
		gclsMutex.signal();
		return;
	}

	giRequestId += 2;

	CSnmpMessage * pclsMessage = new CSnmpMessage();
	if( pclsRequest )
	{
		if( pclsMessage->MakeGetNextRequest( "public", giRequestId, pclsResponse->m_strOid.c_str() ) )
		{
			if( gclsStack.SendRequest( gstrDestIp.c_str(), 161, pclsMessage ) )
			{
			}
		}
	}
}
