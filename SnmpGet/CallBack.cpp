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

#include "SipPlatformDefine.h"
#include "CallBack.h"
#include "SnmpGet.h"
#include "MemoryDebug.h"

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
	}
	else if( pclsResponse->m_pclsOidValueList )
	{
		SNMP_OID_VALUE_LIST::iterator itOL;

		for( itOL = pclsResponse->m_pclsOidValueList->m_clsList.begin(); itOL != pclsResponse->m_pclsOidValueList->m_clsList.end(); ++itOL )
		{
			uint32_t iValue;
			std::string strValue;

			if( (*itOL)->m_pclsValue->GetInt( iValue ) )
			{
				printf( "[%u] (type=int)\n", iValue );
			}
			else if( (*itOL)->m_pclsValue->GetString( strValue ) )
			{
				printf( "[%s] (type=string)\n", strValue.c_str() );
			}
			else
			{
				printf( "(type=no_such_object)\n" );
			}
		}
	}

#ifndef USE_SNMP_SESSION
	gclsMutex.signal();
#endif
}
