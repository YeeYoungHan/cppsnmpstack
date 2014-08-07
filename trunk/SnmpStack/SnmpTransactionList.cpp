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
#include "TimeUtility.h"
#include "SnmpStack.h"
#include "AutoRelease.h"
#include "MemoryDebug.h"

CSnmpTransactionList::CSnmpTransactionList()
{
}

CSnmpTransactionList::~CSnmpTransactionList()
{
}

void CSnmpTransactionList::SetSnmpStack( CSnmpStack * pclsStack )
{
	m_pclsStack = pclsStack;
}

bool CSnmpTransactionList::Insert( CSnmpMessage * pclsRequest )
{
	bool bRes = false;
	SNMP_TRANSACTION_MAP::iterator	itMap;

	m_clsMutex.acquire();
	itMap = m_clsMap.find( pclsRequest->m_iRequestId );
	if( itMap == m_clsMap.end() )
	{
		CSnmpTransaction * pclsTransaction = new CSnmpTransaction();
		if( pclsTransaction )
		{
			pclsTransaction->m_pclsRequest = pclsRequest;
			gettimeofday( &pclsTransaction->m_sttSendTime, NULL );

			m_clsMap.insert( SNMP_TRANSACTION_MAP::value_type( pclsRequest->m_iRequestId, pclsTransaction ) );
			
			bRes = true;
		}
	}
	m_clsMutex.release();

	return bRes;
}

bool CSnmpTransactionList::Delete( CSnmpMessage * pclsRequest )
{
	return Delete( pclsRequest->m_iRequestId );
}

bool CSnmpTransactionList::Select( uint32_t iRequestId, CSnmpTransaction ** ppclsTransaction )
{
	bool bRes = false;
	SNMP_TRANSACTION_MAP::iterator	itMap;

	m_clsMutex.acquire();
	itMap = m_clsMap.find( iRequestId );
	if( itMap != m_clsMap.end() )
	{
		++itMap->second->m_iUseCount;
		*ppclsTransaction = itMap->second;
		bRes = true;
	}
	m_clsMutex.release();

	return bRes;
}

bool CSnmpTransactionList::Delete( uint32_t iRequestId )
{
	bool bRes = false;
	SNMP_TRANSACTION_MAP::iterator	itMap;

	m_clsMutex.acquire();
	itMap = m_clsMap.find( iRequestId );
	if( itMap != m_clsMap.end() )
	{
		--itMap->second->m_iUseCount;
		if( itMap->second->m_iUseCount == 0 )
		{
			delete itMap->second;
			m_clsMap.erase( itMap );
		}
		bRes = true;
	}
	m_clsMutex.release();

	return bRes;
}

void CSnmpTransactionList::Release( CSnmpTransaction * pclsTransaction )
{
	m_clsMutex.acquire();
	--pclsTransaction->m_iUseCount;
	if( pclsTransaction->m_iUseCount == 0 )
	{
		SNMP_TRANSACTION_MAP::iterator	itMap;
		
		itMap = m_clsMap.find( pclsTransaction->m_pclsRequest->m_iRequestId );
		if( itMap != m_clsMap.end() )
		{
			delete itMap->second;
			m_clsMap.erase( itMap );
		}
	}
	m_clsMutex.release();
}

typedef std::list< int > REQUEST_ID_LIST;

void CSnmpTransactionList::Execute( struct timeval * psttTime )
{
	SNMP_TRANSACTION_MAP::iterator	itMap;
	REQUEST_ID_LIST clsIdList;
	REQUEST_ID_LIST::iterator	itList;
	bool bDelete = false;

	m_clsMutex.acquire();
	for( itMap = m_clsMap.begin(); itMap != m_clsMap.end(); ++itMap )
	{
		if( itMap->second->IsTimeout( psttTime, m_pclsStack->m_clsSetup.m_iReSendPeriod ) == false ) continue;

		if( itMap->second->m_iReSendCount >= m_pclsStack->m_clsSetup.m_iReSendMaxCount )
		{
			clsIdList.push_back( itMap->first );
			continue;
		}

		UdpSend( m_pclsStack->m_hSocket, itMap->second->m_pclsRequest->m_pszPacket, itMap->second->m_pclsRequest->m_iPacketLen
			, itMap->second->m_pclsRequest->m_strDestIp.c_str(), itMap->second->m_pclsRequest->m_iDestPort );
		++itMap->second->m_iReSendCount;
	}
	m_clsMutex.release();

	for( itList = clsIdList.begin(); itList != clsIdList.end(); ++itList )
	{
		bDelete = false;

		{
			CAutoRelease< CSnmpTransactionList, CSnmpTransaction > clsData( *this );

			if( Select( *itList, &clsData.m_pclsData ) )
			{
				m_pclsStack->m_pclsCallBack->RecvResponse( clsData.m_pclsData->m_pclsRequest, NULL );
				bDelete = true;
			}
		}

		if( bDelete )
		{
			Delete( *itList );
		}
	}
}

void CSnmpTransactionList::DeleteAll( )
{
	SNMP_TRANSACTION_MAP::iterator	itMap, itNext;

	m_clsMutex.acquire();
	for( itMap = m_clsMap.begin(); itMap != m_clsMap.end(); ++itMap )
	{
LOOP_START:
		--itMap->second->m_iUseCount;
		if( itMap->second->m_iUseCount == 0 )
		{
			itNext = itMap;
			++itNext;

			delete itMap->second;
			m_clsMap.erase( itMap );

			if( itNext == m_clsMap.end() ) break;
			itMap = itNext;
			goto LOOP_START;
		}
	}
	m_clsMutex.release();
}
