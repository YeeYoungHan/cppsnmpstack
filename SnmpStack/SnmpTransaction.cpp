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
#include "SnmpTransaction.h"
#include "TimeUtility.h"
#include "MemoryDebug.h"

CSnmpTransaction::CSnmpTransaction() : m_pclsRequest(NULL), m_iReSendCount(0), m_iUseCount(1)
{
	memset( &m_sttSendTime, 0, sizeof(m_sttSendTime) );
}

CSnmpTransaction::~CSnmpTransaction()
{
	if( m_pclsRequest )
	{
		delete m_pclsRequest;
		m_pclsRequest = NULL;
	}
}

/**
 * @ingroup SnmpStack
 * @brief timeout 되었는지 검사한다.
 * @param psttTime 현재 시간
 * @param iTimeout timeout milisecond
 * @returns timeout 되었으면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool CSnmpTransaction::IsTimeout( struct timeval * psttTime, int iTimeout )
{
	int iMiliSecond = DiffTimeval( &m_sttSendTime, psttTime );

	if( iMiliSecond >= iTimeout ) return true;

	return false;
}
