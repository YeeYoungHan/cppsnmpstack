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
#include "SnmpThread.h"
#include "ServerUtility.h"
#include "TimeUtility.h"
#include "MemoryDebug.h"

static bool gbStop = false;
static bool gbRun = false;

/**
 * @ingroup SnmpStack
 * @brief SNMP stack 쓰레드
 * @param lpParameter CSnmpStack 객체
 * @returns 0 을 리턴한다.
 */
THREAD_API SnmpStackThread( LPVOID lpParameter )
{
	CSnmpStack * pclsSnmpStack = (CSnmpStack *)lpParameter;
	struct timeval sttTime;

	gbRun = true;

	while( gbStop == false )
	{
		gettimeofday( &sttTime, NULL );
		pclsSnmpStack->m_clsTransactionList.Execute( &sttTime );

		MiliSleep( 100 );
	}

	gbRun = false;

	return 0;
}

/**
 * @ingroup SnmpStack
 * @brief SNMP stack 쓰레드를 시작한다.
 * @param pclsSnmpStack CSnmpStack 객체
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool StartSnmpStackThread( CSnmpStack * pclsSnmpStack )
{
	return StartThread( "SnmpStackThread", SnmpStackThread, pclsSnmpStack );
}

/**
 * @ingroup SnmpStack
 * @brief SNMP stack 쓰레드를 종료한다.
 */
void StopSnmpStackThread( )
{
	gbStop = true;
}

/**
 * @ingroup SnmpStack
 * @brief SNMP stack 쓰레드가 실행 중인지 검사한다.
 * @returns SNMP stack 쓰레드가 실행 중이면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool IsSnmpStackThreadRun( )
{
	return gbRun;
}
