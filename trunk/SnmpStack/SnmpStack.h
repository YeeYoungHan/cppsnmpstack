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

#ifndef _SNMP_STACK_H_
#define _SNMP_STACK_H_

/**
 * @defgroup SnmpStack SnmpStack
 * SNMP �޽��� ����/���� ���̺귯��
 */

#include "SnmpStackSetup.h"
#include "SnmpTransactionList.h"
#include "SnmpUdp.h"
#include "SnmpStackCallBack.h"

/**
 * @ingroup SnmpStack
 * @brief SNMP �޽��� ����/���� Ŭ����
 */
class CSnmpStack
{
public:
	CSnmpStack();
	~CSnmpStack();

	bool Start( CSnmpStackSetup & clsSetup, ISnmpStackCallBack * pclsCallBack );
	bool Stop( );

	bool SendRequest( const char * pszIp, int iPort, CSnmpMessage * pclsRequest );

	static bool SendRequest( const char * pszIp, int iPort, CSnmpMessage & clsRequest, CSnmpMessage & clsResponse, int iTimeout = 2 );

	CSnmpStackSetup m_clsSetup;
	Socket					m_hSocket;

	ISnmpStackCallBack	* m_pclsCallBack;

	CSnmpTransactionList	m_clsTransactionList;
};

#endif
