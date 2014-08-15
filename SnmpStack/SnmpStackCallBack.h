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

#ifndef _SNMP_STACK_CALLBACK_H_
#define _SNMP_STACK_CALLBACK_H_

#include "SnmpMessage.h"

/**
 * @ingroup SnmpStack
 * @brief SNMP stack callback 인터페이스
 */
class ISnmpStackCallBack
{
public:
	virtual ~ISnmpStackCallBack(){};

	/**
	 * @ingroup SnmpStack
	 * @brief SNMP 응답 메시지 수신 이벤트 callback
	 * @param pclsRequest		SNMP 요청 메시지
	 * @param pclsResponse	SNMP 응답 메시지. SNMP 응답 메시지가 NULL 이면 timeout 된 것이다.
	 */
	virtual void RecvResponse( CSnmpMessage * pclsRequest, CSnmpMessage * pclsResponse ) = 0;
};

#endif
