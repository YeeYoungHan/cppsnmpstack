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

#ifndef _SNMP_TRANSACTION_LIST_H_
#define _SNMP_TRANSACTION_LIST_H_

#include "SnmpTransaction.h"
#include "SipMutex.h"
#include <map>

class CSnmpStack;

// key = m_iRequestId
typedef std::map< uint32_t, CSnmpTransaction * > SNMP_TRANSACTION_MAP;

/**
 * @ingroup SnmpStack
 * @brief 
 */
class CSnmpTransactionList
{
public:
	CSnmpTransactionList();
	~CSnmpTransactionList();

	void SetSnmpStack( CSnmpStack * pclsStack );

	bool Insert( CSnmpMessage * pclsRequest );
	bool Delete( CSnmpMessage * pclsRequest );

	bool Select( uint32_t iRequestId, CSnmpTransaction ** ppclsTransaction );
	bool Delete( uint32_t iRequestId );
	void Release( CSnmpTransaction * pclsTransaction );

	void Execute( struct timeval * psttTime );
	void DeleteAll( );

private:
	SNMP_TRANSACTION_MAP	m_clsMap;
	CSipMutex						m_clsMutex;
	CSnmpStack						* m_pclsStack;
};

#endif
