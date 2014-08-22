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

#ifndef _SNMP_SESSION_H_
#define _SNMP_SESSION_H_

#include "SnmpUdp.h"
#include "SnmpMessage.h"

class CSnmpSession
{
public:
	CSnmpSession();
	~CSnmpSession();

	bool SetDestination( const char * pszIp, int iPort = 161 );
	bool SetSnmpv2( const char * pszCommunity );
	bool SetSnmpv3( const char * pszUserName, const char * pszAuthPassWord, const char * pszPrivPassWord );
	bool SetTimeout( int iMiliSecond );
	bool SetReSendCount( int iReSendCount );

	bool Open();
	bool Close();

	bool SendRequest( CSnmpMessage * pclsRequest, CSnmpMessage * pclsResponse );
	bool SendGetRequest( const char * pszOid, CAsnType ** ppclsAsnType );

private:
	std::string	m_strIp;
	int					m_iPort;

	uint32_t		m_iIp;
	uint16_t		m_sPort;

	std::string	m_strCommunity;
	std::string	m_strUserName;
	std::string	m_strAuthPassWord;
	std::string	m_strPrivPassWord;

	int					m_iMiliTimeout;
	int					m_iReSendCount;

	uint32_t		m_iRequestId;
	CSnmpMessage	m_clsResponse;

	Socket			m_hSocket;

	bool SendRecv( CSnmpMessage * pclsRequest, CSnmpMessage * pclsResponse );
};

#endif
