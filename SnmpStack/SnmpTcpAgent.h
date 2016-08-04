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

#ifndef _SNMP_TCP_AGENT_H_
#define _SNMP_TCP_AGENT_H_

#include "SnmpTcp.h"
#include "SnmpMessage.h"

class ISnmpTcpAgentCallBack
{
public:
	virtual ~ISnmpTcpAgentCallBack(){};

	virtual bool RecvRequest( CSnmpMessage * pclsRequest, CSnmpMessage * pclsResponse ) = 0;
	virtual void RecvTrap( CSnmpMessage * pclsRequest ) = 0;
};

class CSnmpTcpAgent
{
public:
	CSnmpTcpAgent();
	~CSnmpTcpAgent();

	bool Open( int iTcpPort, const char * pszCommunity, const char * pszUserName, const char * pszAuthPassWord, const char * pszPrivPassWord, ISnmpTcpAgentCallBack * pclsCallBack );
	void Close();

	bool		m_bStop;
	Socket	m_hSocket;

	std::string	m_strCommunity;
	std::string	m_strUserName;
	std::string	m_strAuthPassWord;
	std::string	m_strPrivPassWord;

	ISnmpTcpAgentCallBack * m_pclsCallBack;
};

#endif
