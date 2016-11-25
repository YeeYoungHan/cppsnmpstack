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

#ifndef _SNMP_AGENT_H_
#define _SNMP_AGENT_H_

#include "SipUdp.h"
#include "SnmpMessage.h"

class CSnmpAgent
{
public:
	CSnmpAgent();
	~CSnmpAgent();

	bool Open( int iUdpPort, const char * pszCommunity, const char * pszUserName, const char * pszAuthPassWord, const char * pszPrivPassWord );
	void Close();

	bool RecvRequest( CSnmpMessage * pclsRequest, int iTimeout );
	bool SendResponse( CSnmpMessage * pclsResponse );

private:
	Socket	m_hSocket;

	uint32_t	m_iDestIp;
	uint16_t	m_sDestPort;

	std::string	m_strCommunity;
	std::string	m_strUserName;
	std::string	m_strAuthPassWord;
	std::string	m_strPrivPassWord;

	uint8_t			m_cMsgFlags;
};

#endif
