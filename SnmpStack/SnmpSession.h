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

#include "SnmpTcp.h"
#include "SnmpMessage.h"

/**
 * @ingroup SnmpStack
 * @brief 동기 방식으로 SNMP 통신하는 클래스
 */
class CSnmpSession
{
public:
	CSnmpSession();
	~CSnmpSession();

	bool SetDestination( const char * pszIp, int iPort = 161, bool bTcp = false, bool bTrapOnly = false );
	bool SetSnmpv2( const char * pszCommunity );
	bool SetSnmpv3( const char * pszUserName, const char * pszAuthPassWord, const char * pszPrivPassWord, const char * pszAuthEngineId = NULL );
	bool SetTimeout( int iMiliSecond );
	bool SetReSendCount( int iReSendCount );
	void SetDebug( bool bDebug );

	bool Open();
	void Close();
	bool Check();

	const char * GetIp();

	// SnmpSessionComm.hpp
	bool SendRequest( CSnmpMessage * pclsRequest, CSnmpMessage * pclsResponse );
	bool SendRequest( CSnmpMessage * pclsRequest );
	bool SendGetRequest( const char * pszOid, CAsnType ** ppclsAsnType );
	bool SendGetNextRequest( const char * pszOid, std::string ** ppstrResponseOid, CAsnType ** ppclsAsnType );

	bool SendGetRequest( const char * pszOid, std::string & strValue );
	bool SendGetRequest( const char * pszOid, uint32_t & iValue );

	bool SendGetNextRequest( const char * pszOid, std::string ** ppstrResponseOid, std::string & strValue );
	bool SendGetNextRequest( const char * pszOid, std::string ** ppstrResponseOid, uint32_t & iValue );

	bool				m_bStop;
	Socket			m_hSocket;

private:
	std::string	m_strIp;
	int					m_iPort;

	uint32_t		m_iIp;
	uint16_t		m_sPort;

	std::string	m_strCommunity;
	std::string	m_strUserName;
	std::string	m_strAuthPassWord;
	std::string	m_strPrivPassWord;
	std::string m_strAuthEngineId;

	int					m_iMiliTimeout;
	int					m_iReSendCount;

	uint32_t		m_iRequestId;
	CSnmpMessage	m_clsResponse;

	bool				m_bTcp;
	bool				m_bTrapOnly;
	bool				m_bDebug;

	bool SendRecv( CSnmpMessage * pclsRequest, CSnmpMessage * pclsResponse );
};

#endif
