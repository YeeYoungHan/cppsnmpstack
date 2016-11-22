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

#ifndef _SNMP_MESSAGE_H_
#define _SNMP_MESSAGE_H_

#include "SnmpPlatformDefine.h"
#include "SnmpDefine.h"
#include "AsnString.h"
#include "SnmpOidValueList.h"

/**
 * @ingroup SnmpParser
 * @brief SNMP 패킷 생성/파서 클래스
 */
class CSnmpMessage
{
public:
	CSnmpMessage();
	~CSnmpMessage();

	void Clear();

	bool MakeGetRequest( const char * pszCommunity, uint32_t iRequestId, const char * pszOid );
	bool MakeGetNextRequest( const char * pszCommunity, uint32_t iRequestId, const char * pszOid );
	bool MakeTrapRequest( const char * pszTrapOid );

	bool MakeGetRequest( const char * pszUserName, const char * pszAuthPassWord, const char * pszPrivPassWord, uint32_t iRequestId, const char * pszOid );
	bool MakeGetNextRequest( const char * pszUserName, const char * pszAuthPassWord, const char * pszPrivPassWord, uint32_t iRequestId, const char * pszOid );

	const char * GetOid();

	bool AddOidValue( const char * pszOid, CAsnType * pclsValue );
	bool AddOidValue( const char * pszOid, int32_t iValue );
	bool AddOidValue( const char * pszOid, uint32_t iValue );
	bool AddOidValue( const char * pszOid, time_t iValue );
	bool AddOidValue( const char * pszOid, const char * pszValue );
	bool AddOidValueOid( const char * pszOid, const char * pszValue );
	bool AddOidValueCounter( const char * pszOid, uint32_t iValue );
	bool AddOidValueIpAddress( const char * pszOid, const char * pszIp );

	CSnmpMessage * CreateResponse();

	static CSnmpMessage * Create( CSnmpMessage * pclsMessage );

	// SnmpMessageParse.hpp
	int ParsePacket( const char * pszPacket, int iPacketLen );
	int GetPacketLen( const char * pszPacket, int iPacketLen );

	// SnmpMessageMake.hpp
	int MakePacket( char * pszPacket, int iPacketSize );
	bool MakePacket( );

	// SnmpMessagev3.hpp
	bool SetPrivParams( );
	bool SetAuthParams( );
	bool ParseEncryptedPdu( );
	bool CheckAuth( );

	// 
	uint8_t			m_cVersion;

	// SNMPv2
	std::string	m_strCommunity;

	// SNMP data
	uint8_t			m_cCommand;
	uint32_t		m_iRequestId;
	uint32_t		m_iErrorStatus;
	uint32_t		m_iErrorIndex;
	CSnmpOidValueList * m_pclsOidValueList;

	// SNMPv3
	uint32_t		m_iMsgId;
	uint32_t		m_iMsgMaxSize;
	uint8_t			m_cMsgFlags;
	uint32_t		m_iMsgSecurityModel;

	std::string	m_strMsgAuthEngineId;
	uint32_t		m_iMsgAuthEngineBoots;
	uint32_t		m_iMsgAuthEngineTime;
	std::string	m_strMsgUserName;
	std::string	m_strMsgAuthParams;
	std::string	m_strMsgPrivParams;

	std::string	m_strContextEngineId;
	std::string	m_strContextName;

	// SNMPv3 id & password
	std::string m_strUserId;
	std::string m_strAuthPassWord;
	std::string m_strPrivPassWord;
	std::string m_strReqOid;

	std::string m_strEncryptedPdu;

	// 네트워크 전송 패킷
	char				* m_pszPacket;
	int					m_iPacketLen;

	// 목적지 IP 주소 및 포트 번호
	std::string	m_strDestIp;
	int					m_iDestPort;

private:
	// SnmpMessageParse.hpp
	bool SetMsgGlobalData( CAsnComplex * pclsComplex );
	bool SetMsgSecurityParameters( CAsnComplex * pclsComplex );
	bool SetMsgData( CAsnComplex * pclsComplex );
	bool SetCommand( CAsnComplex * pclsComplex );

	// SnmpMessageMake.hpp
	CAsnComplex * CreateMsgGlobalData( );
	CAsnString * CreateMsgSecurityParameters( );
	CAsnComplex * CreateMsgData( );
	CAsnComplex * CreateCommand( );

	int MakePacketV2( char * pszPacket, int iPacketSize );
	int MakePacketV3( char * pszPacket, int iPacketSize );
};

#endif
