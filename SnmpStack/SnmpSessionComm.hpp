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

/**
 * @ingroup SnmpStack
 * @brief SNMPv2 이면 SNMP 요청 메시지를 전송한 후, 이에 대한 응답 메시지를 수신한다.
 *				SNMPv3 이면 SNMP 요청 메시지를 전송한 후, 이에 대한 응답 메시지 수신후, 다시 SNMP 요청 메시지를 전송한 후, 이에 대한 응답 메시지를 수신한다.
 * @param pclsRequest		SNMP 요청 메시지
 * @param pclsResponse	SNMP 응답 메시지
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CSnmpSession::SendRequest( CSnmpMessage * pclsRequest, CSnmpMessage * pclsResponse )
{
	if( SendRecv( pclsRequest, pclsResponse ) == false ) return false;

	if( pclsRequest->m_cMsgFlags == SNMP_MSG_FLAG_REPORT )
	{
		CSnmpMessage * pclsSecondRequest = CSnmpMessage::Create( pclsRequest );
		if( pclsSecondRequest )
		{
			pclsSecondRequest->m_iMsgId = ++m_iRequestId;
			pclsSecondRequest->m_iRequestId = pclsSecondRequest->m_iMsgId;
			pclsSecondRequest->m_strMsgAuthEngineId = pclsResponse->m_strMsgAuthEngineId;
			pclsSecondRequest->m_iMsgAuthEngineBoots = pclsResponse->m_iMsgAuthEngineBoots;
			pclsSecondRequest->m_iMsgAuthEngineTime = pclsResponse->m_iMsgAuthEngineTime;
			pclsSecondRequest->m_strMsgUserName = pclsSecondRequest->m_strUserId;
			pclsSecondRequest->m_strContextEngineId = pclsResponse->m_strContextEngineId;

			pclsSecondRequest->SetPrivParams( );
			pclsSecondRequest->SetAuthParams( );

			bool bRes = SendRecv( pclsSecondRequest, pclsResponse );
			delete pclsSecondRequest;

			if( bRes == false ) return false;

			if( pclsResponse->m_cMsgFlags & SNMP_MSG_FLAG_AUTH )
			{
				pclsResponse->m_strAuthPassWord = pclsRequest->m_strAuthPassWord;

				if( pclsResponse->CheckAuth() == false )
				{
					return false;
				}
			}

			if( pclsResponse->m_strEncryptedPdu.empty() == false )
			{
				pclsResponse->m_strPrivPassWord = pclsRequest->m_strPrivPassWord;
				pclsResponse->ParseEncryptedPdu( );
			}
		}
	}

	return true;
}

/**
 * @ingroup SnmpStack
 * @brief SNMP trap 과 같은 단방향 SNMP 메시지를 전송한다.
 * @param pclsRequest SNMP 메시지
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CSnmpSession::SendRequest( CSnmpMessage * pclsRequest )
{
	char szSend[SNMP_MAX_PACKET_SIZE];
	int iSendLen;

	if( m_hSocket == INVALID_SOCKET )
	{
		if( Open() == false ) return false;
	}

	if( m_strUserName.empty() == false )
	{
		static uint8_t szEngineId[] = { 0x80, 0x00, 0x00, 0x04, 0x80, 0x00 };

		pclsRequest->m_cVersion = SNMP_VERSION_3;
		pclsRequest->m_iMsgId = ++m_iRequestId;
		pclsRequest->m_iRequestId = pclsRequest->m_iMsgId;
		pclsRequest->m_strMsgAuthEngineId = m_strAuthEngineId;
		pclsRequest->m_strMsgUserName = m_strUserName;
		pclsRequest->m_strUserId = m_strUserName;
		pclsRequest->m_strAuthPassWord = m_strAuthPassWord;
		pclsRequest->m_strPrivPassWord = m_strPrivPassWord;

		pclsRequest->m_strContextEngineId.append( (char *)szEngineId, sizeof(szEngineId) );

		pclsRequest->SetPrivParams( );
		pclsRequest->SetAuthParams( );
	}
	else
	{
		pclsRequest->m_strCommunity = m_strCommunity;
		pclsRequest->m_iRequestId = ++m_iRequestId;
	}

	iSendLen = pclsRequest->MakePacket( szSend, sizeof(szSend) );
	if( iSendLen == -1 )
	{
		CLog::Print( LOG_ERROR, "%s MakePacket error", __FUNCTION__ );
		return false;
	}

	if( m_bTcp )
	{
		if( TcpSend( m_hSocket, szSend, iSendLen ) == false )
		{
			CLog::Print( LOG_ERROR, "%s TcpSend error", __FUNCTION__ );
			return false;
		}
	}
	else
	{
		if( UdpSend( m_hSocket, szSend, iSendLen, m_iIp, m_sPort ) == false )
		{
			CLog::Print( LOG_ERROR, "%s UdpSend error", __FUNCTION__ );
			return false;
		}
	}

	return true;
}

/**
 * @ingroup SnmpStack
 * @brief SNMP 요청 메시지를 전송한 후, 이에 대한 응답 메시지를 수신한다.
 * @param pclsRequest		SNMP 요청 메시지
 * @param pclsResponse	SNMP 응답 메시지
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CSnmpSession::SendRecv( CSnmpMessage * pclsRequest, CSnmpMessage * pclsResponse )
{
	int iSendLen, iRecvLen = 0, n;
	bool	bRes = false;

	if( m_hSocket == INVALID_SOCKET )
	{
		if( Open() == false ) return false;
	}

	if( m_bTcp )
	{
		char szSend[SNMP_MAX_PACKET_SIZE], szRecv[SNMP_MAX_PACKET_SIZE];
		int iWantRecvLen = 0;

		iSendLen = pclsRequest->MakePacket( szSend, sizeof(szSend) );
		if( iSendLen == -1 )
		{
			CLog::Print( LOG_ERROR, "%s MakePacket error", __FUNCTION__ );
			return false;
		}

		if( TcpSend( m_hSocket, szSend, iSendLen ) == false )
		{
			CLog::Print( LOG_ERROR, "%s TcpSend error", __FUNCTION__ );
			return false;
		}

		while( 1 )
		{
			n = TcpRecv( m_hSocket, szRecv + iRecvLen, sizeof(szRecv) - iRecvLen, m_iMiliTimeout / 1000 ); 
			if( n <= 0 )
			{
				CLog::Print( LOG_ERROR, "%s recv error(%d)", __FUNCTION__, GetError() );
				return false;
			}

			iRecvLen += n;
			if( iWantRecvLen <= 0 )
			{
				iWantRecvLen = pclsResponse->GetPacketLen( szRecv, iRecvLen );
			}

			if( iWantRecvLen > 0 )
			{
				if( iRecvLen == iWantRecvLen ) break;
			}
		}

		if( pclsResponse->ParsePacket( szRecv, iRecvLen ) > 0 )
		{
			if( m_bDebug )
			{
				LogPacket( szRecv, iRecvLen );
			}

			if( pclsRequest->m_iRequestId == pclsResponse->m_iRequestId ||
					( pclsRequest->m_iMsgId > 0 && pclsRequest->m_iMsgId == pclsResponse->m_iMsgId ) )
			{
				bRes = true;
			}
		}
	}
	else
	{
		char szSend[SNMP_MAX_PACKET_SIZE], szRecv[SNMP_MAX_PACKET_SIZE];
		struct pollfd arrPoll[1];
		uint32_t	iIp;
		uint16_t	sPort;

		iSendLen = pclsRequest->MakePacket( szSend, sizeof(szSend) );
		if( iSendLen == -1 )
		{
			CLog::Print( LOG_ERROR, "%s MakePacket error", __FUNCTION__ );
			return false;
		}

		for( int iSend = 0; iSend <= m_iReSendCount; ++iSend )
		{
			if( UdpSend( m_hSocket, szSend, iSendLen, m_iIp, m_sPort ) == false )
			{
				CLog::Print( LOG_ERROR, "%s UdpSend error", __FUNCTION__ );
				return false;
			}

			TcpSetPollIn( arrPoll[0], m_hSocket );

POLL_START:
			n = poll( arrPoll, 1, m_iMiliTimeout );
			if( n > 0 )
			{
				iRecvLen = sizeof(szRecv);
				if( UdpRecv( m_hSocket, szRecv, &iRecvLen, &iIp, &sPort ) )
				{
					if( pclsResponse->ParsePacket( szRecv, iRecvLen ) > 0 )
					{
						if( m_bDebug )
						{
							LogPacket( szRecv, iRecvLen );
						}

						if( pclsRequest->m_iRequestId == pclsResponse->m_iRequestId ||
								( pclsRequest->m_iMsgId > 0 && pclsRequest->m_iMsgId == pclsResponse->m_iMsgId ) )
						{
							bRes = true;
							break;
						}
					}

					// 원하는 응답이 수신되지 않으면 다시 수신 대기로 진입한다.
					goto POLL_START;
				}
			}
		}
	}

	return bRes;
}
