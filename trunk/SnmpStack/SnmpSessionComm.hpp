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
 * @brief SNMPv2 �̸� SNMP ��û �޽����� ������ ��, �̿� ���� ���� �޽����� �����Ѵ�.
 *				SNMPv3 �̸� SNMP ��û �޽����� ������ ��, �̿� ���� ���� �޽��� ������, �ٽ� SNMP ��û �޽����� ������ ��, �̿� ���� ���� �޽����� �����Ѵ�.
 * @param pclsRequest		SNMP ��û �޽���
 * @param pclsResponse	SNMP ���� �޽���
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
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
			pclsSecondRequest->m_strOid = pclsSecondRequest->m_strReqOid;

			pclsSecondRequest->m_strMsgAuthEngineId = pclsResponse->m_strMsgAuthEngineId;
			pclsSecondRequest->m_iMsgAuthEngineBoots = pclsResponse->m_iMsgAuthEngineBoots;
			pclsSecondRequest->m_iMsgAuthEngineTime = pclsResponse->m_iMsgAuthEngineTime;
			pclsSecondRequest->m_strMsgUserName = pclsSecondRequest->m_strUserId;

			pclsSecondRequest->m_strContextEngineId = pclsResponse->m_strContextEngineId;
			pclsSecondRequest->m_pclsValue = new CAsnNull();

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
 * @brief SNMP ��û �޽����� ������ ��, �̿� ���� ���� �޽����� �����Ѵ�.
 * @param pclsRequest		SNMP ��û �޽���
 * @param pclsResponse	SNMP ���� �޽���
 * @returns �����ϸ� true �� �����ϰ� �����ϸ� false �� �����Ѵ�.
 */
bool CSnmpSession::SendRecv( CSnmpMessage * pclsRequest, CSnmpMessage * pclsResponse )
{
	char szSend[SNMP_MAX_PACKET_SIZE], szRecv[SNMP_MAX_PACKET_SIZE];
	int iSendLen, iRecvLen, n;
	struct pollfd arrPoll[1];
	uint32_t	iIp;
	uint16_t	sPort;
	bool	bRes = false;

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

		n = poll( arrPoll, 1, m_iMiliTimeout );
		if( n > 0 )
		{
			iRecvLen = sizeof(szRecv);
			if( UdpRecv( m_hSocket, szRecv, &iRecvLen, &iIp, &sPort ) )
			{
				if( pclsResponse->ParsePacket( szRecv, iRecvLen ) > 0 )
				{
					if( pclsRequest->m_iRequestId == pclsResponse->m_iRequestId ||
							( pclsRequest->m_iMsgId > 0 && pclsRequest->m_iMsgId == pclsResponse->m_iMsgId ) )
					{
						bRes = true;
						break;
					}
				}
			}
		}
	}

	return bRes;
}
