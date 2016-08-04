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
 * @brief TCP 기반 SNMP 메시지 수신용 클라이언트 연결 쓰레드 생성 인자
 */
class CSnmpTcpAgentClientArg
{
public:
	CSnmpTcpAgent * m_pclsAgent;

	/** 클라이언트 연결 소켓 핸들 */
	Socket				m_hSocket;

	/** 클라이언트 IP 주소 */
	std::string		m_strIp;

	/** 클라이언트 포트 번호 */
	int						m_iPort;
};

/**
 * @ingroup SnmpStack
 * @brief TCP 기반 SNMP 메시지 수신 쓰레드
 * @param lpParameter CSnmpTcpAgentClientArg 객체의 포인터
 * @returns 0 을 리턴한다.
 */
THREAD_API SnmpTcpAgentClientThread( LPVOID lpParameter )
{
	CSnmpTcpAgentClientArg * pclsArg = (CSnmpTcpAgentClientArg *)lpParameter;
	char szPacket[SNMP_MAX_PACKET_SIZE], szSendPacket[SNMP_MAX_PACKET_SIZE];
	bool bCallCallBack;
	int n, iPacketLen = 0, iWantRecvLen = 0, iSendLen;
	pollfd sttPoll[1];
	CSnmpMessage clsRequest, clsResponse;

	CLog::Print( LOG_INFO, "SnmpTcpAgentClientThread is started - client(%s:%d)", pclsArg->m_strIp.c_str(), pclsArg->m_iPort );

	TcpSetPollIn( sttPoll[0], pclsArg->m_hSocket );

	while( pclsArg->m_pclsAgent->m_bStop == false )
	{
		n = poll( sttPoll, 1, 1000 );
		if( n <= 0 ) continue;

		n = recv( pclsArg->m_hSocket, szPacket + iPacketLen, sizeof(szPacket) - iPacketLen, 0 );
		if( n <= 0 ) break;

		iPacketLen += n;

		if( iWantRecvLen == 0 )
		{
			iWantRecvLen = clsRequest.GetPacketLen( szPacket, iPacketLen );
		}

		if( iWantRecvLen > 0 )
		{
			if( iPacketLen >= iWantRecvLen )
			{
				if( clsRequest.ParsePacket( szPacket, iPacketLen ) == -1 )
				{
					CLog::Print( LOG_ERROR, "%s ParsePacket error", __FUNCTION__ );
					break;
				}
				else
				{
					bCallCallBack = false;

					if( clsRequest.m_cVersion == SNMP_VERSION_3 )
					{
						if( pclsArg->m_pclsAgent->m_strUserName.empty() )
						{
							CLog::Print( LOG_ERROR, "%s SNMPv3 request - no user name", __FUNCTION__ );
						}
						else if( ( clsRequest.m_cMsgFlags & SNMP_MSG_FLAG_ENCRYPT ) && pclsArg->m_pclsAgent->m_strPrivPassWord.empty() )
						{
							CLog::Print( LOG_ERROR, "%s SNMPv3 encrypt request - no priv password", __FUNCTION__ );
						}
						else if( ( clsRequest.m_cMsgFlags & SNMP_MSG_FLAG_AUTH ) && pclsArg->m_pclsAgent->m_strAuthPassWord.empty() )
						{
							CLog::Print( LOG_ERROR, "%s SNMPv3 auth request - no auth password", __FUNCTION__ );
						}
						else if( strcmp( clsRequest.m_strMsgUserName.c_str(), pclsArg->m_pclsAgent->m_strUserName.c_str() ) )
						{
							CLog::Print( LOG_ERROR, "%s userId(%s) != userName(%s)", __FUNCTION__, clsRequest.m_strMsgUserName.c_str(), pclsArg->m_pclsAgent->m_strUserName.c_str() );
						}
						else if( clsRequest.m_iMsgAuthEngineBoots == 0 && clsRequest.m_strMsgAuthParams.empty() )
						{
							CSnmpMessage * pclsResponse = clsRequest.CreateResponse();
							if( pclsResponse )
							{
								time_t iTime;

								time( &iTime );

								static uint8_t szEngineId[] = { 0x80, 0x00, 0x00, 0x04, 0x80, 0x00 };

								pclsResponse->m_cMsgFlags = 0;
								pclsResponse->m_strMsgAuthEngineId.append( (char *)szEngineId, sizeof(szEngineId) );
								pclsResponse->m_strContextEngineId = pclsResponse->m_strMsgAuthEngineId;
								pclsResponse->m_iMsgMaxSize = SNMP_MAX_PACKET_SIZE;
								pclsResponse->m_iMsgAuthEngineBoots = (uint32_t)iTime;
								pclsResponse->m_iMsgAuthEngineTime = pclsResponse->m_iMsgAuthEngineBoots;
								pclsResponse->m_cCommand = SNMP_CMD_REPORT;

								pclsResponse->AddOidValueCounter( "1.3.6.1.6.3.15.1.1.4.0", 10 );

								iSendLen = pclsResponse->MakePacket( szSendPacket, sizeof(szSendPacket) );
								if( iSendLen != -1 )
								{
									TcpSend( pclsArg->m_hSocket, szSendPacket, iSendLen );
								}

								delete pclsResponse;
							}

							continue;
						}
						else
						{
							clsRequest.m_strUserId = pclsArg->m_pclsAgent->m_strUserName;
							clsRequest.m_strAuthPassWord = pclsArg->m_pclsAgent->m_strAuthPassWord;
							clsRequest.m_strPrivPassWord = pclsArg->m_pclsAgent->m_strPrivPassWord;

							if( clsRequest.m_strEncryptedPdu.empty() == false )
							{
								clsRequest.ParseEncryptedPdu( );
							}

							if( clsRequest.CheckAuth() == false )
							{
								CLog::Print( LOG_ERROR, "%s CheckAuth error", __FUNCTION__ );
							}
							else
							{
								bCallCallBack = true;
							}
						}
					}
					else if( strcmp( clsRequest.m_strCommunity.c_str(), pclsArg->m_pclsAgent->m_strCommunity.c_str() ) )
					{
						CLog::Print( LOG_ERROR, "%s community(%s) != setup community(%s)", __FUNCTION__, clsRequest.m_strCommunity.c_str(), pclsArg->m_pclsAgent->m_strCommunity.c_str() );
					}
					else
					{
						bCallCallBack = true;
					}

					if( bCallCallBack && pclsArg->m_pclsAgent->m_pclsCallBack )
					{
						if( clsRequest.m_cCommand == SNMP_CMD_TRAP )
						{
							pclsArg->m_pclsAgent->m_pclsCallBack->RecvTrap( &clsRequest );
						}
						else
						{
							bool bRes = false;
							CSnmpMessage * pclsResponse = clsRequest.CreateResponse();
							if( pclsResponse )
							{
								if( pclsArg->m_pclsAgent->m_pclsCallBack->RecvRequest( &clsRequest, pclsResponse ) )
								{
									if( pclsArg->m_pclsAgent->m_strUserName.empty() == false )
									{
										pclsResponse->m_strMsgUserName = pclsArg->m_pclsAgent->m_strUserName;
										pclsResponse->m_strAuthPassWord = pclsArg->m_pclsAgent->m_strAuthPassWord;
										pclsResponse->m_strPrivPassWord = pclsArg->m_pclsAgent->m_strPrivPassWord;

										if( clsRequest.m_cMsgFlags & SNMP_MSG_FLAG_ENCRYPT )
										{
											pclsResponse->SetPrivParams( );
										}

										if( clsRequest.m_cMsgFlags & SNMP_MSG_FLAG_AUTH )
										{
											pclsResponse->SetAuthParams( );
										}
									}

									iSendLen = pclsResponse->MakePacket( szSendPacket, sizeof(szSendPacket) );
									if( iSendLen == -1 )
									{
										TcpSend( pclsArg->m_hSocket, szSendPacket, iSendLen );
									}

									bRes = true;
								}

								delete pclsResponse;

								if( bRes == false ) break;
							}
						}

						clsRequest.Clear();
					}
				}

				if( iPacketLen > iWantRecvLen )
				{
					memmove( szPacket, szPacket + iWantRecvLen, iPacketLen - iWantRecvLen );
					iPacketLen = iPacketLen - iWantRecvLen;
				}
				else
				{
					iPacketLen = 0;
				}

				iWantRecvLen = 0;
			}
		}
	}

	closesocket( pclsArg->m_hSocket );
	CLog::Print( LOG_INFO, "SnmpTcpAgentClientThread is terminated - client(%s:%d)", pclsArg->m_strIp.c_str(), pclsArg->m_iPort );

	delete pclsArg;

	return 0;
}

/**
 * @ingroup SnmpStack
 * @brief SNMP 클라이언트의 TCP 연결 처리 쓰레드
 * @param lpParameter CSnmpTcpAgent 객체
 * @returns 0 을 리턴한다.
 */
THREAD_API SnmpTcpAgentListenThread( LPVOID lpParameter )
{
	CSnmpTcpAgent * pclsAgent = (CSnmpTcpAgent *)lpParameter;
	pollfd sttPoll[1];
	char	szIp[52];
	int		iPort, n;

	TcpSetPollIn( sttPoll[0], pclsAgent->m_hSocket );

	CLog::Print( LOG_INFO, "SnmpTcpAgentListenThread is started" );

	while( pclsAgent->m_bStop == false )
	{
		n = poll( sttPoll, 1, 1000 );
		if( n <= 0 ) continue;
		if( pclsAgent->m_bStop ) break;

		Socket hSocket = TcpAccept( pclsAgent->m_hSocket, szIp, sizeof(szIp), &iPort );
		if( hSocket != INVALID_SOCKET )
		{
			CSnmpTcpAgentClientArg * pclsArg = new CSnmpTcpAgentClientArg();
			if( pclsArg == NULL )
			{
				CLog::Print( LOG_ERROR, "%s new error(%d)", __FUNCTION__, GetError() );
				closesocket( hSocket );
			}
			else
			{
				pclsArg->m_pclsAgent = pclsAgent;
				pclsArg->m_hSocket = hSocket;
				pclsArg->m_strIp = szIp;
				pclsArg->m_iPort = iPort;

				if( StartThread( "SnmpTcpAgentClientThread", SnmpTcpAgentClientThread, pclsArg ) == false )
				{
					closesocket( hSocket );
					delete pclsArg;

					CLog::Print( LOG_ERROR, "%s SnmpTcpAgentClientThread thread start error(%d)", __FUNCTION__, GetError() );
				}
			}
		}
	}

	closesocket( pclsAgent->m_hSocket );

	CLog::Print( LOG_INFO, "SnmpTcpAgentListenThread is terminated" );

	return 0;
}

