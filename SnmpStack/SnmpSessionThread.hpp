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
 * @brief 
 * @param lpParameter 
 * @returns 
 */
THREAD_API SnmpSessionThread( LPVOID lpParameter )
{
	CSnmpSession * pclsSession = (CSnmpSession *)lpParameter;
	pollfd sttPoll[1];
	int n;
	char szPacket[1480];

	CLog::Print( LOG_INFO, "SnmpSessionThread is started" );

	TcpSetPollIn( sttPoll[0], pclsSession->m_hSocket );

	while( pclsSession->m_bStop == false )
	{
		n = poll( sttPoll, 1, 1000 );
		if( n <= 0 ) continue;

		n = recv( pclsSession->m_hSocket, szPacket, sizeof(szPacket), 0 );
		if( n <= 0 ) break;
	}

	CLog::Print( LOG_INFO, "SnmpSessionThread is terminated" );

	pclsSession->Close();

	return 0;
}
