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

#include "SnmpPlatformDefine.h"
#include "Log.h"
#include "MemoryDebug.h"

/**
 * @ingroup SnmpStack
 * @brief ��Ŷ�� HEX ���ڿ��� �α� ����Ѵ�.
 * @param pszPacket		��Ŷ
 * @param iPacketLen	��Ŷ ����
 */
void LogPacket( const char * pszPacket, int iPacketLen )
{
	char	szHex[3000];
	int		iLen = 0;

	for( int i = 0; i < iPacketLen; ++i )
	{
		if( ( iLen + 2 ) >= sizeof(szHex) ) break;

		iLen += snprintf( szHex + iLen, sizeof(szHex) - iLen, "%02x", (uint8_t)pszPacket[i] );
	}

	CLog::Print( LOG_DEBUG, "packet[%s]", szHex );
}
