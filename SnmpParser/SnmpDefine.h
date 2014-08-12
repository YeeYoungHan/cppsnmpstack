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

#ifndef _SNMP_DEFINE_H_
#define _SNMP_DEFINE_H_

#define SNMP_VERSION_1	0
#define SNMP_VERSION_2C	1
#define SNMP_VERSION_3	3

#define SNMP_CMD_GET			0xA0
#define SNMP_CMD_GET_NEXT	0xA1
#define SNMP_CMD_RESPONSE	0xA2

#define SNMP_SECURITY_MODEL_USM	3

#define SNMP_MAX_PACKET_SIZE	1480

/**
 * @defgroup SnmpParser SnmpParser
 * SNMP 메시지 생성/파서 라이브러리
 */

#endif
