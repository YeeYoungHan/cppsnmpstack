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
#include "TestSnmpParser.h"
#include <stdio.h>
#include "MemoryDebug.h"

int main( int argc, char * argv[] )
{
#ifdef WIN32
	_CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF );
#endif

	if( argc == 2 )
	{
		SendAsnInt();
		return 0;
	}

	if( TestAsnLong() == false ) goto FUNC_ERROR;
	if( TestAsnInt() == false ) goto FUNC_ERROR;
	if( TestAsnOid() == false ) goto FUNC_ERROR;
	if( TestAsnType() == false ) goto FUNC_ERROR;
	if( TestParseSnmpv3Packet() == false ) goto FUNC_ERROR;
	if( TestAuthenticationParameters() == false ) goto FUNC_ERROR;
	if( TestEncryptedPdu() == false ) goto FUNC_ERROR;

	printf( "All Test is O.K!!!!\n" );
	return 0;

FUNC_ERROR:
	printf( "Error\n" );

	return -1;
}
