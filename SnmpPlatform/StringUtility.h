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

#ifndef _STRING_UTILITY_H_
#define _STRING_UTILITY_H_

#include "SnmpPlatformDefine.h"
#include <string>
#include <list>
#include <vector>

typedef std::list< std::string > STRING_LIST;
typedef std::vector< std::string > STRING_VECTOR;

void ReplaceString( std::string & strCallId, const char * pszBefore, const char * pszAfter );
void ReplaceStringFirst( std::string & strCallId, const char * pszBefore, const char * pszAfter );
bool SearchValue( std::string & strText, const char * pszKey, char cSep, std::string & strValue );
bool SearchValue( std::string & strText, const char * pszKey, char cSep, int & iValue );
bool SearchString( std::string & strText, const char * pszValue );
bool SearchString( std::string & strText, char cValue );
void LeftTrimString( std::string & strText );
void RightTrimString( std::string & strText );
void TrimString( std::string & strText );
char ** ParseCommandString( const char * pszCommand );
void FreeCommandArg( char ** ppszArg );
bool IsStringAllDigit( std::string & strText );

#ifdef WIN32
bool Utf8ToAnsi( const char * pszUtf8, std::string & strOutput );
bool AnsiToUtf8( const char * pszAnsi, std::string & strOutput );
#endif

uint32_t GetUInt32( const char * pszText );
uint64_t GetUInt64( const char * pszText );

int GetInt( const char * pszText, int TextLen );

bool HexToString( const char * pszInput, std::string & strOutput );
void StringAppend( std::string & strBuf, const char * fmt, ... );

#endif
