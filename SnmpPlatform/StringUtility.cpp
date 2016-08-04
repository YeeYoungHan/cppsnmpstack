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
#include "StringUtility.h"
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "Log.h"
#include "MemoryDebug.h"

/**
 * @ingroup SipPlatform
 * @brief 문자열에 포함된 문자열을 수정한다.
 * @param strCallId	문자열
 * @param pszBefore 수정 대상 문자열
 * @param pszAfter	수정 대상 문자열을 수정할 문자열
 */
void ReplaceString( std::string & strCallId, const char * pszBefore, const char * pszAfter )
{
	size_t iPos = strCallId.find( pszBefore );
	size_t iBeforeLen = strlen( pszBefore );
	size_t iAfterLen = strlen( pszAfter );

	while( iPos < std::string::npos )
	{
		strCallId.replace( iPos, iBeforeLen, pszAfter );
		iPos = strCallId.find( pszBefore, iPos + iAfterLen );
	}
}

/**
 * @ingroup SipPlatform
 * @brief 문자열에 포함된 맴 처음 문자열을 수정한다.
 * @param strCallId	문자열
 * @param pszBefore 수정 대상 문자열
 * @param pszAfter	수정 대상 문자열을 수정할 문자열
 */
void ReplaceStringFirst( std::string & strCallId, const char * pszBefore, const char * pszAfter )
{
	size_t iPos = strCallId.find( pszBefore );
	size_t iBeforeLen = strlen( pszBefore );

	if( iPos < std::string::npos )
	{
		strCallId.replace( iPos, iBeforeLen, pszAfter );
	}
}

/**
 * @ingroup SipPlatform
 * @brief 문자열에 포함된 키의 값을 추출한다. 
 *				"app=36;msg=36;hotline=46;presence=36; broadcast=46" 문자열에서 
 *				app 의 값을 추출하고 싶으면 pszKey 에 "app=" 를 입력하고 cSep 에 ';' 를 입력하면 된다.
 * @param strText		문자열
 * @param pszKey		키
 * @param cSep			구분자
 * @param strValue	키의 값을 저장할 변수
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool SearchValue( std::string & strText, const char * pszKey, char cSep, std::string & strValue )
{
	strValue.clear();

	size_t iPos = strText.find( pszKey );
	if( iPos < std::string::npos )
	{
		size_t iKeyLen = strlen( pszKey );
		size_t iEndPos = strText.find( cSep, iPos + iKeyLen );

		if( iEndPos < std::string::npos )
		{
			strValue = strText.substr( iPos + iKeyLen, iEndPos - ( iPos + iKeyLen ) );
		}
		else
		{
			strValue = strText.substr( iPos + iKeyLen );
		}

		return true;
	}

	return false;
}

/**
 * @ingroup SipPlatform
 * @brief 문자열에 포함된 키의 값을 추출한다. 
 *				"app=36;msg=36;hotline=46;presence=36; broadcast=46" 문자열에서 
 *				app 의 값을 추출하고 싶으면 pszKey 에 "app=" 를 입력하고 cSep 에 ';' 를 입력하면 된다.
 * @param strText		문자열
 * @param pszKey		키
 * @param cSep			구분자
 * @param iValue		키의 값을 저장할 변수
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool SearchValue( std::string & strText, const char * pszKey, char cSep, int & iValue )
{
	std::string	strValue;

	if( SearchValue( strText, pszKey, cSep, strValue ) )
	{
		iValue = atoi( strValue.c_str() );

		return true;
	}

	return false;
}

/**
 * @ingroup SipPlatform
 * @brief 문자열에 입력된 값이 존재하는지 검사한다.
 * @param strText		문자열
 * @param pszValue	검색 문자열
 * @returns 문자열에 입력된 값이 존재하면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool SearchString( std::string & strText, const char * pszValue )
{
	size_t iPos = strText.find( pszValue );
	if( iPos < std::string::npos )
	{
		return true;
	}

	return false;
}

/**
 * @ingroup SipPlatform
 * @brief 문자열에 입력된 값이 존재하는지 검사한다.
 * @param strText		문자열
 * @param cValue		검색 문자
 * @returns 문자열에 입력된 값이 존재하면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool SearchString( std::string & strText, char cValue )
{
	size_t iPos = strText.find( cValue );
	if( iPos < std::string::npos )
	{
		return true;
	}

	return false;
}

/**
 * @ingroup SipPlatform
 * @brief 문자열의 왼쪽 공백을 제거한다.
 * @param strText 문자열
 */
void LeftTrimString( std::string & strText )
{
	int iIndex;
	int iLen = (int)strText.length();
	for( iIndex = 0; iIndex < iLen; ++iIndex )
	{
		char c = strText.at(iIndex);
		if( c == ' ' || c == '\t' ) continue;

		strText.erase( 0, iIndex );
		break;
	}

	if( iIndex == iLen )
	{
		strText.clear();
	}
}

/**
 * @ingroup SipPlatform
 * @brief 문자열의 오른쪽 공백을 제거한다.
 * @param strText 문자열
 */
void RightTrimString( std::string & strText )
{
	int iIndex;
	int iLen = (int)strText.length();
	for( iIndex = iLen - 1; iIndex >= 0; --iIndex )
	{
		char c = strText.at(iIndex);
		if( c == ' ' || c == '\t' ) continue;

		if( iIndex != ( iLen - 1 ) )
		{
			strText.erase( iIndex + 1 );
		}

		break;
	}

	if( iIndex == -1 )
	{
		strText.clear();
	}
}

/**
 * @ingroup SipPlatform
 * @brief 문자열의 왼쪽, 오른쪽 공백을 제거한다.
 * @param strText 문자열
 */
void TrimString( std::string & strText )
{
	LeftTrimString( strText );
	RightTrimString( strText );
}

/**
 * @ingroup SipPlatform
 * @brief 프로그램 실행 문자열을 파싱하여서 문자열 배열을 생성한다.
 * @param pszCommand 프로그램 실행 문자열
 * @returns 성공하면 문자열 배열을 리턴하고 실패하면 NULL 을 리턴한다.
 */
char ** ParseCommandString( const char * pszCommand )
{
	char ** ppszArg = NULL;
	STRING_LIST clsList;
	int iStartPos = 0;
	bool bDoubleQuotes = false, bSingleQuotes = false, bStart = false;

	for( int i = 0; pszCommand[i]; ++i )
	{
		if( bStart == false )
		{
			if( isspace( pszCommand[i] ) == 0 )
			{
				bDoubleQuotes = false;
				bSingleQuotes = false;
				bStart = true;
				iStartPos = i;

				if( pszCommand[i] == '"' )
				{
					bDoubleQuotes = true;
					iStartPos = i + 1;
				}
				else if( pszCommand[i] == '\'' )
				{
					bSingleQuotes = true;
					iStartPos = i + 1;
				}
			}
		}
		else
		{
			if( bDoubleQuotes )
			{
				if( pszCommand[i] == '"' )
				{
					std::string strArg;

					strArg.append( pszCommand + iStartPos, i - iStartPos );
					clsList.push_back( strArg );
					bStart = false;
				}
			}
			else if( bSingleQuotes )
			{
				if( pszCommand[i] == '\'' )
				{
					std::string strArg;

					strArg.append( pszCommand + iStartPos, i - iStartPos );
					clsList.push_back( strArg );
					bStart = false;
				}
			}
			else
			{
				if( isspace( pszCommand[i] ) )
				{
					std::string strArg;

					strArg.append( pszCommand + iStartPos, i - iStartPos );
					clsList.push_back( strArg );
					bStart = false;
				}
			}
		}
	}

	if( bStart )
	{
		std::string strArg;

		strArg.append( pszCommand + iStartPos );
		clsList.push_back( strArg );
	}

	int iCount = (int)clsList.size();

	if( iCount > 0 )
	{
		++iCount;
		ppszArg = (char **)malloc( sizeof(char *) * iCount );
		if( ppszArg )
		{
			memset( ppszArg, 0, sizeof(char *) * iCount );

			STRING_LIST::iterator	itList;
			int iPos = 0;

			for( itList = clsList.begin(); itList != clsList.end(); ++itList )
			{
				ppszArg[iPos] = (char *)malloc( itList->length() + 1 );
				if( ppszArg[iPos] == NULL ) break;

				sprintf( ppszArg[iPos], "%s", itList->c_str() );
				++iPos;
			}
		}
	}

	return ppszArg;
}

/**
 * @ingroup SipPlatform
 * @brief ParseCommandString 로 생성한 배열을 삭제한다.
 * @param ppszArg ParseCommandString 로 생성한 배열
 */
void FreeCommandArg( char ** ppszArg )
{
	if( ppszArg )
	{
		for( int i = 0; ppszArg[i]; ++i )
		{
			free( ppszArg[i] );
		}

		free( ppszArg );
	}
}

/**
 * @ingroup SipPlatform
 * @brief 문자열이 모두 0 ~ 9 문자로만 구성되어 있는가?
 * @param strText 문자열
 * @returns 문자열이 모두 0 ~ 9 문자로만 구성되어 있으면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool IsStringAllDigit( std::string & strText )
{
	int iLen = (int)strText.length();
	const char * pszText = strText.c_str();

	for( int i = 0; i < iLen; ++i )
	{
		if( pszText[i] < '0' || pszText[i] > '9' ) return false;
	}

	return true;
}

#ifdef WIN32

#include <windows.h>

/**
 * @ingroup SipPlatform
 * @brief UTF8 문자열을 ANSI 문자열로 변환한다.
 * @param pszUtf8		UTF8 문자열 (input)
 * @param strOutput ANSI 문자열 (output)
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool Utf8ToAnsi( const char * pszUtf8, std::string & strOutput )
{
	BSTR    strWide = NULL;
	char*   pszAnsi = NULL;
	int     iLength;
	int			iUtf8Length = (int)strlen(pszUtf8) + 1;
	
	iLength = MultiByteToWideChar( CP_UTF8, 0, pszUtf8, iUtf8Length, NULL, NULL );
	if( iLength == 0 )
	{
		CLog::Print( LOG_ERROR, "%s MultiByteToWideChar error(%d)", __FUNCTION__, GetLastError() );
		return false;
	}

	strWide = SysAllocStringLen( NULL, iLength );
	if( strWide == NULL )
	{
		CLog::Print( LOG_ERROR, "%s SysAllocStringLen error(%d)", __FUNCTION__, GetLastError() );
		return false;
	}

	MultiByteToWideChar( CP_UTF8, 0, pszUtf8, iUtf8Length, strWide, iLength );

	iLength = WideCharToMultiByte( CP_ACP, 0, strWide, -1, NULL, 0, NULL, NULL );
	if( iLength == 0 )
	{
		SysFreeString( strWide );
		CLog::Print( LOG_ERROR, "%s WideCharToMultiByte error(%d)", __FUNCTION__, GetLastError() );
		return false;
	}

	pszAnsi = new char[iLength];
	if( pszAnsi == NULL )
	{
		SysFreeString( strWide );
		CLog::Print( LOG_ERROR, "%s new error(%d)", __FUNCTION__, GetLastError() );
		return false;
	}

	WideCharToMultiByte( CP_ACP, 0, strWide, -1, pszAnsi, iLength, NULL, NULL );
	strOutput = pszAnsi;
	
	SysFreeString( strWide );
	delete [] pszAnsi;
	
	return true;
}

/**
 * @ingroup SipPlatform
 * @brief ANSI 문자열을 UTF-8 문자열로 변환한다. EUC-KR 문자열을 UTF-8 문자열로 변환한다.
 * @param pszAnsi		ANSI 문자열
 * @param strOutput UTF-8 문자열을 저장할 변수
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool AnsiToUtf8( const char * pszAnsi, std::string & strOutput )
{
	BSTR    strWide = NULL;
	char*   pszUtf8 = NULL;
	int     iLength;
	int			iAnsiLength = (int)strlen(pszAnsi) + 1;
	
	iLength = MultiByteToWideChar( CP_ACP, 0, pszAnsi, iAnsiLength, NULL, NULL );
	if( iLength == 0 )
	{
		CLog::Print( LOG_ERROR, "%s MultiByteToWideChar error(%d)", __FUNCTION__, GetLastError() );
		return false;
	}

	strWide = SysAllocStringLen( NULL, iLength );
	if( strWide == NULL )
	{
		CLog::Print( LOG_ERROR, "%s SysAllocStringLen error(%d)", __FUNCTION__, GetLastError() );
		return false;
	}

	MultiByteToWideChar( CP_ACP, 0, pszAnsi, iAnsiLength, strWide, iLength );

	iLength = WideCharToMultiByte( CP_UTF8, 0, strWide, -1, NULL, 0, NULL, NULL );
	if( iLength == 0 )
	{
		SysFreeString( strWide );
		CLog::Print( LOG_ERROR, "%s WideCharToMultiByte error(%d)", __FUNCTION__, GetLastError() );
		return false;
	}

	pszUtf8 = new char[iLength];
	if( pszUtf8 == NULL )
	{
		SysFreeString( strWide );
		CLog::Print( LOG_ERROR, "%s new error(%d)", __FUNCTION__, GetLastError() );
		return false;
	}

	WideCharToMultiByte( CP_UTF8, 0, strWide, -1, pszUtf8, iLength, NULL, NULL );
	strOutput = pszUtf8;
	
	SysFreeString( strWide );
	delete [] pszUtf8;
	
	return true;
}

#endif

/**
 * @ingroup SipPlatform
 * @brief 문자열을 unsigned int 로 변환한다.
 * @param pszText 문자열
 * @returns unsigned int 를 리턴한다.
 */
uint32_t GetUInt32( const char * pszText )
{
	if( pszText == NULL ) return 0;

	int iRadix = 10;

	// 16진수 처리
	if( pszText[0] == '0' && pszText[1] == 'x' )
	{
		iRadix = 16;
		pszText += 2;
	}

	return strtoul( pszText, NULL, iRadix );
}

/**
 * @ingroup SipPlatform
 * @brief 문자열을 unsigned long long 으로 변환한다.
 * @param pszText 문자열
 * @returns unsigned long long 을 리턴한다.
 */
uint64_t GetUInt64( const char * pszText )
{
	if( pszText == NULL ) return 0;

	int iRadix = 10;

	// 16진수 처리
	if( pszText[0] == '0' && pszText[1] == 'x' )
	{
		iRadix = 16;
		pszText += 2;
	}

#ifdef WIN32
	return _strtoui64( pszText, NULL, iRadix );
#else
	return strtoull( pszText, NULL, iRadix );
#endif
}

/**
 * @ingroup SipPlatform
 * @brief 지정될 길이만큼의 문자열을 숫자로 변환한다.
 * @param pszText		숫자 문자열
 * @param iTextLen	문자열 길이
 * @returns 성공하면 원하는 숫자가 리턴되고 실패하면 0 이 리턴된다.
 */
int GetInt( const char * pszText, int iTextLen )
{
	char szNum[11];

	if( iTextLen > 10 || iTextLen <= 0 ) return 0;

	memcpy( szNum, pszText, iTextLen );
	szNum[iTextLen] = '\0';

	return atoi( szNum );
}

static inline char HexToChar( char c )
{
  if( c >= '0' && c <= '9' )
  {
		return c - '0';
  }
  else if( c >= 'a' && c <= 'f' )
  {
		return c + 10 - 'a';
  }
  else if( c >= 'A' && c <= 'F' )
  {
		return c + 10 - 'A';
  }

  return -1;
}

/**
 * @ingroup SipPlatform
 * @brief HEX 만 저장된 문자열을 숫자로 변환한 문자열을 생성한다.
 * @param pszInput	HEX 만 저장된 문자열
 * @param strOutput 숫자로 변환된 문자열 저장용 변수
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool HexToString( const char * pszInput, std::string & strOutput )
{
	int iLen = (int)strlen( pszInput );
	int iValue;

	strOutput.clear();

	if( iLen >= 2 )
	{
		if( pszInput[0] == '0' && pszInput[1] == 'x' )
		{
			pszInput += 2;
			iLen -= 2;
		}
	}

	if( iLen == 0 || iLen % 2 == 1 ) return false;

	for( int i = 0; i < iLen; i += 2 )
	{
		sscanf( pszInput + i, "%02x", &iValue );
		strOutput.push_back( (char)iValue );
	}

	return true;
}

/**
 * @ingroup SipPlatform
 * @brief 문자열에 입력한 문자열을 추가한다.
 * @param strBuf	[out] 문자열
 * @param fmt			[in] 포맷 문자열
 * @param ...			[in] fmt 포맷에 입력할 인자들
 */
void StringAppend( std::string & strBuf, const char * fmt, ... )
{
	va_list		ap;
	char		szBuf[1024];

	va_start( ap, fmt );
	vsnprintf( szBuf, sizeof(szBuf)-1, fmt, ap );
	va_end( ap );

	strBuf.append( szBuf );
}
