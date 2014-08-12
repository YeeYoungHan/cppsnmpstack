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

bool CSnmpMessage::SetMsgGlobalData( CAsnComplex * pclsComplex )
{
	ASN_TYPE_LIST::iterator	itList;
	uint8_t cType = 0;

	for( itList = pclsComplex->m_clsList.begin(); itList != pclsComplex->m_clsList.end(); ++itList )
	{
		++cType;

		if( cType == 1 )
		{
			if( (*itList)->m_cType == ASN_TYPE_INT )
			{
				CAsnInt * pclsValue = (CAsnInt *)(*itList);
				m_iMsgId = pclsValue->m_iValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s msgId type(%d) is not int", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
		else if( cType == 2 )
		{
			if( (*itList)->m_cType == ASN_TYPE_INT )
			{
				CAsnInt * pclsValue = (CAsnInt *)(*itList);
				m_iMsgMaxSize = pclsValue->m_iValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s msgMaxSize type(%d) is not int", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
		else if( cType == 3 )
		{
			if( (*itList)->m_cType == ASN_TYPE_OCTET_STR )
			{
				CAsnString * pclsValue = (CAsnString *)(*itList);
				m_cMsgFlags = pclsValue->m_strValue.at(0);
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s msgFlags type(%d) is not octet string", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
		else if( cType == 4 )
		{
			if( (*itList)->m_cType == ASN_TYPE_INT )
			{
				CAsnInt * pclsValue = (CAsnInt *)(*itList);
				m_iMsgSecurityModel = pclsValue->m_iValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s msgSecurityModel type(%d) is not int", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
	}

	return true;
}

bool CSnmpMessage::SetMsgSecurityParameters( CAsnComplex * pclsComplex )
{
	ASN_TYPE_LIST::iterator	itList;
	uint8_t cType = 0;

	for( itList = pclsComplex->m_clsList.begin(); itList != pclsComplex->m_clsList.end(); ++itList )
	{
		++cType;

		if( cType == 1 )
		{
			if( (*itList)->m_cType == ASN_TYPE_OCTET_STR )
			{
				CAsnString * pclsValue = (CAsnString *)(*itList);
				m_strMsgAuthEngineId = pclsValue->m_strValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s msgAuthoritativeEngineID type(%d) is not octet string", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
		else if( cType == 2 )
		{
			if( (*itList)->m_cType == ASN_TYPE_INT )
			{
				CAsnInt * pclsValue = (CAsnInt *)(*itList);
				m_iMsgAuthEngineBoots = pclsValue->m_iValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s msgAuthoritativeEngineBoots type(%d) is not int", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
		else if( cType == 3 )
		{
			if( (*itList)->m_cType == ASN_TYPE_INT )
			{
				CAsnInt * pclsValue = (CAsnInt *)(*itList);
				m_iMsgAuthEngineTime = pclsValue->m_iValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s msgAuthoritativeEngineTime type(%d) is not int", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
		else if( cType == 4 )
		{
			if( (*itList)->m_cType == ASN_TYPE_OCTET_STR )
			{
				CAsnString * pclsValue = (CAsnString *)(*itList);
				m_strMsgUserName = pclsValue->m_strValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s msgUserName type(%d) is not octet string", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
		else if( cType == 5 )
		{
			if( (*itList)->m_cType == ASN_TYPE_OCTET_STR )
			{
				CAsnString * pclsValue = (CAsnString *)(*itList);
				m_strMsgAuthParams = pclsValue->m_strValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s msgAuthenticationParameters type(%d) is not octet string", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
		else if( cType == 6 )
		{
			if( (*itList)->m_cType == ASN_TYPE_OCTET_STR )
			{
				CAsnString * pclsValue = (CAsnString *)(*itList);
				m_strMsgPrivParams = pclsValue->m_strValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s msgPrivacyParameters type(%d) is not octet string", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
	}

	return true;
}

bool CSnmpMessage::SetMsgData( CAsnComplex * pclsComplex )
{
	ASN_TYPE_LIST::iterator	itList;
	uint8_t cType = 0;

	for( itList = pclsComplex->m_clsList.begin(); itList != pclsComplex->m_clsList.end(); ++itList )
	{
		++cType;

		if( cType == 1 )
		{
			if( (*itList)->m_cType == ASN_TYPE_OCTET_STR )
			{
				CAsnString * pclsValue = (CAsnString *)(*itList);
				m_strContextEngineId = pclsValue->m_strValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s contextEngineId type(%d) is not int", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
		else if( cType == 2 )
		{
			if( (*itList)->m_cType == ASN_TYPE_OCTET_STR )
			{
				CAsnString * pclsValue = (CAsnString *)(*itList);
				m_strContextName = pclsValue->m_strValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s contextName type(%d) is not int", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
		else if( cType == 3 )
		{
			if( SetCommand( (CAsnComplex *)(*itList) ) == false )
			{
				return false;
			}
		}
	}

	return true;
}

bool CSnmpMessage::SetCommand( CAsnComplex * pclsComplex )
{
	m_cCommand = pclsComplex->m_cType;
	ASN_TYPE_LIST::iterator	itList;
	uint8_t cType = 0;

	for( itList = pclsComplex->m_clsList.begin(); itList != pclsComplex->m_clsList.end(); ++itList )
	{
		++cType;

		if( cType == 1 )
		{
			if( (*itList)->m_cType == ASN_TYPE_INT )
			{
				CAsnInt * pclsValue = (CAsnInt *)(*itList);
				m_iRequestId = pclsValue->m_iValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s request-id type(%d) is not int", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
		else if( cType == 2 )
		{
			if( (*itList)->m_cType == ASN_TYPE_INT )
			{
				CAsnInt * pclsValue = (CAsnInt *)(*itList);
				m_iErrorStatus = pclsValue->m_iValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s error-status type(%d) is not int", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
		else if( cType == 3 )
		{
			if( (*itList)->m_cType == ASN_TYPE_INT )
			{
				CAsnInt * pclsValue = (CAsnInt *)(*itList);
				m_iErrorIndex = pclsValue->m_iValue;
			}
			else
			{
				CLog::Print( LOG_ERROR, "%s error-index type(%d) is not int", __FUNCTION__, (*itList)->m_cType );
				return false;
			}
		}
		else if( cType == 4 )
		{
			CAsnComplex * pclsBodyFrame = (CAsnComplex *)(*itList);
			CAsnComplex * pclsBody = (CAsnComplex *)(*pclsBodyFrame->m_clsList.begin());
			ASN_TYPE_LIST::iterator	itBody;
			cType = 0;

			for( itBody = pclsBody->m_clsList.begin(); itBody != pclsBody->m_clsList.end(); ++itBody )
			{
				++cType;

				if( cType == 1 )
				{
					CAsnOid * pclsValue = (CAsnOid *)(*itBody);
					m_strOid = pclsValue->m_strValue;
				}
				else if( cType == 2 )
				{
					m_pclsValue = (*itBody)->Copy();
				}
			}
		}
	}

	return true;
}
