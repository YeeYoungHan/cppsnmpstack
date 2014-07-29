#include "AsnComplex.h"
#include "AsnInt.h"
#include "AsnString.h"
#include "AsnOid.h"
#include "AsnNull.h"
#include "Log.h"

CAsnComplex::CAsnComplex()
{
}

CAsnComplex::~CAsnComplex()
{
	Clear();
}

int CAsnComplex::ParsePacket( const char * pszPacket, int iPacketLen )
{
	int			iPos = 0, n;
	uint8_t	cLength;
	CAsnType	* pclsValue;

	m_cType = pszPacket[iPos++];
	cLength = pszPacket[iPos++];

	for( uint8_t i = 0; i < cLength; )
	{
		switch( pszPacket[iPos] )
		{
		case ASN_TYPE_INT:
			pclsValue = new CAsnInt();
			break;
		case ASN_TYPE_OCTET_STR:
			pclsValue = new CAsnString();
			break;
		case ASN_TYPE_OID:
			pclsValue = new CAsnOid();
			break;
		case ASN_TYPE_NULL:
		case ASN_TYPE_NO_SUCH_OBJECT:
			pclsValue = new CAsnNull();
			break;
		case ASN_TYPE_COMPLEX:
			pclsValue = new CAsnComplex();
			break;
		default:
			CLog::Print( LOG_ERROR, "%s type(%u) is not defined", __FUNCTION__, pszPacket[iPos] );
			break;
		}

		if( pclsValue == NULL ) return -1;
		n = pclsValue->ParsePacket( pszPacket + iPos, iPacketLen - iPos );
		if( n == -1 ) 
		{
			delete pclsValue;
			return -1;
		}

		m_clsList.push_back( pclsValue );
	}

	return 0;
}

int CAsnComplex::MakePacket( char * pszPacket, int iPacketSize )
{
	int iPos = 0, n;
	ASN_TYPE_LIST::iterator	itList;
	
	pszPacket[iPos++] = ASN_TYPE_COMPLEX;
	++iPos;

	for( itList = m_clsList.begin(); itList != m_clsList.end(); ++itList )
	{
		n = (*itList)->MakePacket( pszPacket + iPos, iPacketSize - iPos );
		if( n == -1 ) return -1;
		iPos += n;
	}

	pszPacket[1] = iPos - 1;

	return 0;
}

void CAsnComplex::Clear()
{
	ASN_TYPE_LIST::iterator	itList;

	for( itList = m_clsList.begin(); itList != m_clsList.end(); ++itList )
	{
		delete *itList;
	}

	m_clsList.clear();
}
