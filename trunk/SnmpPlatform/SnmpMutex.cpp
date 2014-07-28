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

#include "SnmpMutex.h"
#include "MemoryDebug.h"

/**
 * @ingroup SipPlatform
 * @brief ������
 */
CSnmpMutex::CSnmpMutex( )
{
#ifdef WIN32
	InitializeCriticalSection( &m_sttMutex );
#else
	pthread_mutex_init( &m_sttMutex, NULL );
#endif
}

/**
 * @ingroup SipPlatform
 * @brief �Ҹ���
 */
CSnmpMutex::~CSnmpMutex()
{
#ifdef WIN32
	DeleteCriticalSection( &m_sttMutex );
#else
	pthread_mutex_destroy( &m_sttMutex );
#endif
}

/**
 * @ingroup SipPlatform
 * @brief mutex lock �Ѵ�.
 * @return true �� �����Ѵ�.
 */
bool CSnmpMutex::acquire()
{
#ifdef WIN32
	EnterCriticalSection( &m_sttMutex );
#else
	if( pthread_mutex_lock( &m_sttMutex ) != 0 )
	{
		return false;
	}
#endif

	return true;
}

/**
 * @ingroup SipPlatform
 * @brief mutex unlock �Ѵ�.
 * @return true �� �����Ѵ�.
 */
bool CSnmpMutex::release()
{
#ifdef WIN32
	LeaveCriticalSection( &m_sttMutex );
#else
	if( pthread_mutex_unlock( &m_sttMutex ) != 0 )
	{
		return false;
	}
#endif

	return true;
}

/**
 * @ingroup SipPlatform
 * @brief ������
 */
CSnmpMutexSignal::CSnmpMutexSignal()
{
#ifdef WIN32
	m_sttCond = CreateEvent( NULL, FALSE, FALSE, NULL );
#else
	pthread_cond_init( &m_sttCond, NULL );
#endif
}

/**
 * @ingroup SipPlatform
 * @brief �Ҹ���
 */
CSnmpMutexSignal::~CSnmpMutexSignal()
{
#ifdef WIN32
	if( m_sttCond )
	{
		CloseHandle( m_sttCond );
	}
#else
	pthread_cond_destroy( &m_sttCond );
#endif
}

/**
 * @ingroup SipPlatform
 * @brief signal �Ǵ� broadcast �޼ҵ尡 ȣ��� ������ ����Ѵ�.
 * @return true �� �����Ѵ�.
 */
bool CSnmpMutexSignal::wait()
{
#ifdef WIN32
	if( m_sttCond == NULL )
	{
		Sleep(20);
		return true;
	}

	if( WaitForSingleObject( m_sttCond, INFINITE ) == WAIT_FAILED )
	{
		return false;
	}

	return true;
#else
	int n = pthread_cond_wait( &m_sttCond, &m_sttMutex );
	if( n != 0 )
	{
		return false;
	}
#endif

	return true;
}

/**
 * @ingroup SipPlatform
 * @brief signal �Ǵ� broadcast �޼ҵ尡 ȣ��� ������ ����ϴ� ������ 1���� ��� ������Ų��.
 * @return true �� �����Ѵ�.
 */
bool CSnmpMutexSignal::signal()
{
#ifdef WIN32
	if( m_sttCond )
	{
		SetEvent( m_sttCond );
	}
#else
	int n = pthread_cond_signal( &m_sttCond );
	if( n != 0 )
	{
		return false;
	}
#endif

	return true;
}

/**
 * @ingroup SipPlatform
 * @brief signal �Ǵ� broadcast �޼ҵ尡 ȣ��� ������ ����ϴ� ��� �����带 ��� ������Ų��.
 * @return true �� �����Ѵ�.
 */
bool CSnmpMutexSignal::broadcast()
{
#ifdef WIN32
	if( m_sttCond )
	{
		SetEvent( m_sttCond );
	}
#else
	int n = pthread_cond_broadcast( &m_sttCond );
	if( n != 0 )
	{
		return false;
	}
#endif

	return true;
}