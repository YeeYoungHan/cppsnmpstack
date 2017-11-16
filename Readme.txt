==================
C++ SNMP stack 프로젝트
==================

1. 개요

 본 프로젝트의 목표는 다음과 같다.

 * C++ STL 기반 SNMP stack 개발

 본 프로젝트의 라이선스는 GPLv3 이다.
 본 프로젝트를 진행하는 개발자 정보는 다음과 같다. 본 프로젝트에 대한 상용 라이선스 발급을 원하시면 아래의 이메일 주소로 연락해 주세요.

 이메일: websearch@naver.com
 블로그: http://blog.naver.com/websearch

2. 폴더 설명

 * SnmpGet
   - SnmpStack 과 SnmpParser 라이브러리를 이용한 SNMP get 프로그램

 * SnmpWalk
   - SnmpStack 과 SnmpParser 라이브러리를 이용한 SNMP get next 프로그램

 * SnmpStack
   - SNMP 메시지 전송/수신 라이브러리

 * SnmpParser
   - SNMP 메시지 파서/생성 라이브러리

 * SnmpPlatform
   - OS 독립적으로 개발하기 위한 라이브러리

3. 컴파일 방법

 * VC++ 2008
   - SipStack.sln 더블클릭한 후, 빌드한다.

 * 리눅스 / OSX
   - make 를 실행한다.
   - [참고] 아직 Makefile 을 개발하지 않았습니다.
