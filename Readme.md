# C++ SNMP stack 프로젝트
C++ STL 기반으로 SNMP stack 을 개발하는 프로젝트입니다.

### 개요
본 프로젝트의 목표는 다음과 같다.

* C++ STL 기반 SNMP stack 개발

### 개발자 정보
본 프로젝트를 진행하는 개발자 정보는 다음과 같습니다.

* 이메일 : websearch@naver.com
* 블로그 : http://blog.naver.com/websearch

### 라이선스

* 본 프로젝트의 라이선스는 GPLv3 이고 기업용 라이선스는 websearch@naver.com 으로 문의해 주세요.

### API 문서

* https://yeeyounghan.github.io/doc/CppSnmpStack/html/index.html

### 폴더 설명

* SnmpGet
  * SnmpStack 과 SnmpParser 라이브러리를 이용한 SNMP get 프로그램

* SnmpWalk
  * SnmpStack 과 SnmpParser 라이브러리를 이용한 SNMP get next 프로그램

* SnmpStack
  * SNMP 메시지 전송/수신 라이브러리

* SnmpParser
  * SNMP 메시지 파서/생성 라이브러리

* SipPlatform
  * OS 독립적으로 개발하기 위한 라이브러리

### 컴파일 방법

* VC++ 2008
  * SnmpStack.sln 더블클릭한 후, 빌드한다.

* 리눅스 / OSX
  * make 를 실행한다.
