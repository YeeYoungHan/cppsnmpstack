# Makefile for all of C++ SnmpStack
#
# programmer : yee young han ( websearch@naver.com )
#            : http://blog.naver.com/websearch
# start date : 2014/07/29

all:
	cd SipPlatform && make
	cd SnmpParser && make
	cd SnmpStack && make
	cd SnmpGet && make
	cd SnmpWalk && make

clean:
	cd SipPlatform && make clean
	cd SnmpParser && make clean
	cd SnmpStack && make clean
	cd SnmpGet && make clean
	cd SnmpWalk && make clean

install:

