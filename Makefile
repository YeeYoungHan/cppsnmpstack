# Makefile for all of C++ SnmpStack
#
# programmer : yee young han ( websearch@naver.com )
#            : http://blog.naver.com/websearch
# start date : 2014/07/29

all:
	cd SnmpPlatform && make
	cd SnmpParser && make
	cd SnmpStack && make
	cd SnmpGet && make

clean:
	cd SnmpPlatform && make clean
	cd SnmpParser && make clean
	cd SnmpStack && make clean
	cd SnmpGet && make clean

install:

