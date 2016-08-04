# Makefile for SnmpStack
#
# programmer : yee young han ( websearch@naver.com )
#            : http://blog.naver.com/websearch
# start date : 2014/07/29

include ../Makefile.mk

INC=-I../SnmpParser -I../SnmpPlatform

.SUFFIXES: .o .cpp
%.o : %.cpp
	$(CC) $(CFLAGS) -c $< $(INC)

all: libsnmpstack.a

LIB_OBJ=SnmpStack.o SnmpStackSetup.o \
	SnmpTransaction.o SnmpTransactionList.o \
	SnmpStackThread.o SnmpUdpThread.o \
	SnmpSession.o SnmpDebug.o \
	SnmpAgent.o SnmpTcpAgent.o

libsnmpstack.a: $(LIB_OBJ)
	ar crv $@ $(LIB_OBJ)

clean:
	rm -f *.a
	rm -f *.o
	rm -f core.*

