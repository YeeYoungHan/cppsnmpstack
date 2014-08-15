# Makefile for SnmpPlatform
#
# programmer : yee young han ( websearch@naver.com )
#            : http://blog.naver.com/websearch
# start date : 2014/07/29

include ../Makefile.mk

INC=

.SUFFIXES: .o .cpp
%.o : %.cpp
	$(CC) $(CFLAGS) -c $< $(INC)

all: libsnmpplatform.a

LIB_OBJ=Directory.o Log.o \
	SnmpMutex.o \
	SnmpTcp.o SnmpUdp.o \
	TimeUtility.o \
	FileUtility.o \
	ServerUtility.o

libsnmpplatform.a: $(LIB_OBJ)
	ar crv $@ $(LIB_OBJ)

clean:
	rm -f *.a
	rm -f *.o
	rm -f core.*

