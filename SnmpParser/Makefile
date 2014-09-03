# Makefile for SnmpParser
#
# programmer : yee young han ( websearch@naver.com )
#            : http://blog.naver.com/websearch
# start date : 2014/07/29

include ../Makefile.mk

INC=-I../SnmpPlatform

.SUFFIXES: .o .cpp
%.o : %.cpp
	$(CC) $(CFLAGS) -c $< $(INC)

all: libsnmpparser.a

LIB_OBJ=AsnComplex.o \
	AsnInt.o AsnLong.o AsnNull.o AsnOid.o AsnString.o AsnType.o \
	SnmpMessage.o \
	SnmpAuth.o

libsnmpparser.a: $(LIB_OBJ)
	ar crv $@ $(LIB_OBJ)

clean:
	rm -f *.a
	rm -f *.o
	rm -f core.*

