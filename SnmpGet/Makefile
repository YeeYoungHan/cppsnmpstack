# Makefile for SnmpGet
#
# programmer : yee young han ( websearch@naver.com )
#            : http://blog.naver.com/websearch
# start date : 2014/07/29

include ../Makefile.mk

INC=-I../SnmpStack -I../SnmpParser -I../SnmpPlatform
LIB=-L../SnmpStack -lsnmpstack \
	-L../SnmpParser -lsnmpparser \
	-L../SnmpPlatform -lsnmpplatform \
	-lpthread

.SUFFIXES: .o .cpp
%.o : %.cpp
	$(CC) $(CFLAGS) -c $< $(INC)

all: SnmpGet.exe

SRV_OBJ=SnmpGet.o

SnmpGet.exe: $(SRV_OBJ)
	$(CC) $(CFLAGS) -o $@ $(SRV_OBJ) $(INC) $(LIB)

clean:
	rm -f *.exe
	rm -f *.o
	rm -f core.*

