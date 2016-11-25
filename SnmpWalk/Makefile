# Makefile for SnmpWalk
#
# programmer : yee young han ( websearch@naver.com )
#            : http://blog.naver.com/websearch
# start date : 2014/08/07

include ../Makefile.mk

INC=-I../SnmpStack -I../SnmpParser -I../SipPlatform
LIB=-L../SnmpStack -lsnmpstack \
	-L../SnmpParser -lsnmpparser \
	-L../SipPlatform -lsipplatform \
	-lssl -lcrypto -lpthread

.SUFFIXES: .o .cpp
%.o : %.cpp
	$(CC) $(CFLAGS) -c $< $(INC)

all: SnmpWalk.exe

SRV_OBJ=SnmpWalk.o CallBack.o

SnmpWalk.exe: $(SRV_OBJ)
	$(CC) $(CFLAGS) -o $@ $(SRV_OBJ) $(INC) $(LIB)

clean:
	rm -f *.exe
	rm -f *.o
	rm -f core.*

