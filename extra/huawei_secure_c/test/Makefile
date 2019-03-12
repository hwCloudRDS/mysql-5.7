vpath %.c ./comptest
vpath %.h ./comptest
vpath %.c ./basecases
vpath %.h ./basecases

#include ./comptest/Makefile
CASEOBJS=gets_test.o memcpytest.o scanftestutf8.o sprintftest.o strcattest.o strcpytest.o strtoktest.o testmain.o testutil.o memset_s_test.o memmove_test.o str_perf.o pub_funcs.o dopra_comptest.o swprintftest_utf8.o
COMP_CASEOBJS=compare_printftest_float.o compare_printftest_int_d.o compare_printftest_int_i.o compare_printftest_other.o compare_printftest_str_c.o compare_printftest_str_s.o compare_swprintftest_str_s_utf8.o compare_sscanftest_float.o compare_sscanftest_int_d.o compare_sscanftest_int_i.o compare_sscanftest_other.o compare_sscanftest_str_c.o compare_sscanftest_str_s.o wscanftest_utf8.o 

CASEOBJS+= $(COMP_CASEOBJS)

CC = gcc
FLAGS = -I ../include -I. -g -D_DEBUG

OS := $(shell uname -s)
IS_LINUX := $(shell echo $(OS)|grep -i Linux)

ifdef IS_LINUX
    FLAGS+= -DLinux
endif

all: $(CASEOBJS)
	mkdir -p obj
	$(CC)  $(FLAGS)  -o maintest $(CASEOBJS)  -L../lib -lsecurec
all_2: $(CASEOBJS)
	$(CC)  $(FLAGS) -o maintest $(CASEOBJS) libsecurec.a
gets_test.o: gets_test.c base_funcs.h testutil.h
	$(CC)  $(FLAGS) -c $<
memcpytest.o: memcpytest.c base_funcs.h testutil.h
	$(CC)  $(FLAGS) -c $<
memset_s_test.o: memset_s_test.c base_funcs.h testutil.h
	$(CC)  $(FLAGS) -c $<
memmove_test.o: memmove_test.c base_funcs.h testutil.h
	$(CC)  $(FLAGS) -c $<
scanftestutf8.o: scanftestutf8.c base_funcs.h testutil.h
	$(CC)  $(FLAGS) -c $<
sprintftest.o: sprintftest.c base_funcs.h testutil.h
	$(CC)  $(FLAGS) -c $<
strcattest.o: strcattest.c base_funcs.h testutil.h
	$(CC)  $(FLAGS) -c $<
strcpytest.o: strcpytest.c base_funcs.h testutil.h
	$(CC)  $(FLAGS) -c $<
strtoktest.o: strtoktest.c base_funcs.h testutil.h
	$(CC)  $(FLAGS) -c $<
pub_funcs.o: pub_funcs.c
	$(CC)  $(FLAGS) -c $<
str_perf.o: str_perf.c
	$(CC)  $(FLAGS) -c $<
dopra_comptest.o: dopra_comptest.c dopra_comptest.h
	$(CC)  $(FLAGS) -c $<
testmain.o: testmain.c base_funcs.h testutil.h
	$(CC)  $(FLAGS) -c $<
testutil.o: testutil.c base_funcs.h testutil.h
	$(CC)  $(FLAGS) -c $<
compare_printftest_float.o: compare_printftest_float.c comp_funcs.h
	$(CC)  $(FLAGS) -c $<
compare_printftest_int_d.o: compare_printftest_int_d.c comp_funcs.h
	$(CC)  $(FLAGS) -c $<
compare_printftest_int_i.o: compare_printftest_int_i.c comp_funcs.h
	$(CC)  $(FLAGS) -c $<
compare_printftest_other.o: compare_printftest_other.c comp_funcs.h
	$(CC)  $(FLAGS) -c $<
compare_printftest_str_c.o: compare_printftest_str_c.c comp_funcs.h
	$(CC)  $(FLAGS) -c $<
compare_printftest_str_s.o: compare_printftest_str_s.c comp_funcs.h
	$(CC)  $(FLAGS) -c $<
compare_sscanftest_float.o: compare_sscanftest_float.c comp_funcs.h
	$(CC)  $(FLAGS) -c $<
compare_sscanftest_int_d.o: compare_sscanftest_int_d.c comp_funcs.h
	$(CC)  $(FLAGS) -c $<
compare_sscanftest_int_i.o: compare_sscanftest_int_i.c comp_funcs.h
	$(CC)  $(FLAGS) -c $<
compare_sscanftest_other.o: compare_sscanftest_other.c comp_funcs.h
	$(CC)  $(FLAGS) -c $<
compare_sscanftest_str_c.o: compare_sscanftest_str_c.c comp_funcs.h
	$(CC)  $(FLAGS) -c $<
compare_sscanftest_str_s.o: compare_sscanftest_str_s.c comp_funcs.h
	$(CC)  $(FLAGS) -c $<
compare_swprintftest_str_s_utf8.o: compare_swprintftest_str_s_utf8.c comp_funcs.h
	$(CC)  $(FLAGS) -c $<
swprintftest_utf8.o: swprintftest_utf8.c base_funcs.h
	$(CC)  $(FLAGS) -c $<
wscanftest_utf8.o: wscanftest_utf8.c base_funcs.h
	$(CC)  $(FLAGS) -c $<
clean:
	rm *.o maintest*