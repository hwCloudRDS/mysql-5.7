/*
testutil.h
*/

#ifndef __TESTUTIL_H__076E9CE7_555E_49b2_8DE3_A37C82A6F431
#define __UNITTEST_H__076E9CE7_555E_49b2_8DE3_A37C82A6F431

#include "securec.h" /*lint !e537*/
#include <stddef.h>
#include <time.h>
#include <limits.h>

#if !(defined(_WIN32) ||  defined(_WIN64))
#if !(defined(SECUREC_VXWORKS_PLATFORM))
#include <sys/time.h>
#endif
#endif

#if !(defined(__hpux) || defined(__SOLARIS) || defined(SECUREC_VXWORKS_PLATFORM))
/*typedef unsigned int uint32_t;*/
typedef int int32_t;
#endif

/*1: test the unsupport format; 0:not test */
#define UNSUPPORT_TEST 0
/*1: test %a/A; 0:not test */
#define UNSUPPORT_TEST_A 0
/* 1: test the overflow value,0: not test */
#define OVERFLOW_MARK 0
/* 1: printf the compared result on the screen,0: not print */
#define SCREEN_PRINT 1
/* 1: printf the compared result int the txt document,0: not print */
#define TXT_DOCUMENT_PRINT 1


#define COMPATIBLE_TESTCASE_LINUX_MANUAL  1  /*打开该宏测试从linux 手册中集成的测试用例，用例名称后缀为_add --90005350*/
#define COMPATIBLE_TESTCASE_COMBIN 1

#define SSCANF(formats,sample, sampletype,stdresult,secresult,     \
    stdnumber,stdformats,secnumber,secformats,line)    \
    do \
{\
    /* print out the compare result to stdard function result file */\
    printf("sscanf(%s)(%s)(%lu):", formats, sampletype,line);\
    printf("%s\n", sample);\
    printf("system: %d,", stdresult);\
    printf(stdformats, stdnumber);\
    printf("   secure: %d,", secresult);\
    printf(secformats, secnumber);\
    printf("\n\n");\
}while(0)

#define SPRINTF(formats,sample,sampletype,stdresult, \
    secresult,stdbuffer,secbuffer,line)\
    do\
{\
    /* print out the compare result to stdard function result file */\
    printf("sprintf(%s)(%s)(%lu):", formats, sampletype,line);\
    printf("%s\n", sample);\
    printf("system: %d, ", stdresult);\
    printf("%s", stdbuffer);\
    printf("   secure: %d,", secresult);\
    printf("%s", secbuffer);\
    printf("\n\n");\
}while(0)

#ifdef _DEBUG
#define NULL_OR_SOME_ERROR_HANDLER printf("NOT OK")
#define COMP_MEMCPY(dest, destSize, src, cnt) (memcpy_s(dest, destSize, src, cnt) == EOK ? dest : NULL_OR_SOME_ERROR_HANDLER)
#define COMP_STRCPY(p, dSize, s) (strcpy_s(p, dSize, s) == EOK ? p : NULL)
#else /*for release*/
#define COMP_MEMCPY(dest, destSize, src, cnt) (memcpy_s(dest, destSize, src, cnt) , dest)
#define COMP_STRCPY(p, dSize, s) (strcpy_s(p, dSize, s), p)
#endif

#if (defined(_WIN32) ||  defined(_WIN64))
#define FSCANF_FILES_PATH(str) ("../test/fscanfFiles/"str)
#else
#define FSCANF_FILES_PATH(str) ("./fscanfFiles/"str)
#endif


#if (defined(_MSC_VER) && (_MSC_VER >= 1400)) || (defined(__GNUC__) && (__GNUC__ > 3))
/*VC6 don't support "..." in macro*/
/* coverity[exp_identifier] */
#define COMP_SNPRINTF(strDest, destMax, count,format, ...) snprintf_s(strDest, destMax, count,format, ##__VA_ARGS__)== -1 ? ( strlen(strDest) == (size_t)count ? count : -1 ) : (int)strlen(strDest);
#endif

#define COMP_VSNPRINTF(strDest, destMax, count,format, arglist) vsnprintf_s(strDest, destMax, count,format, arglist)== -1 ? ( strlen(strDest) == (size_t)count ? count : -1 ) : (int)strlen(strDest);


int assertFloatEqu(float v, float expectedVal);
size_t  slen (const char * str);
size_t  wslen (const wchar_t * str);
int  my_wcscmp (  const wchar_t * src,   const wchar_t * dst);

int is64Bits(void);
int is32Bits(void);

UINT64T GetCurMilliSecond(void);

#endif
