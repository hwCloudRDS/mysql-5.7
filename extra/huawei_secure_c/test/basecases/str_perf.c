/*
str_perf.c

*/
#include "securec.h"
#include "base_funcs.h"
/*#include <assert.h>*/
#include <string.h>
#include <stdlib.h>
#include <time.h>
#if !(defined(SECUREC_VXWORKS_PLATFORM))
#include <wchar.h>
#endif
#include "testutil.h"

#ifndef RUN_TIME
#define RUN_TIME 7
#endif

#if defined(SECUREC_VXWORKS_PLATFORM)
    #define DECLARE_VAR struct timespec tvs,tve;      long cost_time;
    #define GET_START_TS clock_gettime(CLOCK_REALTIME, &tvs);
    #define GET_END_TS clock_gettime(CLOCK_REALTIME, &tve);
    #define CALC_INTERVAL   (tve.tv_sec-tvs.tv_sec)*1000000 + (tve.tv_nsec-tvs.tv_nsec) / 1000; 

#elif defined(_WIN32) || defined(_WIN64) 
    #include <Windows.h>
    #include <Winbase.h> /*lint !e537*/
    
        #define DECLARE_VAR LARGE_INTEGER startTs;  clock_t cost_time;
    #define GET_START_TS getStartTs(&startTs);
    #define GET_END_TS 
    #define CALC_INTERVAL calcTimeElapse(&startTs);

    static void getStartTs(LARGE_INTEGER* startTs)
    {
        (void)QueryPerformanceCounter(startTs);
        return;
    }

    static clock_t calcTimeElapse(LARGE_INTEGER* startTs)
    {
        LARGE_INTEGER endTs;
        clock_t interval = 0;
        static int runCnt = 0;
        static    LARGE_INTEGER freq;

        if (0 == runCnt) {
            (void)QueryPerformanceFrequency(&freq);
            ++runCnt;
        }
        (void)QueryPerformanceCounter(&endTs);

        interval = (clock_t)(((endTs.QuadPart - startTs->QuadPart)* 1000000 ) / freq.QuadPart );
        return interval;
    }

#else

    #include    <sys/time.h>

    #define DECLARE_VAR struct timeval tvs,tve;      clock_t cost_time;
    #define GET_START_TS gettimeofday(&tvs, NULL);
    #define GET_END_TS gettimeofday(&tve,NULL);
    #define CALC_INTERVAL (tve.tv_sec <= tvs.tv_sec && tve.tv_usec <= tvs.tv_usec) ? 0 : (tve.tv_sec-tvs.tv_sec)*1000000 + (tve.tv_usec-tvs.tv_usec);

    #define LINUX_LIKE_SYSTEM
#endif

#define SAMPLE_NUMBER 4
#define BASIC_STR_LEN 39

clock_t CalcAvg(clock_t* ary, int arySize)
{
    clock_t avg = 0;
    int i= 0;
    
    for(i= 0; i < arySize; ++ i) {
        avg += ary[i];
    }
    return avg  / arySize;
}



#define MAKE_TEST_FUNC(funcName,charType) clock_t funcName##Test(int is_secure, int loopCnt) {\
    charType destBuf[BASIC_STR_LEN];    \
    charType srcBuf[BASIC_STR_LEN];    \
    int i = 0;    \
     unsigned int tmp = 0;    \
    DECLARE_VAR    \
\
    for(i = 0 ; i < BASIC_STR_LEN -1; ++i ) {    \
        srcBuf[i] = 'a' + (i % 26);    \
    }    \
    srcBuf[ BASIC_STR_LEN -1] = '\0';    \
\
     GET_START_TS    \
    if (is_secure) {    \
        for(i = 0 ; i < loopCnt; ++i ) {    \
            destBuf[0] = '\0';    \
            srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
            (void)funcName##_s(destBuf, BASIC_STR_LEN, srcBuf);    \
            tmp += destBuf[i % BASIC_STR_LEN];        \
        }    \
     }    \
    else {    \
        for(i = 0 ; i < loopCnt; ++i ) {    \
            destBuf[0] = '\0';    \
            srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
            (void)funcName(destBuf, srcBuf);    \
            tmp += destBuf[i % BASIC_STR_LEN];        \
        }    \
    }    \
    GET_END_TS    \
    cost_time = CALC_INTERVAL     \
\
    GET_START_TS    \
    for(i = 0 ; i < loopCnt; ++i ) {    \
        destBuf[0] = '\0';    \
        srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
        tmp += srcBuf[i % BASIC_STR_LEN];        \
    }    \
    GET_END_TS    \
    cost_time -= CALC_INTERVAL      \
    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    \
    return cost_time;    \
}

#define MAKE_N_TEST_FUNC(funcName,charType) clock_t funcName##Test(int is_secure, int loopCnt) {\
    charType destBuf[BASIC_STR_LEN];    \
    charType srcBuf[BASIC_STR_LEN];    \
    int i = 0;    \
     unsigned int tmp = 0;    \
    DECLARE_VAR     \
\
    for(i = 0 ; i < BASIC_STR_LEN -1; ++i ) {    \
        srcBuf[i] = 'a' + (i % 26);    \
    }    \
    srcBuf[ BASIC_STR_LEN -1] = '\0';    \
\
    GET_START_TS     \
    if (is_secure) {    \
        for(i = 0 ; i < loopCnt; ++i ) {    \
            destBuf[0] = '\0';    \
            srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
            (void)funcName##_s(destBuf, BASIC_STR_LEN, srcBuf, BASIC_STR_LEN - 1);    \
            tmp += destBuf[i % BASIC_STR_LEN];        \
        }    \
     }    \
    else {    \
        for(i = 0 ; i < loopCnt; ++i ) {    \
            destBuf[0] = '\0';    \
            srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
            (void)funcName(destBuf, srcBuf, BASIC_STR_LEN - 1);    \
            tmp += destBuf[i % BASIC_STR_LEN];        \
        }    \
    }    \
\
    GET_END_TS \
    cost_time = CALC_INTERVAL     \
    GET_START_TS     \
    for(i = 0 ; i < loopCnt; ++i ) {    \
        destBuf[0] = '\0';    \
        srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
        tmp += srcBuf[i % BASIC_STR_LEN];        \
    }    \
    GET_END_TS    \
    cost_time -= CALC_INTERVAL     \
\
    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    \
    return cost_time;    \
}


#define MAKE_PERFORMANCE_FUNC(funcName) void funcName##PerformanceTest(void)       \
{   \
    clock_t cost_time[SAMPLE_NUMBER]   = {0};    \
    clock_t cost_time_s[SAMPLE_NUMBER] = {0};    \
    int loopCnt[RUN_TIME];    \
    int i, j = 0;    \
    clock_t avg, avg_s;    \
\
    loopCnt[0] =  50 * 10000;    \
    loopCnt[1] = 100 * 10000;    \
    for (i = 2 ; i< RUN_TIME ; ++i) {    \
        loopCnt[i] = loopCnt[i -1] + 100 * 10000;    \
    }    \
\
    printf(" "#funcName " vs "#funcName "_s\n");    \
    for (j = 0 ; j< RUN_TIME ; ++j) {    \
        for(i = 0; i < SAMPLE_NUMBER; i++) {    \
            cost_time[i] = funcName##Test(0, j == 0 ? 10*10000 : loopCnt[j]);    \
            if (j > 0 && 0 >= (long)cost_time[i]) {    \
                --i;    \
                continue;    \
            }    \
        }    \
\
        for(i = 0; i < SAMPLE_NUMBER; i++) {    \
            cost_time_s[i] = funcName##Test( 1/*SECURITY_TRUE*/, j == 0 ? 10*10000 :loopCnt[j]);    \
            if (j > 0 && 0 >= (long)cost_time_s[i]) {    \
                --i;    \
                continue;    \
            }    \
        }    \
        avg = CalcAvg(cost_time+1, SAMPLE_NUMBER - 1)/ 1000;    \
        avg_s = CalcAvg(cost_time_s+1, SAMPLE_NUMBER - 1)/ 1000;    \
        printf("loop: %8d, avg: %6ldms  -- %6ldms %.2f\n",loopCnt[j], avg , avg_s, (float)avg_s / avg  );    \
    }    \
    printf("\n");    \
}

#define MAKE_CHUNK_TEST_FUNC(funcName, bufType) clock_t funcName##ChunkTest(int is_secure, bufType destBuf, int len, bufType srcBuf)    \
{    \
    DECLARE_VAR     \
    GET_START_TS     \
    if(is_secure)    \
    {    \
        (void)funcName##_s(destBuf, len, srcBuf);    \
    }    \
    else    \
    {    \
        (void)funcName(destBuf, srcBuf);    \
    }    \
    GET_END_TS     \
    cost_time = CALC_INTERVAL    \
    return cost_time;        \
}

#define MEM_CHUNK_NUMBER 4
#define M_SIZE (1024*1024)

#define MAKE_CHUNK_PERF_TEST_FUNC(funcName, bufType) void funcName##ChunkPerformanceTest(void)      \
{    \
    bufType* dest_mem = NULL;    \
    bufType* src_mem =  NULL;    \
    clock_t cost_time[SAMPLE_NUMBER]   = {0};    \
    clock_t cost_time_s[SAMPLE_NUMBER] = {0};    \
    clock_t avg, avg_s;                        \
    int bufSize[MEM_CHUNK_NUMBER] = {50* M_SIZE,100* M_SIZE, 200* M_SIZE, 300* M_SIZE};    \
    int i, j;    \
\
    printf(" "#funcName " vs "#funcName "_s in chunk\n");    \
\
    if (sizeof(bufType) > 1) { \
        for(i = 0; i < MEM_CHUNK_NUMBER ; i++) {    \
            bufSize[i] /= (int)sizeof(bufType);    \
        }    \
    } \
    dest_mem = (bufType*)malloc(bufSize[MEM_CHUNK_NUMBER -1] * sizeof(bufType));    \
    src_mem =  (bufType*)malloc(bufSize[MEM_CHUNK_NUMBER -1] * sizeof(bufType));     \
    if (NULL == dest_mem || NULL == src_mem) {    \
        return;    \
    }    \
    for(i = 0; i < bufSize[MEM_CHUNK_NUMBER -1 ] -1; i++) {    \
        src_mem[i] = 'a' + (i % 26);    \
    }    \
    src_mem[i] = '\0';    \
    for(j = 0 ; j < MEM_CHUNK_NUMBER; ++j) {    \
        src_mem[bufSize[j] -1] = '\0';    \
        for(i = 0; i < MEM_CHUNK_NUMBER; i++) {    \
            src_mem[i] = 'a' +i;    \
            dest_mem[0] =  '\0';    \
            cost_time[i] = funcName##ChunkTest(0, dest_mem, bufSize[j], src_mem);    \
            src_mem[i + 2] = dest_mem[i];    \
        }    \
\
        for(i = 0; i < MEM_CHUNK_NUMBER; i++) {    \
            src_mem[i + 1] = 'a' +i;    \
            dest_mem[0] =  '\0';    \
            cost_time_s[i] = funcName##ChunkTest(1 /*for secure function*/,dest_mem,  bufSize[j], src_mem);    \
        }    \
        src_mem[bufSize[j] -1] = 'a';    \
        avg = CalcAvg(cost_time+1, MEM_CHUNK_NUMBER - 1)/ 1000;    \
        avg_s = CalcAvg(cost_time_s+1, MEM_CHUNK_NUMBER - 1)/ 1000;    \
        printf("chunk: %5luM, avg: %6ldms  -- %6ldms %.2f\n", (unsigned long)(bufSize[j]* sizeof(bufType) / M_SIZE), avg, avg_s, (float)avg_s / avg );    \
    }    \
    free(dest_mem); \
    free(src_mem);     \
    dest_mem = NULL;    \
    src_mem =  NULL;    \
    printf("\n");    \
}


#define FMT_STR_LEN 30


static clock_t sprintfPerfTest(int is_secure, int loopCnt) 
{
    char destBuf[FMT_STR_LEN + 20];    
    char srcBuf[FMT_STR_LEN];    
    int i = 0;    
     unsigned int tmp = 0;    
    DECLARE_VAR    

    for(i = 0 ; i < FMT_STR_LEN -1; ++i ) {    
        srcBuf[i] = 'a' + (i % 26);    
    }    
    srcBuf[ FMT_STR_LEN -1] = '\0';    

     GET_START_TS    
    if (is_secure) {    
        for(i = 0 ; i < loopCnt; ++i ) {    
            srcBuf[i % (FMT_STR_LEN -1)] = 'a' + (i % 26);    
            
            (void)sprintf_s(destBuf, FMT_STR_LEN + 20, "%d %s", i, srcBuf);    
            tmp += destBuf[i % FMT_STR_LEN];        
        }    
     }    
    else {    
        for(i = 0 ; i < loopCnt; ++i ) {    
            srcBuf[i % (FMT_STR_LEN -1)] = 'a' + (i % 26);    
            sprintf(destBuf, "%d %s", i, srcBuf);    
            tmp += destBuf[i % FMT_STR_LEN];        
        }    
    }    
    GET_END_TS    
    cost_time = CALC_INTERVAL     

    GET_START_TS    
    for(i = 0 ; i < loopCnt; ++i ) {    
        destBuf[0] = '\0';    
        srcBuf[i % (FMT_STR_LEN -1)] = 'a' + (i % 26);    
        tmp += srcBuf[i % FMT_STR_LEN];        
    }    
    GET_END_TS    
    cost_time -= CALC_INTERVAL      
    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    
    return cost_time;    
}



void sprintfPerformanceTest(void)       
{
    clock_t cost_time[SAMPLE_NUMBER]   = {0};    
    clock_t cost_time_s[SAMPLE_NUMBER] = {0};    
    int loopCnt[RUN_TIME];    
    int i, j = 0;    
    clock_t avg, avg_s;    

    loopCnt[0] =   100000;    
    loopCnt[1] =   200000;    
    for (i = 2 ; i< RUN_TIME ; ++i) {    
        loopCnt[i] = loopCnt[i -1] + 100000;    
    }    

    printf(" sprintf vs sprintf_s\n");    
    for (j = 0 ; j< RUN_TIME ; ++j) {    
        for(i = 0; i < SAMPLE_NUMBER; i++) {    
            cost_time[i] = sprintfPerfTest(0, j == 0 ? 10*10000 : loopCnt[j]);    
            if (j > 0 && 0 >= (long)cost_time[i]) {    
                --i;    
                continue;    
            }    
        }    

        for(i = 0; i < SAMPLE_NUMBER; i++) {    
            cost_time_s[i] = sprintfPerfTest( 1/*SECURITY_TRUE*/, j == 0 ? 10*10000 :loopCnt[j]);    
            if (j > 0 && 0 >= (long)cost_time_s[i]) {    
                --i;    
                continue;    
            }    
        }    
        avg = CalcAvg(cost_time+1, SAMPLE_NUMBER - 1)/ 1000;    
        avg_s = CalcAvg(cost_time_s+1, SAMPLE_NUMBER - 1)/ 1000;    
        printf("loop: %8d, avg: %6ldms  -- %6ldms %.2f\n",loopCnt[j], avg , avg_s, (float)avg_s / avg  );    
    }    
    printf("\n");    
}


/*
these are used to test string copy with strlen and sys strcpy
MAKE_TEST_FUNC(strcpy_s, char)
MAKE_PERFORMANCE_FUNC(strcpy_s)

MAKE_CHUNK_TEST_FUNC(strcpy_s, char*)
MAKE_CHUNK_PERF_TEST_FUNC(strcpy_s, char)
*/

MAKE_CHUNK_TEST_FUNC(strcpy, char*) /*lint !e668*/
#ifndef SECUREC_VXWORKS_PLATFORM
MAKE_CHUNK_TEST_FUNC(wcscpy, wchar_t*)
#endif

MAKE_CHUNK_TEST_FUNC(strcat, char*) /*lint !e668*/
#ifndef SECUREC_VXWORKS_PLATFORM
MAKE_CHUNK_TEST_FUNC(wcscat, wchar_t*)
#endif

MAKE_CHUNK_PERF_TEST_FUNC(strcpy, char) /*lint !e429*/
#ifndef SECUREC_VXWORKS_PLATFORM
MAKE_CHUNK_PERF_TEST_FUNC(wcscpy, wchar_t) /*lint !e429*/
#endif

MAKE_CHUNK_PERF_TEST_FUNC(strcat, char) /*lint !e429*/
#ifndef SECUREC_VXWORKS_PLATFORM
MAKE_CHUNK_PERF_TEST_FUNC(wcscat, wchar_t) /*lint !e429*/
#endif


MAKE_TEST_FUNC(strcpy, char)
#ifndef SECUREC_VXWORKS_PLATFORM
MAKE_TEST_FUNC(wcscpy, wchar_t)
#endif

MAKE_TEST_FUNC(strcat, char)
#ifndef SECUREC_VXWORKS_PLATFORM
MAKE_TEST_FUNC(wcscat, wchar_t)
#endif

MAKE_N_TEST_FUNC(strncpy, char)
#ifndef SECUREC_VXWORKS_PLATFORM
MAKE_N_TEST_FUNC(wcsncpy, wchar_t)
#endif

MAKE_N_TEST_FUNC(strncat, char)
#ifndef SECUREC_VXWORKS_PLATFORM
MAKE_N_TEST_FUNC(wcsncat, wchar_t)
#endif

/*MAKE_N_TEST_FUNC(memcpy, char)*/


MAKE_PERFORMANCE_FUNC(strcpy)
#ifndef SECUREC_VXWORKS_PLATFORM
MAKE_PERFORMANCE_FUNC(wcscpy)
#endif

MAKE_PERFORMANCE_FUNC(strcat)
#ifndef SECUREC_VXWORKS_PLATFORM
MAKE_PERFORMANCE_FUNC(wcscat)
#endif

MAKE_PERFORMANCE_FUNC(strncpy)
#ifndef SECUREC_VXWORKS_PLATFORM
MAKE_PERFORMANCE_FUNC(wcsncpy)
#endif

MAKE_PERFORMANCE_FUNC(strncat)
#ifndef SECUREC_VXWORKS_PLATFORM
MAKE_PERFORMANCE_FUNC(wcsncat)
#endif

/*MAKE_PERFORMANCE_FUNC(memcpy)*/
