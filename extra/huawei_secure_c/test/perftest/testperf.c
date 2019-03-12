/*
performance test.c
2014/7/11

*/
#include "securec.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/*function type*/
#define FUNC_TYPE_SYS 0
#define FUNC_TYPE_SECURE_S 1
#define FUNC_TYPE_SECURE_SP 2
#define FUNC_TYPE_SECURE_SP2 3

#if defined(SECUREC_VXWORKS_PLATFORM)
    #define DECLARE_VAR struct timespec tvs,tve;      long cost_time;
    #define GET_START_TS clock_gettime(CLOCK_REALTIME, &tvs);
    #define GET_END_TS clock_gettime(CLOCK_REALTIME, &tve);
    #define CALC_INTERVAL   (tve.tv_sec-tvs.tv_sec)*1000000 + (tve.tv_nsec-tvs.tv_nsec) / 1000; 

#elif defined(_WIN32) || defined(_WIN64) 
    #include <Windows.h>
    #include <Winbase.h>
    
    #define DECLARE_VAR LARGE_INTEGER startTs;  clock_t cost_time;
    #define GET_START_TS getStartTs(&startTs);
    #define GET_END_TS 
    #define CALC_INTERVAL calcTimeElapse(&startTs);

	static void getStartTs(LARGE_INTEGER* startTs)
    {
    	QueryPerformanceCounter(startTs);
    	return;
    }

	static clock_t calcTimeElapse(LARGE_INTEGER* startTs)
    {
    	LARGE_INTEGER endTs;
    	clock_t interval = 0;
    	static int runCnt = 0;
    	static	LARGE_INTEGER freq;

    	if (0 == runCnt) {
        	QueryPerformanceFrequency(&freq);
            ++runCnt;
        }
    	QueryPerformanceCounter(&endTs);

    	interval = (clock_t)(((endTs.QuadPart - startTs->QuadPart)* 1000000 ) / freq.QuadPart );
    	return interval;
    }

#else /* Linux like system */
    #include    <sys/time.h>

    #define DECLARE_VAR struct timeval tvs,tve;      clock_t cost_time;
    #define GET_START_TS gettimeofday(&tvs, NULL);
    #define GET_END_TS gettimeofday(&tve,NULL);
    #define CALC_INTERVAL (tve.tv_sec <= tvs.tv_sec && tve.tv_usec <= tvs.tv_usec) ? 0 : (tve.tv_sec-tvs.tv_sec)*1000000 + (tve.tv_usec-tvs.tv_usec);

    #define LINUX_LIKE_SYSTEM
#endif

#define SAMPLE_NUMBER 4
#define BASIC_STR_LEN 39 /* change from 256 to 39 */
#define TEST_PARA_MEM_LEN (10*1024)
#define LARGE_MEM_LEN (800*1024)
#define RUN_TIME 6

#define BASIC_T_STR "PKT_HDR_V_1.4"
#define BASIC_T_STR_LEN (strlen(BASIC_T_STR))


#define COMP_MEMCPY(dest, destSize, src, cnt) (memcpy_s(dest, destSize, src, cnt) , dest)

/*Products using scene simulation*/
#define MEMSET1(d, max, v, c) memset(d, v, c)
#define MEMCPY1(d, max, s, c) memcpy(d, s, c)
#define MEMSET1V(d, max, v, c) memset(d, v, c)
#define MEMCPY1V(d, max, s, c) memcpy(d, s, c)

#define MEMSET2(d, max, v, c) memset_s(d, max, v, c)
#define MEMCPY2(d, max, s, c) memcpy_s(d, max, s, c)
#define MEMSET2V(d, max, v, c) memset_s(d, max, v, c)
#define MEMCPY2V(d, max, s, c) memcpy_s(d, max, s, c)

#define MEMSET3(d, max, v, c)  memset_sp(d, max, v, c)
#define MEMCPY3(d, max, s, c)  memcpy_sp(d, max, s, c)
#define MEMSET3V(d, max, v, c)  memset_sp(d, max, v, c)
#define MEMCPY3V(d, max, s, c)  memcpy_sp(d, max, s, c)

static clock_t CalcAvg(clock_t* ary, int arySize)
{
	clock_t avg = 0;
	int i= 0;
    
	for(i= 0; i < arySize; ++ i) {
    	avg += ary[i];
    }
	return avg  / arySize;
}

#define COPY_SIZE_COUNT 100

static clock_t memcpyPerfTest(int iFuncType, int* copyLen, int loopCnt)
{
    static char destBuf[LARGE_MEM_LEN];    
    static char srcBuf[LARGE_MEM_LEN];    
    int i = 0;    
    unsigned int tmp = 0;    
    char* pDest = NULL;
    DECLARE_VAR     

    for(i = 0 ; i < LARGE_MEM_LEN -1; ++i ) {    
        srcBuf[i] = 'a' + (i % 26);    
    }    
    srcBuf[ LARGE_MEM_LEN -1] = '\0';    

    GET_START_TS	
    switch(iFuncType)
    {
        case FUNC_TYPE_SYS:
            for(i = 0 ; i < loopCnt; ++i ) {    
                srcBuf[i % (LARGE_MEM_LEN -1)] = 'a' + (i % 26);    
                /* call system memcpy */
                pDest = i % 40 == 0 ? (destBuf + (copyLen[ i % COPY_SIZE_COUNT] % 512) / sizeof(void*) *  sizeof(void*) )  : destBuf;
                memcpy(pDest, srcBuf, copyLen[ i % COPY_SIZE_COUNT] );    
                tmp += destBuf[i % LARGE_MEM_LEN];        
            }    
            break;    
        case FUNC_TYPE_SECURE_S:
            for(i = 0 ; i < loopCnt; ++i ) {    
                srcBuf[i % (LARGE_MEM_LEN -1)] = 'a' + (i % 26);
                pDest = i % 40 == 0 ? (destBuf + (copyLen[ i % COPY_SIZE_COUNT] % 512) / sizeof(void*) *  sizeof(void*) )  : destBuf;
                /* call original memcpy_s */
                memcpy_s(pDest, LARGE_MEM_LEN, srcBuf, copyLen[ i % COPY_SIZE_COUNT] );    
                tmp += destBuf[i % LARGE_MEM_LEN];        
            }
            break;
        case FUNC_TYPE_SECURE_SP:
            for(i = 0 ; i < loopCnt; ++i ) {    
                srcBuf[i % (LARGE_MEM_LEN -1)] = 'a' + (i % 26);    
                pDest = i % 40 == 0 ? (destBuf + (copyLen[ i % COPY_SIZE_COUNT] % 512) / sizeof(void*) *  sizeof(void*) )  : destBuf;
#if defined(WITH_PERFORMANCE_ADDONS) 
                /* call optimized memcpy_s */
                (void)memcpy_sp(pDest, LARGE_MEM_LEN, srcBuf, copyLen[ i % COPY_SIZE_COUNT]);    
#else
                *(char*)pDest = srcBuf[ i % COPY_SIZE_COUNT];    
#endif
                tmp += destBuf[i % LARGE_MEM_LEN];        
            }
            break;
        case FUNC_TYPE_SECURE_SP2:
            for(i = 0 ; i < loopCnt; ++i ) {    
                srcBuf[i % (LARGE_MEM_LEN -1)] = 'a' + (i % 26);
                pDest = i % 40 == 0 ? (destBuf + (copyLen[ i % COPY_SIZE_COUNT] % 512) / sizeof(void*) *  sizeof(void*) )  : destBuf;
#if defined(WITH_PERFORMANCE_ADDONS) 
                /* you can put your own memcpy_s function here */    
                memcpy_sp(pDest, LARGE_MEM_LEN, srcBuf, copyLen[ i % COPY_SIZE_COUNT] );    
#else
                *(char*)pDest = srcBuf[ i % COPY_SIZE_COUNT];
#endif
                tmp += destBuf[i % LARGE_MEM_LEN];        
            }
            break;
    }

    GET_END_TS;
    cost_time = CALC_INTERVAL;     
    tmp = 0;
    GET_START_TS;    
    for(i = 0 ; i < loopCnt; ++i ) {    
        srcBuf[i % (LARGE_MEM_LEN -1)] = 'a' + (i % 26);    
        tmp += srcBuf[i % LARGE_MEM_LEN];        
    }    
    GET_END_TS;    
    cost_time -= CALC_INTERVAL;     

    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    
    return cost_time;    
}

static void ThreeMemcpyPerformanceTest(void)       
{
    clock_t cost_time[SAMPLE_NUMBER]   = {0};    
    clock_t cost_time_s[SAMPLE_NUMBER] = {0};    
    clock_t cost_time_sp[SAMPLE_NUMBER] = {0};
    //clock_t cost_time_sOpt2[SAMPLE_NUMBER] = {0};
    int copyLen[COPY_SIZE_COUNT];
    int loopCnt[RUN_TIME];    
    int i, j = 0, k = 0, upBound = 0;    
    clock_t avg, avg_s, avg_sp/*, avg_sOpt2*/;    

    loopCnt[0] =  40 * 10000;    
    for (i = 1 ; i< RUN_TIME ; ++i) {    
        loopCnt[i] = loopCnt[i -1] + 20 * 10000;    
    }

    for (k = 0; k < 15; ++k)
    {
        if ( k < 3 ){
            upBound = 8 * (1 << (k));
        }else if ( k < 10 ){
            upBound = 64 + 32 * (k - 3);
        }else if ( k < 12 ){
            upBound =   32 * (2<<(k-7));
        }else {
            upBound = 16 * (2 << (k - 6));
        } 
        for (i = 0 ; i< COPY_SIZE_COUNT ; ++i)
        {    
            copyLen[i] = rand() % upBound;    
            if ( copyLen[i] == 0 || copyLen[i] < upBound - 32) {
                --i;
                continue;
            }
        }

        printf("Copy size about  %dBytes\n", upBound);    
        printf("           memcpy:    memcpy_s(_s/sys):    memcpy_sp(sp/sys,sp/_s):\n");
        for (j = 0 ; j< RUN_TIME ; ++j)
        {
            for(i = 0; i < SAMPLE_NUMBER; i++) {    
                cost_time[i] = memcpyPerfTest(FUNC_TYPE_SYS, copyLen, j == 0 ? 10*10000 : loopCnt[j]);    
                if (j > 0 && 0 >= (long)cost_time[i]) {    
                    --i;    
                    continue;    
                }    
            }    

            for(i = 0; i < SAMPLE_NUMBER; i++) {    
                cost_time_s[i] = memcpyPerfTest(FUNC_TYPE_SECURE_S, copyLen, j == 0 ? 10*10000 :loopCnt[j]);    
                if (j > 0 && 0 >= (long)cost_time_s[i]) {    
                    --i;    
                    continue;    
                }    
            }
            for(i = 0; i < SAMPLE_NUMBER; i++) {    
                cost_time_sp[i] = memcpyPerfTest(FUNC_TYPE_SECURE_SP, copyLen, j == 0 ? 10*10000 :loopCnt[j]);    
                if (j > 0 && 0 >= (long)cost_time_sp[i]) {    
                    --i;
                    continue;    
                }    
            }
            //for(i = 0; i < SAMPLE_NUMBER; i++) {    
            //    cost_time_sOpt2[i] = memcpyPerfTest(FUNC_TYPE_SECURE_SP2, copyLen, j == 0 ? 10*10000 :loopCnt[j]);    
            //    if (j > 0 && 0 >= (long)cost_time_sOpt2[i]) {    
            //        --i;
            //        continue;    
            //    }
            //}
            avg = CalcAvg(cost_time+1, SAMPLE_NUMBER - 1)/ 1000;    /*sys function const time*/
            avg_s = CalcAvg(cost_time_s+1, SAMPLE_NUMBER - 1)/ 1000;    /*secure function cost time*/
            avg_sp = CalcAvg(cost_time_sp+1, SAMPLE_NUMBER - 1)/ 1000;    
            //avg_sOpt2 = CalcAvg(cost_time_sOpt2+1, SAMPLE_NUMBER - 1)/ 1000;    

            //printf("loop:%7d, %6ldms %6ldms(%.2f) %6ldms(%.2f,%.2f) - %6ldms(%.2f)\n",loopCnt[j], avg , avg_s, (float)avg_s / avg, avg_sp, (float)avg_sp / avg, (float)avg_sp /avg_s, avg_sOpt2, (float)avg_sOpt2 / avg );    
            printf("loop:%7d, %6ldms %6ldms(%.2f) %6ldms(%.2f,%.2f) \n",loopCnt[j], avg , avg_s, (float)avg_s / avg, avg_sp, (float)avg_sp / avg, (float)avg_sp /avg_s);    
        }
        printf("\n");    
    }
}

static clock_t memsetPerfTest(int iFuncType, int* copyLen, int loopCnt)
{
    static char destBuf[LARGE_MEM_LEN];    
    int i = 0, c =0;
    unsigned int tmp = 0;    
    char* pDest = NULL;
    DECLARE_VAR;     

    GET_START_TS;     
    switch(iFuncType) 
    {
    case FUNC_TYPE_SYS:
        for(i = 0 ; i < loopCnt; ++i ) {    
            switch( i%2) {
            case 0: c =1; break;
            case 1: c = 0xFF; break;
            case 2: c = i; break;
            }
            /* call system memset */
            pDest = i % 20 == 0 ? (destBuf + copyLen[ i % COPY_SIZE_COUNT] % 512) : destBuf;
            memset(pDest, c, copyLen[ i % COPY_SIZE_COUNT] );    
            tmp += destBuf[i % LARGE_MEM_LEN];        
        }    
        break;    
    case FUNC_TYPE_SECURE_S:
        for(i = 0 ; i < loopCnt; ++i ) {    
            switch( i%2) {
            case 0: c =1;	break;
            case 1: c = 0xFF; break;
            case 2: c = i; break;
            }
            pDest = i % 20 == 0 ? (destBuf + copyLen[ i % COPY_SIZE_COUNT] % 512) : destBuf;
            memset_s(pDest, LARGE_MEM_LEN, c, copyLen[ i % COPY_SIZE_COUNT]);    
            tmp += destBuf[i % LARGE_MEM_LEN];        
        }
        break;    
    case FUNC_TYPE_SECURE_SP:
        for(i = 0 ; i < loopCnt; ++i ) {    
            switch( i%2) {
            case 0: c =1;	break;
            case 1: c = 0xFF; break;
            case 2: c = i; break;
            }
            pDest = i % 20 == 0 ? (destBuf + copyLen[ i % COPY_SIZE_COUNT] % 512) : destBuf;
#if defined(WITH_PERFORMANCE_ADDONS) 
            memset_sp(pDest, LARGE_MEM_LEN, c, copyLen[ i % COPY_SIZE_COUNT] );    
#else
            *(char*)pDest = c;
#endif
            tmp += destBuf[i % LARGE_MEM_LEN];        
        }
        break;
    }

    GET_END_TS;
    cost_time = CALC_INTERVAL;    
    GET_START_TS;     
    for(i = 0 ; i < loopCnt; ++i ) {    
        tmp += destBuf[i % LARGE_MEM_LEN];        
    }    
    GET_END_TS;    
    cost_time -= CALC_INTERVAL;     

    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    
    return cost_time;    
}

static void ThreeMemsetPerformanceTest(void) 
{
    clock_t cost_time[SAMPLE_NUMBER]   = {0};    
    clock_t cost_time_s[SAMPLE_NUMBER] = {0};    
	clock_t cost_time_sp[SAMPLE_NUMBER] = {0};
    //clock_t cost_time_sp2[SAMPLE_NUMBER] = {0};
	int copyLen[COPY_SIZE_COUNT];
	int loopCnt[RUN_TIME];    
    int i, j = 0, k = 0, upBound = 0;    
	clock_t avg, avg_s, avg_sp/*, avg_sp2*/;    

	loopCnt[0] =  40 * 10000;    
	for (i = 1 ; i< RUN_TIME ; ++i) {    
    	loopCnt[i] = loopCnt[i -1] + 20 * 10000;    
    }

    for (k = 0; k < 16; ++k) 
    {
        if ( k < 3 ){
            upBound = 8 * (1 << (k));
        }else if ( k < 10 ){
            upBound = 64 + 32 * (k - 3);
        }else if ( k < 12 ){
            upBound =   32 * (2<<(k-7));
        }else {
            upBound = 16 * (2 << (k - 6));
        }

    	for (i = 0 ; i< COPY_SIZE_COUNT ; ++i) {    
        	copyLen[i] =  rand() % upBound;    
        	if ( copyLen[i] == 0 || copyLen[i] < upBound - 32) {
                --i;
            	continue;
            }
        }

    	printf("set size about  %dBytes\n", upBound);
        printf("         memset:    memset_s(_s/sys):    memset_sp(sp/sys,sp/_s)      \n");

    	for (j = 0 ; j< RUN_TIME ; ++j) 
        {
        	for(i = 0; i < SAMPLE_NUMBER; i++) {    
            	cost_time[i] = memsetPerfTest(FUNC_TYPE_SYS, copyLen, j == 0 ? 10*10000 : loopCnt[j]);    
            	if (j > 0 && 0 >= (long)cost_time[i]) {    
                    --i;    
                	continue;    
                }    
            }    
        	for(i = 0; i < SAMPLE_NUMBER; i++) {    
            	cost_time_s[i] = memsetPerfTest(FUNC_TYPE_SECURE_S, copyLen, j == 0 ? 10*10000 :loopCnt[j]);    
            	if (j > 0 && 0 >= (long)cost_time_s[i]) {    
                    --i;    
                	continue;    
                }    
            }
        	for(i = 0; i < SAMPLE_NUMBER; i++) {    
            	cost_time_sp[i] = memsetPerfTest(FUNC_TYPE_SECURE_SP, copyLen, j == 0 ? 10*10000 :loopCnt[j]);    
            	if (j > 0 && 0 >= (long)cost_time_sp[i]) {    
                    --i;
                	continue;    
                }    
            }
            //for(i = 0; i < SAMPLE_NUMBER; i++) {    
            //	cost_time_sp2[i] = memsetPerfTest(FUNC_TYPE_SECURE_SP2, copyLen, j == 0 ? 10*10000 :loopCnt[j]);    
            //	if (j > 0 && 0 >= (long)cost_time_sp2[i]) {    
            //        --i;
            //    	continue;    
            //    }    
            //}
        	avg = CalcAvg(cost_time+1, SAMPLE_NUMBER - 1)/ 1000;    
        	avg_s = CalcAvg(cost_time_s+1, SAMPLE_NUMBER - 1)/ 1000;    
        	avg_sp = CalcAvg(cost_time_sp+1, SAMPLE_NUMBER - 1)/ 1000;    
            //avg_sp2 = CalcAvg(cost_time_sp2+1, SAMPLE_NUMBER - 1)/ 1000;    

            //printf("loop: %7d, %6ldms %6ldms(%.2f) %6ldms(%.2f,%.2f) %6ldms(%.2f)\n",loopCnt[j], avg , avg_s, (float)avg_s / avg, avg_sp, (float)avg_sp / avg, (float)avg_sp /avg_s, avg_sp2, (float)avg_sp2 / avg );    
            printf("loop: %7d, %6ldms %6ldms(%.2f) %6ldms(%.2f,%.2f) \n",loopCnt[j], avg , avg_s, (float)avg_s / avg, avg_sp, (float)avg_sp / avg, (float)avg_sp /avg_s);    
        }
    	printf("\n");    

    }
}

 typedef errno_t (*PFUNC_MEMCPY)(void* dest, size_t destMax, const void* src, size_t count);
 
static clock_t memcpyParaTest(PFUNC_MEMCPY whichOne, int* copyLen, int loopCnt, int copyPara)
 {
	static char destBuf[TEST_PARA_MEM_LEN];    
	static char srcBuf[TEST_PARA_MEM_LEN];    
	int i = 0;    
     unsigned int tmp = 0;    
     char* pDest = NULL;
	DECLARE_VAR     

	for(i = 0 ; i < TEST_PARA_MEM_LEN -1; ++i ) {
    	srcBuf[i] = 'a' + (i % 26);    
    }    
	srcBuf[ TEST_PARA_MEM_LEN -1] = '\0';    

    GET_START_TS     
	if (NULL == whichOne) {
    	for(i = 0 ; i < loopCnt; ++i ) {    
        	srcBuf[i % (TEST_PARA_MEM_LEN -1)] = 'a' + (i % 26);    
            /* call system memcpy */
        	pDest = i % 20 == 0 ? (destBuf + copyLen[ i % COPY_SIZE_COUNT] % 512) : destBuf;
        	memcpy(pDest, srcBuf, copyLen[ i % COPY_SIZE_COUNT] );    
        	tmp += destBuf[i % TEST_PARA_MEM_LEN];        
        }
    }else if (memcpy_s == whichOne) {
    	for(i = 0 ; i < loopCnt; ++i ) {    
        	srcBuf[i % (TEST_PARA_MEM_LEN -1)] = 'a' + (i % 26);    
        	pDest = i % 20 == 0 ? (destBuf + copyLen[ i % COPY_SIZE_COUNT] % 512) : destBuf;
        	memcpy_s(pDest, TEST_PARA_MEM_LEN, srcBuf, copyLen[ i % COPY_SIZE_COUNT]);    
        	tmp += destBuf[i % TEST_PARA_MEM_LEN];        
        }
    }
	else
    {
    	return 0;
    }
	GET_END_TS 
	cost_time = CALC_INTERVAL     
	GET_START_TS     
	for(i = 0 ; i < loopCnt; ++i ) {    
    	srcBuf[i % (TEST_PARA_MEM_LEN -1)] = 'a' + (i % 26);    
    	tmp += srcBuf[i % TEST_PARA_MEM_LEN];        
    }    
	GET_END_TS	
	cost_time -= CALC_INTERVAL;

    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    
    return cost_time;    
}

static void analyseBestMaxCopyLen(void)
{
    clock_t cost_time[SAMPLE_NUMBER]   = {0};    
	clock_t cost_time_sOpt[SAMPLE_NUMBER] = {0};
	int copyLen[COPY_SIZE_COUNT];
	int loopCnt[RUN_TIME];    
	float eachResult[RUN_TIME];
    int i, j = 0, k = 0, upBound = 0;    
	clock_t avg, avg_sOpt;    
	float maxVal = 0, minVal = 0;
	int valPos = 0;
	PFUNC_MEMCPY funcPtrs[] = {  memcpy_s};


	loopCnt[0] =  40 * 10000;    
	for (i = 1 ; i< RUN_TIME ; ++i) {    
    	loopCnt[i] = loopCnt[i -1] + 20 * 10000;    
    }

	printf("%s\n", "calc best threshold in memcpy_s \n memcpy vs memcpy_sOpt");    

	for (k = 0; k < 13; ++k) {
    	upBound = 16 * (k + 4);
    	for (i = 0 ; i< COPY_SIZE_COUNT ; ++i) {    
        	copyLen[i] = rand() % upBound;    
        	if (copyLen[i] == 0 || copyLen[i] < upBound - 32) {
                --i;
            	continue;
            }
        }
    	printf("Copy size about  %dBytes\n", upBound);    

    	for (j = 0 ; j< RUN_TIME ; ++j) {

        	for(i = 0; i < SAMPLE_NUMBER; i++) {    
            	cost_time[i] = memcpyParaTest(NULL, copyLen, j == 0 ? 10*10000 : loopCnt[j], upBound);    
            	if (j > 0 && 0 >= (long)cost_time[i]) {    
                    --i;    
                	continue;    
                }    
            }    

        	for(i = 0; i < SAMPLE_NUMBER; i++) {    
            	cost_time_sOpt[i] = memcpyParaTest( funcPtrs[k ]/*optimization version*/, copyLen, j == 0 ? 10*10000 :loopCnt[j], upBound);    
            	if (j > 0 && 0 >= (long)cost_time_sOpt[i]) {    
                    --i;
                	continue;    
                }    
            }
        	avg = CalcAvg(cost_time+1, SAMPLE_NUMBER - 1)/ 1000;    
        	avg_sOpt = CalcAvg(cost_time_sOpt+1, SAMPLE_NUMBER - 1)/ 1000;    
        	eachResult[j] = (float)avg_sOpt / avg;

        	printf("loop: %8d, avg: %6ldms  -- %6ldms (%.2f)\n",loopCnt[j], avg , avg_sOpt, (float)avg_sOpt / avg );    
        }
        
        /* remove eachResult max value */
    	maxVal = eachResult[0];
    	valPos = 0;
    	for (j = 1 ; j< RUN_TIME ; ++j) {
        	if (eachResult[j] > maxVal) {
            	maxVal = eachResult[j];
            	valPos = j;
            }
        }
    	for (j = valPos ; j< RUN_TIME -1 ; ++j) {
        	eachResult[j] = eachResult[j + 1] ;
        }

        /* remove eachResult min value */
    	minVal = eachResult[0];
    	valPos = 0;
    	for (j = 1 ; j< RUN_TIME -1 ; ++j) {
        	if (eachResult[j] < minVal) {
            	minVal = eachResult[j];
            	valPos = j;
            }
        }
    	for (j = valPos ; j< RUN_TIME -2 ; ++j) {
        	eachResult[j] = eachResult[j + 1] ;
        }
        
        /* calc average value */
    	maxVal = 0;
    	for (j = 0 ; j< RUN_TIME -2 ; ++j) {
        	maxVal += eachResult[j];
        }
    	printf("----------------- average ------         (%.2f)\n", (float)maxVal /(RUN_TIME -2));
    	printf("\n");    
    }
}

/*copy variable string*/
#define MAKE_TEST_FUNC(funcName,charType)\
static clock_t funcName##Test(int iFuncType, int loopCnt)\
{\
	charType destBuf[BASIC_STR_LEN];    \
	charType srcBuf[BASIC_STR_LEN];    \
	int i = 0;    \
	unsigned int tmp = 0;    \
	DECLARE_VAR	\
\
	for(i = 0 ; i < BASIC_STR_LEN -1; ++i ) {    \
    	srcBuf[i] = 'a' + (i % 26);    \
    }    \
	srcBuf[ BASIC_STR_LEN -1] = '\0';    \
\
     GET_START_TS	\
     switch(iFuncType)                                 \
    {                                                 \
     case FUNC_TYPE_SYS:                               \
     for(i = 0 ; i < loopCnt; ++i )                    \
     {                                                 \
        destBuf[0] = '\0';                                \
        srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26); \
        funcName(destBuf, srcBuf);                       \
        tmp += destBuf[i % BASIC_STR_LEN];               \
     }                                                 \
     break;                                            \
     case FUNC_TYPE_SECURE_S:                          \
     for(i = 0 ; i < loopCnt; ++i )                    \
     {                                                 \
        destBuf[0] = '\0';                                \
        srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26); \
        funcName##_s(destBuf, BASIC_STR_LEN, srcBuf);    \
        tmp += destBuf[i % BASIC_STR_LEN];               \
     }                                                 \
    break;                                            \
    case FUNC_TYPE_SECURE_SP:                         \
    for(i = 0 ; i < loopCnt; ++i )                    \
    {                                                 \
        destBuf[0] = '\0';                                \
        srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26); \
        funcName##_sp(destBuf, BASIC_STR_LEN, srcBuf);   \
        tmp += destBuf[i % BASIC_STR_LEN];               \
    }                                                 \
    break;                                            \
    }                                                 \
	GET_END_TS	\
	cost_time = CALC_INTERVAL     \
\
	tmp = 0;    \
	GET_START_TS	\
	for(i = 0 ; i < loopCnt; ++i ) {    \
    	destBuf[0] = '\0';    \
    	srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
    	tmp += srcBuf[i % BASIC_STR_LEN];        \
    }    \
	GET_END_TS	\
	cost_time -= CALC_INTERVAL      \
    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    \
    return cost_time;    \
}

#define MAKE_TEST_FUNC_VS_S(funcName,charType) \
static clock_t funcName##Test(int is_secure, int loopCnt)\
{\
	charType destBuf[BASIC_STR_LEN];    \
	charType srcBuf[BASIC_STR_LEN];    \
	int i = 0;    \
	unsigned int tmp = 0;    \
	DECLARE_VAR	\
\
	for(i = 0 ; i < BASIC_STR_LEN -1; ++i ) {    \
    	srcBuf[i] = 'a' + (i % 26);    \
    }    \
	srcBuf[ BASIC_STR_LEN -1] = '\0';    \
\
    GET_START_TS	\
	if (is_secure) {    \
    	for(i = 0 ; i < loopCnt; ++i ) {    \
        	destBuf[0] = '\0';    \
        	srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
        	funcName##_s(destBuf, BASIC_STR_LEN, srcBuf);    \
        	tmp += destBuf[i % BASIC_STR_LEN];        \
        }    \
     }    \
    else {    \
    	for(i = 0 ; i < loopCnt; ++i ) {    \
        	destBuf[0] = '\0';    \
        	srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
        	funcName(destBuf, srcBuf);    \
        	tmp += destBuf[i % BASIC_STR_LEN];        \
        }    \
    }    \
	GET_END_TS	\
	cost_time = CALC_INTERVAL     \
\
	tmp = 0;    \
	GET_START_TS	\
	for(i = 0 ; i < loopCnt; ++i ) {    \
    	destBuf[0] = '\0';    \
    	srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
    	tmp += srcBuf[i % BASIC_STR_LEN];        \
    }    \
	GET_END_TS	\
	cost_time -= CALC_INTERVAL      \
    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    \
    return cost_time;    \
}
/*copy const string*/
#define MAKE_TEST_CONST_FUNC(funcName,charType) \
static clock_t funcName##ConstTest(int iFuncType, int loopCnt)\
{\
	charType destBuf[BASIC_STR_LEN];    \
	int i = 0;    \
	unsigned int tmp = 0;    \
	DECLARE_VAR	\
\
    GET_START_TS	\
    switch(iFuncType)                                        \
{                                                        \
    case FUNC_TYPE_SYS:                                      \
    for(i = 0 ; i < loopCnt; ++i )                           \
{                                                     \
    destBuf[0] = '\0';                                     \
    funcName(destBuf, BASIC_T_STR);                     \
    tmp += destBuf[i % BASIC_STR_LEN];                 \
}                                                        \
    break;                                                   \
    case FUNC_TYPE_SECURE_S:                                 \
    for(i = 0 ; i < loopCnt; ++i )                           \
{                                                     \
    destBuf[0] = '\0';                                     \
    funcName##_s(destBuf, BASIC_STR_LEN, BASIC_T_STR);     \
    tmp += destBuf[i % BASIC_STR_LEN];                 \
}                                                        \
    break;                                                   \
    case FUNC_TYPE_SECURE_SP:                                \
    for(i = 0 ; i < loopCnt; ++i )                           \
{                                                     \
    destBuf[0] = '\0';                                     \
    funcName##_sp(destBuf, BASIC_STR_LEN, BASIC_T_STR);     \
    tmp += destBuf[i % BASIC_STR_LEN];                 \
}                                                        \
    break;                                                   \
}                                                        \
	GET_END_TS	\
	cost_time = CALC_INTERVAL     \
\
	tmp = 0;    \
	GET_START_TS	\
	for(i = 0 ; i < loopCnt; ++i ) {    \
    	destBuf[0] = '\0';    \
    	tmp += destBuf[i % BASIC_STR_LEN];        \
    }    \
	GET_END_TS	\
	cost_time -= CALC_INTERVAL      \
    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    \
    return cost_time;    \
}

#define MAKE_N_TEST_FUNC(funcName,charType) \
static clock_t funcName##Test(int is_secure, int loopCnt) \
{\
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
        	funcName##_s(destBuf, BASIC_STR_LEN, srcBuf, BASIC_STR_LEN - 1);    \
        	tmp += destBuf[i % BASIC_STR_LEN];        \
        }    \
     }    \
    else {    \
    	for(i = 0 ; i < loopCnt; ++i ) {    \
        	destBuf[0] = '\0';    \
        	srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
        	funcName(destBuf, srcBuf, BASIC_STR_LEN - 1);    \
        	tmp += destBuf[i % BASIC_STR_LEN];        \
        }    \
    }    \
\
	GET_END_TS \
	cost_time = CALC_INTERVAL     \
	tmp = 0;    \
	GET_START_TS     \
	for(i = 0 ; i < loopCnt; ++i ) {    \
    	destBuf[0] = '\0';    \
    	srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
    	tmp += srcBuf[i % BASIC_STR_LEN];        \
    }    \
	GET_END_TS	\
	cost_time -= CALC_INTERVAL     \
\
    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    \
    return cost_time;    \
}

#define MAKE_N_TEST_FUNC_VS_S(funcName,charType) \
static clock_t funcName##Test(int is_secure, int loopCnt) \
{\
    \
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
        	funcName##_s(destBuf, BASIC_STR_LEN, srcBuf, BASIC_STR_LEN - 1);    \
        	tmp += destBuf[i % BASIC_STR_LEN];        \
        }    \
     }    \
    else {    \
    	for(i = 0 ; i < loopCnt; ++i ) {    \
        	destBuf[0] = '\0';    \
        	srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
        	funcName(destBuf, srcBuf, BASIC_STR_LEN - 1);    \
        	tmp += destBuf[i % BASIC_STR_LEN];        \
        }    \
    }    \
\
	GET_END_TS \
	cost_time = CALC_INTERVAL     \
	tmp = 0;    \
	GET_START_TS     \
	for(i = 0 ; i < loopCnt; ++i ) {    \
    	destBuf[0] = '\0';    \
    	srcBuf[i % (BASIC_STR_LEN -1)] = 'a' + (i % 26);    \
    	tmp += srcBuf[i % BASIC_STR_LEN];        \
    }    \
	GET_END_TS	\
	cost_time -= CALC_INTERVAL     \
\
    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    \
    return cost_time;    \
}

#define MAKE_N_TEST_CONST_FUNC(funcName,charType) \
static clock_t funcName##ConstTest(int is_secure, int loopCnt) \
{\
	charType destBuf[BASIC_STR_LEN];    \
	int i = 0;    \
     unsigned int tmp = 0;    \
	DECLARE_VAR     \
\
    GET_START_TS     \
	if (is_secure) {    \
    	for(i = 0 ; i < loopCnt; ++i ) {    \
        	destBuf[0] = '\0';    \
        	funcName##_s(destBuf, BASIC_STR_LEN, BASIC_T_STR, BASIC_STR_LEN - 1);    \
        	tmp += destBuf[i % BASIC_STR_LEN];        \
        }    \
     }    \
    else {    \
    	for(i = 0 ; i < loopCnt; ++i ) {    \
        	destBuf[0] = '\0';    \
        	funcName(destBuf, BASIC_T_STR, BASIC_STR_LEN - 1);    \
        	tmp += destBuf[i % BASIC_STR_LEN];        \
        }    \
    }    \
\
	GET_END_TS \
	cost_time = CALC_INTERVAL     \
	tmp = 0;    \
	GET_START_TS     \
	for(i = 0 ; i < loopCnt; ++i ) {    \
    	destBuf[0] = '\0';    \
    	tmp += destBuf[i % BASIC_STR_LEN];        \
    }    \
	GET_END_TS	\
	cost_time -= CALC_INTERVAL     \
\
    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    \
    return cost_time;    \
}

#define MAKE_PERFORMANCE_FUNC(funcName) \
static void funcName##PerformanceTest(void)       \
{   \
    clock_t cost_time[SAMPLE_NUMBER]   = {0};    \
    clock_t cost_time_s[SAMPLE_NUMBER] = {0};    \
    clock_t cost_time_sp[SAMPLE_NUMBER] = {0};    \
	int loopCnt[RUN_TIME];    \
    int i, j = 0;    \
	clock_t avg, avg_s,avg_sp;    \
\
	loopCnt[0] =  50 * 10000;    \
	loopCnt[1] = 100 * 10000;    \
	for (i = 2 ; i< RUN_TIME ; ++i) {    \
    	loopCnt[i] = loopCnt[i -1] + 100 * 10000;    \
    }    \
\
	printf("               "#funcName":       "#funcName"_s(_s/sys):      "#funcName"_sp(sp/sys,sp/_s):     in variable mode\n");    \
	for (j = 0 ; j< RUN_TIME ; ++j) {    \
    	for(i = 0; i < SAMPLE_NUMBER; i++) {    \
        	cost_time[i] = funcName##Test(FUNC_TYPE_SYS, j == 0 ? 10*10000 : loopCnt[j]);    \
        	if (j > 0 && 0 >= (long)cost_time[i]) {    \
                --i;    \
            	continue;    \
            }    \
        }    \
\
    	for(i = 0; i < SAMPLE_NUMBER; i++) {    \
        	cost_time_s[i] = funcName##Test(FUNC_TYPE_SECURE_S, j == 0 ? 10*10000 :loopCnt[j]);    \
        	if (j > 0 && 0 >= (long)cost_time_s[i]) {    \
                --i;    \
            	continue;    \
            }    \
        }    \
        for(i = 0; i < SAMPLE_NUMBER; i++) {    \
        cost_time_sp[i] = funcName##Test(FUNC_TYPE_SECURE_SP, j == 0 ? 10*10000 :loopCnt[j]);    \
        if (j > 0 && 0 >= (long)cost_time_sp[i]) {    \
                --i;    \
                continue;    \
            }    \
        }    \
    	avg = CalcAvg(cost_time+1, SAMPLE_NUMBER - 1)/ 1000;    \
    	avg_s = CalcAvg(cost_time_s+1, SAMPLE_NUMBER - 1)/ 1000;    \
        avg_sp = CalcAvg(cost_time_sp+1, SAMPLE_NUMBER - 1)/ 1000;    \
        printf("loop:%7d, %6ldms %6ldms(%.2f) %6ldms(%.2f,%.2f) \n",\
        loopCnt[j], avg , avg_s, (0==avg)?(float)avg_s:((float)avg_s / avg), avg_sp, (0==avg)?(float)avg_sp:((float)avg_sp / avg), (float)avg_sp /avg_s);\
    }    \
    printf("\n");    \
}

#define MAKE_PERFORMANCE_CONST_FUNC(funcName) \
static void funcName##ConstPerformanceTest(void)       \
{   \
    clock_t cost_time[SAMPLE_NUMBER]   = {0};    \
    clock_t cost_time_s[SAMPLE_NUMBER] = {0};    \
    clock_t cost_time_sp[SAMPLE_NUMBER] = {0};    \
	int loopCnt[RUN_TIME];    \
    int i, j = 0;    \
	clock_t avg, avg_s, avg_sp;    \
\
	loopCnt[0] =  50 * 10000;    \
	loopCnt[1] = 100 * 10000;    \
	for (i = 2 ; i< RUN_TIME ; ++i) {    \
    	loopCnt[i] = loopCnt[i -1] + 100 * 10000;    \
    }    \
\
	printf("               "#funcName":       "#funcName"_s(_s/sys):      "#funcName"_sp(sp/sys,sp/_s):       in const mode\n");    \
	for (j = 0 ; j< RUN_TIME ; ++j) {    \
    	for(i = 0; i < SAMPLE_NUMBER; i++) {    \
        	cost_time[i] = funcName##ConstTest(FUNC_TYPE_SYS, j == 0 ? 10*10000 : loopCnt[j]);    \
        	if (j > 0 && 0 >= (long)cost_time[i]) {    \
                --i;    \
            	continue;    \
            }    \
        }    \
    	for(i = 0; i < SAMPLE_NUMBER; i++) {    \
        	cost_time_s[i] = funcName##ConstTest(FUNC_TYPE_SECURE_S, j == 0 ? 10*10000 :loopCnt[j]);    \
        	if (j > 0 && 0 >= (long)cost_time_s[i]) {    \
                --i;    \
            	continue;    \
            }    \
        }    \
        for(i = 0; i < SAMPLE_NUMBER; i++) {    \
            cost_time_sp[i] = funcName##ConstTest(FUNC_TYPE_SECURE_SP, j == 0 ? 10*10000 :loopCnt[j]);    \
            if (j > 0 && 0 >= (long)cost_time_sp[i]) {    \
                --i;    \
                continue;    \
            }    \
        }    \
    	avg = CalcAvg(cost_time+1, SAMPLE_NUMBER - 1)/ 1000;    \
    	avg_s = CalcAvg(cost_time_s+1, SAMPLE_NUMBER - 1)/ 1000;    \
        avg_sp = CalcAvg(cost_time_sp+1, SAMPLE_NUMBER - 1)/ 1000;    \
        printf("loop:%7d, %6ldms %6ldms(%.2f) %6ldms(%.2f,%.2f) \n",\
        loopCnt[j], avg , avg_s, (0==avg)?(float)avg_s:((float)avg_s / avg), avg_sp, (0==avg)?(float)avg_sp:((float)avg_sp / avg), (float)avg_sp /avg_s);\
    }    \
    printf("\n");    \
}

#ifdef WITH_PERFORMANCE_ADDONS
/* for strcpy */
MAKE_TEST_FUNC(strcpy, char)
MAKE_PERFORMANCE_FUNC(strcpy)

MAKE_TEST_CONST_FUNC(strcpy, char)
MAKE_PERFORMANCE_CONST_FUNC(strcpy)

/* for strcat */
MAKE_TEST_FUNC(strcat, char)
MAKE_PERFORMANCE_FUNC(strcat)

MAKE_TEST_CONST_FUNC(strcat, char)
MAKE_PERFORMANCE_CONST_FUNC(strcat)

/* for strncpy */
MAKE_N_TEST_FUNC(strncpy, char)
MAKE_PERFORMANCE_FUNC(strncpy)

MAKE_N_TEST_CONST_FUNC(strncpy, char)
MAKE_PERFORMANCE_CONST_FUNC(strncpy)

/* for strncat */
MAKE_N_TEST_FUNC(strncat, char)
MAKE_PERFORMANCE_FUNC(strncat)

MAKE_N_TEST_CONST_FUNC(strncat, char)
MAKE_PERFORMANCE_CONST_FUNC(strncat)
#endif

/*Testing wide character function*/
#ifndef SECUREC_VXWORKS_PLATFORM
MAKE_TEST_FUNC_VS_S(wcscpy, wchar_t)
MAKE_PERFORMANCE_FUNC(wcscpy)

MAKE_TEST_FUNC_VS_S(wcscat, wchar_t)
MAKE_PERFORMANCE_FUNC(wcscat)

MAKE_N_TEST_FUNC_VS_S(wcsncpy, wchar_t)
MAKE_PERFORMANCE_FUNC(wcsncpy)

MAKE_N_TEST_FUNC_VS_S(wcsncat, wchar_t)
MAKE_PERFORMANCE_FUNC(wcsncat)
#endif

#define BUF_SIZE 5400
static char destBuf[BUF_SIZE];
static char srcBuf[BUF_SIZE];


static void shuffleData(char* a, int n)
{
    static int runCnt = 0;
    int i =0;
    ++runCnt;
    runCnt += rand();
    /*	srand(runCnt + a[0]); */

    for (i = 0; i <( n >> 4); i+= 4) {
        a[i] += runCnt;
    }
}

static void sortData(char* a, int n)
{
	static int runCnts = 0;
/*	int i, j, index; 
	char value;
    */
    ++runCnts;

	a[ runCnts % n] += runCnts;
    /*
    for (i = 0; i < n - 1; i ++) {
        index = i;
        value = a[i];
    	for (j = i + 1; j < n; j ++) {
            if (value > a[j]) {
                index = j;
                value = a[j];
            }
        }
        a[index] = a[i];
        a[i] = value;
    }
    */
}

#ifdef TEST_MEMCPY_BENCHMARK
void fooCalc1 (int* outVal) 
{
 int v = 12 + 1;
MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc2 (int* outVal) 
{
 int v = 12 + 2;
MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc3 (int* outVal) 
{
 int v = 12 + 3;
MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc4 (int* outVal) 
{
 int v = 12 + 4;
MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc5 (int* outVal) 
{
 int v = 12 + 5;
MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc6 (int* outVal) 
{
 int v = 12 + 6;
MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc7 (int* outVal) 
{
 int v = 12 + 7;
MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc8 (int* outVal) 
{
 int v = 12 + 8;
MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET1V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET1(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY1V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc9 (int* outVal) 
{
 int v = 12 + 9;
(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc10 (int* outVal) 
{
 int v = 12 + 10;
(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc11 (int* outVal) 
{
 int v = 12 + 11;
(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc12 (int* outVal) 
{
 int v = 12 + 12;
(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc13 (int* outVal) 
{
 int v = 12 + 13;
(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc14 (int* outVal) 
{
 int v = 12 + 14;
(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc15 (int* outVal) 
{
 int v = 12 + 15;
(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc16 (int* outVal) 
{
 int v = 12 + 16;
(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

(void)MEMSET2V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

(void)MEMSET2(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY2V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc17 (int* outVal) 
{
 int v = 12 + 17;
MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc18 (int* outVal) 
{
 int v = 12 + 18;
MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc19 (int* outVal) 
{
 int v = 12 + 19;
MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc20 (int* outVal) 
{
 int v = 12 + 20;
MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc21 (int* outVal) 
{
 int v = 12 + 21;
MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc22 (int* outVal) 
{
 int v = 12 + 22;
MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc23 (int* outVal) 
{
 int v = 12 + 23;
MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
void fooCalc24 (int* outVal) 
{
 int v = 12 + 24;
MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 32);
v += destBuf[ (1 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (2 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 96);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (3 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 128);
v += destBuf[ (4 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (5 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (6 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (7 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 256);
v += destBuf[ (8 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 288);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (9 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (10 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 352);
v += destBuf[ (11 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (12 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 416);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (13 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (14 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (15 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 512);
v += destBuf[ (16 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 544);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 544);
v += destBuf[ (17 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (18 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 608);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 608);
v += destBuf[ (19 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (20 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (21 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 704);
v += destBuf[ (22 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 736);
v += destBuf[ (23 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (24 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (25 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (26 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 864);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (27 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (28 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 928);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (29 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (30 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 992);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 992);
v += destBuf[ (31 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1024);
v += destBuf[ (32 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (33 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1088);
v += destBuf[ (34 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (35 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (36 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1184);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1184);
v += destBuf[ (37 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1216);
v += destBuf[ (38 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1248);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (39 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (40 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1312);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1312);
v += destBuf[ (41 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (42 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1376);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1376);
v += destBuf[ (43 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1408);
v += destBuf[ (44 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (45 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1472);
v += destBuf[ (46 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1504);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1504);
v += destBuf[ (47 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (48 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (49 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (50 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1632);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (51 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (52 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1696);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1696);
v += destBuf[ (53 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (54 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (55 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (56 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1824);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (57 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (58 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1888);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1888);
v += destBuf[ (59 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (60 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1952);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1952);
v += destBuf[ (61 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1984);
v += destBuf[ (62 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (63 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2048);
v += destBuf[ (64 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (65 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (66 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2144);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2144);
v += destBuf[ (67 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2176);
v += destBuf[ (68 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 511);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (69 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (70 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2272);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2272);
v += destBuf[ (71 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (72 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2336);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2336);
v += destBuf[ (73 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2368);
v += destBuf[ (74 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (75 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2432);
v += destBuf[ (76 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (77 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (78 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2528);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2528);
v += destBuf[ (79 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (80 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2592);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (81 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2624);
v += destBuf[ (82 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2656);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2656);
v += destBuf[ (83 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (84 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (85 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2752);
v += destBuf[ (86 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2784);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (87 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2816);
v += destBuf[ (88 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2848);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2848);
v += destBuf[ (89 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (90 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (91 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 2944);
v += destBuf[ (92 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 2976);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (93 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3008);
v += destBuf[ (94 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (95 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (96 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3104);
v += destBuf[ (97 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (98 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (99 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (100 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3232);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3232);
v += destBuf[ (101 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (102 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3296);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3296);
v += destBuf[ (103 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (104 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (105 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3392);
v += destBuf[ (106 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3424);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3424);
v += destBuf[ (107 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (108 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3488);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3488);
v += destBuf[ (109 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (110 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3552);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (111 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (112 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3616);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3616);
v += destBuf[ (113 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (114 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (115 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 125);
v += destBuf[ (116 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3744);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (117 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3776);
v += destBuf[ (118 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (119 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (120 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3872);
v += destBuf[ (121 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3904);
v += destBuf[ (122 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 3936);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (123 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 3968);
v += destBuf[ (124 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (125 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (126 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4064);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4064);
v += destBuf[ (127 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4096);
v += destBuf[ (128 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4128);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (129 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (130 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4192);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4192);
v += destBuf[ (131 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (132 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (133 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4288);
v += destBuf[ (134 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (135 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4352);
v += destBuf[ (136 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4384);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4384);
v += destBuf[ (137 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (138 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4448);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4448);
v += destBuf[ (139 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (140 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4512);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (141 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4544);
v += destBuf[ (142 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (143 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (144 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (145 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4672);
v += destBuf[ (146 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (147 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4736);
v += destBuf[ (148 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4768);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4768);
v += destBuf[ (149 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (150 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4832);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4832);
v += destBuf[ (151 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 4864);
v += destBuf[ (152 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 4896);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (153 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (154 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (155 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (156 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 24);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 24);
v += destBuf[ (157 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 56);
v += destBuf[ (158 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 88);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (159 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (160 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (161 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (162 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 216);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 216);
v += destBuf[ (163 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 248);
v += destBuf[ (164 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (165 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 312);
v += destBuf[ (166 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 344);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 344);
v += destBuf[ (167 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (168 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 408);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 97);
v += destBuf[ (169 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (170 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 472);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (171 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 504);
v += destBuf[ (172 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 536);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 536);
v += destBuf[ (173 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (174 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (175 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 632);
v += destBuf[ (176 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 664);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (177 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 696);
v += destBuf[ (178 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 728);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 728);
v += destBuf[ (179 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (180 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 792);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 792);
v += destBuf[ (181 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (182 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 856);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (183 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 888);
v += destBuf[ (184 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (185 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (186 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 85);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 984);
v += destBuf[ (187 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1016);
v += destBuf[ (188 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 48);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (189 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (190 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1112);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1112);
v += destBuf[ (191 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (192 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1176);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1176);
v += destBuf[ (193 + rand() ) % BUF_SIZE];

MEMSET3V(srcBuf, BUF_SIZE, rand(), (unsigned int)v % BUF_SIZE);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1208);
v += destBuf[ (194 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 32);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (195 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 48);
v += destBuf[ (196 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1304);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1304);
v += destBuf[ (197 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 64);
v += destBuf[ (198 + rand() ) % BUF_SIZE];

MEMSET3(srcBuf, BUF_SIZE, 0, 1368);
shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3(destBuf, BUF_SIZE, srcBuf, 1368);
v += destBuf[ (199 + rand() ) % BUF_SIZE];

shuffleData(srcBuf, BUF_SIZE);
sortData(srcBuf, BUF_SIZE);
MEMCPY3V(destBuf, BUF_SIZE, srcBuf, (unsigned int)v % BUF_SIZE);
v += destBuf[ (200 + rand() ) % BUF_SIZE];

*outVal = v;
}
#endif


#define GEN_FIX_LEN_CMP_FUNC(loop, FIX_LEN)\
long memcpyFixLenPerfTest##FIX_LEN( int loopCnt)\
{\
	static char srcBuf[LARGE_MEM_LEN];    \
	int i = 0;    \
	unsigned int tmp = 0;    \
	char* pDest = NULL;\
	int iFuncType = 0;\
	clock_t baseVal = 0;\
	DECLARE_VAR     \
	loopCnt = loop;\
\
	for(i = 0 ; i < LARGE_MEM_LEN -1; ++i ) {\
    	srcBuf[i] = 'a' + (i % 26);    \
    }    \
	srcBuf[ LARGE_MEM_LEN -1] = '\0';    \
	printf("loop:%7d FixLen: %4d |",loopCnt, FIX_LEN);\
    GET_START_TS     \
	do{\
    	switch(iFuncType) {\
    	case 0:\
        	for(i = 0 ; i < loopCnt; ++i ) {    \
            	srcBuf[i % (LARGE_MEM_LEN -1)] = 'a' + (i % 26);    \
            	pDest = i % 20 == 0 ? (destBuf + i % 512) : destBuf;\
            	memcpy(pDest, srcBuf, FIX_LEN );    \
            	tmp += destBuf[i % BUF_SIZE];        \
            }\
        	break;\
        \
    	case 1:\
        	for(i = 0 ; i < loopCnt; ++i ) {    \
            	srcBuf[i % (LARGE_MEM_LEN -1)] = 'a' + (i % 26);    \
            	pDest = i % 20 == 0 ? (destBuf + i % 512) : destBuf;\
            	memcpy_s(pDest, LARGE_MEM_LEN, srcBuf, FIX_LEN);    \
            	tmp += destBuf[i % BUF_SIZE];        \
            }\
        	break;\
        \
    	case 2:\
        	for(i = 0 ; i < loopCnt; ++i ) {    \
            	srcBuf[i % (LARGE_MEM_LEN -1)] = 'a' + (i % 26);\
            	pDest = i % 20 == 0 ? (destBuf + i % 512) : destBuf;\
            	memcpy_sp(pDest, LARGE_MEM_LEN, srcBuf, FIX_LEN);    \
            	tmp += destBuf[i % BUF_SIZE];        \
            }\
        	break;\
    	case 3:\
        	for(i = 0 ; i < loopCnt; ++i ) {    \
            	srcBuf[i % (LARGE_MEM_LEN -1)] = 'a' + (i % 26);\
            	pDest = i % 20 == 0 ? (destBuf + i % 512) : destBuf;\
            	memcpy_sp(pDest, LARGE_MEM_LEN, srcBuf, FIX_LEN);    \
             	tmp += destBuf[i % BUF_SIZE];        \
            }\
        	break;\
        }\
    	GET_END_TS \
    	cost_time = CALC_INTERVAL     \
/*    	GET_START_TS     \
    	for(i = 0 ; i < loopCnt; ++i ) {\
        	srcBuf[i % (LARGE_MEM_LEN -1)] = 'a' + (i % 26);    \
        	tmp += srcBuf[i % LARGE_MEM_LEN];        \
        }\
    	GET_END_TS\
    	cost_time -= CALC_INTERVAL \  */   \
    	if (0 == iFuncType) {\
        	baseVal = cost_time;\
        	printf(" %dms", (int)cost_time );\
        }else {\
        	printf(" %dms(%.2f)", (int)cost_time, (float)cost_time /baseVal );\
        }\
        ++iFuncType;\
    }while(iFuncType < 4);\
\
	printf("\r\n");\
    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    \
    return cost_time;    \
}

#if defined(WITH_PERFORMANCE_ADDONS) 
GEN_FIX_LEN_CMP_FUNC(3000000, 32)
GEN_FIX_LEN_CMP_FUNC(3000000, 48)
GEN_FIX_LEN_CMP_FUNC(3000000, 64)
GEN_FIX_LEN_CMP_FUNC(3000000, 128)
GEN_FIX_LEN_CMP_FUNC(3000000, 197)
GEN_FIX_LEN_CMP_FUNC(3000000, 256)
GEN_FIX_LEN_CMP_FUNC(3000000, 512)
GEN_FIX_LEN_CMP_FUNC(3000000, 1024)
#endif

extern int sprintf_sOld (char* strDest, size_t destMax, const char* format, ...);
#define  MAX_SPRBUF_LEN  1024

static char szBuf1[MAX_SPRBUF_LEN]; //avoid gcc optimization
static char szBuf2[MAX_SPRBUF_LEN];

#define FMT_CNT 7
#define FMT_STR_LEN 30
    
#ifdef WIN32
static unsigned __int64 n64AddrRange[15][2] = 
{
    {0,                 0},
    {0,                 9},
    {10,                99},
    {100,               999},
    {1000,              9999},
    {10000,             99999},
    {100000,            999999},
    {1000000,           9999999},
    {10000000,          99999999},
    {100000000,         999999999},
    {1000000000,        9999999999},
    {10000000000,       99999999999},
    {100000000000,      999999999999},
    {1000000000000,     9999999999999},
    {10000000000000,    99999999999999}}
;
#else
static unsigned long long n64AddrRange[15][2] = 
{
    {0,                 0},
    {0,                 9},
    {10,                99},
    {100,               999},
    {1000,              9999},
    {10000,             99999},
    {100000,            999999},
    {1000000,           9999999},
    {10000000,          99999999},
    {100000000,         999999999},
    {1000000000LL,      9999999999LL},
    {10000000000LL,     99999999999LL},
    {100000000000LL,    999999999999LL},
    {1000000000000LL,   9999999999999LL},
    {10000000000000LL,  99999999999999LL}
};
#endif

static void sprintf_test(int nMaxLoopCount)
{
	int i, j, n, k;
	clock_t  tClock2, tClock3, tClock4;
    DECLARE_VAR
	const char *szFormat[FMT_CNT] = { "%c", "%d", "%u",  "%x", "%p", "%o", "%f"};
    /*const char chFormat[FMT_CNT]  = { 'c', 'd', 'u',  'x', 'p', 'o', 'f'};*/
	char szNumTable[32][28] =
    {
        "8613900000000",
            "8613900000001",
            "8613900000002",
            "8613900000003",
            "8613900000003",
            "8613900000004",
            "8613900000005",
            "86139000000068613900000006",
            "86139000000078613900000007",
            "86139000000088613900000008",
            "86139000000098613900000009",
            "10086",
            "100860",
            "100861",
            "100862",
            "100863",
            "100864",
            "100865",
            "100866",
            "100867",
            "100868",
            "100869",
            "1008610",
            "861380000001",
            "861380000002",
            "861380000003",
            "861380000004",
            "861380000005",
            "861380000006",
            "861380000007",
            "861380000008",
            "861380000009",
    };

int jj = 0;
size_t nVal = 0;

	memset(szBuf1, 0, MAX_SPRBUF_LEN);
	memset(szBuf2, 0, MAX_SPRBUF_LEN);

#ifdef TEST_LLU
	GET_START_TS
	for( n = 0; n < nMaxLoopCount; n++)
    {
    	for ( i = 0; i < 15; i++)
        {
        	for( j = 0; j < 2; j++)
            {
            	sprintf_s(szBuf2, MAX_SPRBUF_LEN, "%llu", n64AddrRange[i][j]);
            }
        }
    }
    GET_END_TS
    tClock2 =  CALC_INTERVAL 

    GET_START_TS
    for( n = 0; n < nMaxLoopCount; n++)
    {
    	for ( i = 0; i < 15; i++)
        {
        	for( j = 0; j < 2; j++)
            {
#               ifdef WIN32
            	sprintf(szBuf1, "%I64u", n64AddrRange[i][j]);
#               else
            	sprintf(szBuf1, "%llu",  n64AddrRange[i][j]);
#               endif
            }
        }
    }

    GET_END_TS
    tClock3 =  CALC_INTERVAL 
	printf("%%llu: sprintf_s = %u(%.2f), sprintf = %u\n", tClock2, (float)tClock2 / tClock3, tClock3);
#endif /*END TEST_LLU*/
    
	for( k = 0; k < FMT_CNT; k++)
    {
        GET_START_TS
    	for( n = 0; n < nMaxLoopCount; n++)
        {    
        	for(i = 0; i < 2; i ++)
            {
            	for( j = 0; j < 32; j++ )
                {
                	nVal = (size_t)n64AddrRange[ j % 15][i]; /*i ? -1 : 1;*/
                	sprintf_s(szBuf2, MAX_SPRBUF_LEN, szFormat[k], nVal);
                    jj += szBuf2[2];
                }
            }
        }
    	GET_END_TS
        tClock2 =  CALC_INTERVAL  /* tClock2 = clock(); */
        
         GET_START_TS
    	for( n = 0; n < nMaxLoopCount; n++)
        {    
        	for(i  = 0; i < 2; i ++)
            {
            	for( j = 0; j < 32; j++ )
                {
                    nVal = (size_t)n64AddrRange[ j % 15][i];
                	sprintf(szBuf1, szFormat[k], nVal);
                    jj += szBuf1[2];
                    
                }
            }
        }
        GET_END_TS
        tClock3 =  CALC_INTERVAL   /*tClock3 = clock();*/
        
        GET_START_TS
        for( n = 0; n < nMaxLoopCount; n++)
        {    
        	for(i = 0; i < 2; i ++)
            {
            	for( j = 0; j < 32; j++ )
                {
                    nVal = (size_t)n64AddrRange[ j % 15][i];
                	sprintf_sOld(szBuf2, MAX_SPRBUF_LEN, szFormat[k], nVal);
                    jj += szBuf2[2];
                }
            }
        }
        
        GET_END_TS
        tClock4 =  CALC_INTERVAL   /* tClock4 = clock(); */

    	printf("%s: sprintf_s = %u(%.2f), sprintf = %u, old_sprintf = %u(%.2f)\n", szFormat[k],
            tClock2, (float)tClock2 / tClock3,
            tClock3,
            tClock4, (float)tClock4 / tClock3
            );
    }

	GET_START_TS 
	for( n = 0; n < nMaxLoopCount; n++)
    {    
    	for(i  = 0; i < 32; i ++)
        {    
        	sprintf_s(szBuf2, MAX_SPRBUF_LEN, "%s", szNumTable[i]);
            jj += szBuf2[ i % 16];
        }
    }
	GET_END_TS
    tClock2 =  CALC_INTERVAL   
    
    GET_START_TS
	for( n = 0; n < nMaxLoopCount; n++)
    {    
    	for(i  = 0; i < 32; i ++)
        {
        	sprintf(szBuf1,"%s", szNumTable[i]);
            jj += szBuf1[ i % 16];
        }
    }
	GET_END_TS
    tClock3 =  CALC_INTERVAL  

    GET_START_TS
    for( n = 0; n < nMaxLoopCount; n++)
    {    
    	for(i  = 0; i < 32; i ++)
        {    
        	sprintf_sOld(szBuf2, MAX_SPRBUF_LEN, "%s", szNumTable[i]);
            jj += szBuf2[ i % 16];
        }
    }
    
	GET_END_TS
    tClock4 =  CALC_INTERVAL  /* tClock4 = clock(); */

	printf("%%s: sprintf_s = %8u(%.2f), sprintf = %8u , old_sprintf = %8u(%.2f)\n", 
            tClock2, (float)tClock2 / tClock3,
            tClock3,
            tClock4, (float)tClock4 / tClock3);

/*test %s again */
    GET_START_TS 
	for( n = 0; n < nMaxLoopCount; n++)
    {    
    	for(i  = 0; i < 32; i ++)
        {    
        	sprintf_s(szBuf2, MAX_SPRBUF_LEN, "ab %s", szNumTable[i]);
            jj += szBuf2[ i % 8];
        }
    }
	GET_END_TS
    tClock2 =  CALC_INTERVAL   
    
    GET_START_TS
	for( n = 0; n < nMaxLoopCount; n++)
    {    
    	for(i  = 0; i < 32; i ++)
        {
        	sprintf(szBuf1,"ab %s", szNumTable[i]);
            jj += szBuf1[ i % 8];
        }
    }
	GET_END_TS
    tClock3 =  CALC_INTERVAL  

    GET_START_TS
    for( n = 0; n < nMaxLoopCount; n++)
    {    
    	for(i  = 0; i < 32; i ++)
        {    
        	sprintf_sOld(szBuf2, MAX_SPRBUF_LEN, "ab %s", szNumTable[i]);
            jj += szBuf2[ i % 8];
        }
    }
    
	GET_END_TS
    tClock4 =  CALC_INTERVAL  /* tClock4 = clock(); */

	printf("\"ab %%s\": sprintf_s = %8u(%.2f), sprintf = %8u , old_sprintf = %8u(%.2f)\n", 
            tClock2, (float)tClock2 / tClock3,
            tClock3,
            tClock4, (float)tClock4 / tClock3);

    /* const string */
   GET_START_TS 
	for( n = 0; n < nMaxLoopCount; n++)
    {    
    	for(i  = 0; i < 32; i ++)
        {    
        	sprintf_s(szBuf2, MAX_SPRBUF_LEN, "abcd%defghijklmnopqrstuvwxyz123", i);
            jj += szBuf2[ i % 8];
        }
    }
	GET_END_TS
    tClock2 =  CALC_INTERVAL   
    
    GET_START_TS
	for( n = 0; n < nMaxLoopCount; n++)
    {    
    	for(i  = 0; i < 32; i ++)
        {
        	sprintf(szBuf1,"abcd%defghijklmnopqrstuvwxyz123", i);
            jj += szBuf1[ i % 8];
        }
    }
	GET_END_TS
    tClock3 =  CALC_INTERVAL  

    GET_START_TS
    for( n = 0; n < nMaxLoopCount; n++)
    {    
    	for(i  = 0; i < 32; i ++)
        {    
        	sprintf_sOld(szBuf2, MAX_SPRBUF_LEN, "abcd%defghijklmnopqrstuvwxyz123", i);
            jj += szBuf2[ i % 8];
        }
    }
    
	GET_END_TS
    tClock4 =  CALC_INTERVAL  /* tClock4 = clock(); */

	printf("\"abcd%%defghijklmnopqrstuvwxyz123\": sprintf_s = %8u(%.2f), sprintf = %8u , old_sprintf = %8u(%.2f)\n", 
            tClock2, (float)tClock2 / tClock3,
            tClock3,
            tClock4, (float)tClock4 / tClock3);

	printf("sprintf_test LOOP_COUNT = %u finish.\n", nMaxLoopCount);
    printf("rand = %d  %d\n", j, jj);
}

#define PRINTF_FUNC_TYPEF_S 1
#define PRINTF_FUNC_TYPEF_SYS 2
#define PRINTF_FUNC_TYPEF_S_OLD 3

static clock_t sprintfPerfTest1121(int funcId, int loopCnt) 
{
    char destBuf[FMT_STR_LEN + 50];    
    char srcBuf[FMT_STR_LEN];    
    int i = 0;    
    unsigned int tmp = 0;    
    DECLARE_VAR;   

    for(i = 0 ; i < FMT_STR_LEN -1; ++i ) {    
        srcBuf[i] = 'a' + (i % 26);    
    }
    srcBuf[i] = '\0';    

    GET_START_TS;
    switch (funcId)
    {
    case PRINTF_FUNC_TYPEF_SYS:
        for(i = 0 ; i < loopCnt; ++i ) {    
            srcBuf[i % (FMT_STR_LEN -1)] = 'a' + (i % 26);    
            sprintf(destBuf, "err:%d %% %s\n", i, srcBuf);    
            tmp += destBuf[i % FMT_STR_LEN];        
        }
    	break;
    case PRINTF_FUNC_TYPEF_S:
        for(i = 0 ; i < loopCnt; ++i ) {    
            srcBuf[i % (FMT_STR_LEN -1)] = 'a' + (i % 26);    
            (void)sprintf_s(destBuf, FMT_STR_LEN + 50, "err:%d %% %s\n", i, srcBuf);    
            tmp += destBuf[i % FMT_STR_LEN];        
        } 
        break;
    case PRINTF_FUNC_TYPEF_S_OLD:
        for(i = 0 ; i < loopCnt; ++i ) {    
            srcBuf[i % (FMT_STR_LEN -1)] = 'a' + (i % 26);    
            (void)sprintf_sOld(destBuf, FMT_STR_LEN + 50, "err:%d %% %s\n", i, srcBuf);    
            tmp += destBuf[i % FMT_STR_LEN];        
        }
        break;
    }
    GET_END_TS;   
    cost_time = CALC_INTERVAL;    

    GET_START_TS;    
    for(i = 0 ; i < loopCnt; ++i ) {    
        destBuf[0] = '\0';    
        srcBuf[i % (FMT_STR_LEN -1)] = 'a' + (i % 26);    
        tmp += srcBuf[i % FMT_STR_LEN];        
    }    
    GET_END_TS;    
    cost_time -= CALC_INTERVAL;      
    *(volatile int*)(&tmp) = *(volatile int*)(&tmp);    
    return cost_time;    
}

static void sprintfPerformanceTest1121(void)       
{   
    clock_t cost_time[SAMPLE_NUMBER]   = {0};    
    clock_t cost_time_s[SAMPLE_NUMBER] = {0};    
    clock_t cost_time_old[SAMPLE_NUMBER] = {0};    

    int loopCnt[RUN_TIME];    
    int i, j = 0;    
    clock_t avg, avg_s, avg_old;    

    loopCnt[0] =   100000;    
    loopCnt[1] =   200000;    
    for (i = 2 ; i< RUN_TIME ; ++i) {    
        loopCnt[i] = loopCnt[i -1] + 100000;    
    }    

    printf(" sprintf vs sprintf_s vs old_sprintf_s with format \"err:%%d %%%% %%s\n\"\n");    
    for (j = 0 ; j< RUN_TIME ; ++j) {    
        for(i = 0; i < SAMPLE_NUMBER; i++) {    
            cost_time[i] = sprintfPerfTest1121(PRINTF_FUNC_TYPEF_SYS, j == 0 ? 10*10000 : loopCnt[j]);    
            if (j > 0 && 0 >= (long)cost_time[i]) {    
                --i;    
                continue;    
            }    
        }    

        for(i = 0; i < SAMPLE_NUMBER; i++) {    
            cost_time_s[i] = sprintfPerfTest1121(PRINTF_FUNC_TYPEF_S, j == 0 ? 10*10000 :loopCnt[j]);    
            if (j > 0 && 0 >= (long)cost_time_s[i]) {    
                --i;    
                continue;    
            }    
        }   
        for(i = 0; i < SAMPLE_NUMBER; i++) {    
            cost_time_old[i] = sprintfPerfTest1121(PRINTF_FUNC_TYPEF_S_OLD, j == 0 ? 10*10000 :loopCnt[j]);    
            if (j > 0 && 0 >= (long)cost_time_old[i]) {    
                --i;    
                continue;    
            }    
        }   
        avg = CalcAvg(cost_time+1, SAMPLE_NUMBER - 1)/ 1000;    
        avg_s = CalcAvg(cost_time_s+1, SAMPLE_NUMBER - 1)/ 1000;    
        avg_old = CalcAvg(cost_time_old+1, SAMPLE_NUMBER - 1)/ 1000;   

        printf("loop: %8d, avg: %6ldms  -- %6ldms(%.2f) -- %6ldms(%.2f)  \n",
            loopCnt[j], avg ,
            avg_s, (float)avg_s / avg, 
            avg_old, (float)avg_old / avg  );    
    }    
    printf("\n");    
}

/* total call times 8*200 *625* 80 */
#define LOOPS (625* 80) 

#ifdef PERF_TEST_AS_MAIN
int main(int argc, char* argv[])
#else
int testFuncsPerformance(int argc, char* argv[])
#endif
{
	unsigned char myVal[] = {0x12, 0x34, 0x56, 0x78, 0x91, 0x32, 0x54, 0x76};
	int i = 0;
	int j = 0;
	unsigned short wValue = 0x1234;
	clock_t cost_sys = 0, cost_s = 0,cost_sp = 0;
	char buf[30];
    int testStrFunc = 1;
	DECLARE_VAR

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#if defined(__GNUC_PATCHLEVEL__) 
	printf("GNU C version = %d  %d   %d \n",__GNUC__ , __GNUC_MINOR__ , __GNUC_PATCHLEVEL__ );
#else
	printf("GNU C version = %d  %d   \n",__GNUC__ , __GNUC_MINOR__  );    
#endif
#endif

#ifdef SECUREC_ON_64BITS
	printf("Secure C on 64Bits\n");
#else
	printf("Secure C on 32Bits\n");
#endif

    if (argc > 1) {
        testStrFunc = atoi(argv[1]);
    }
	printf("size_t = %d\n", sizeof(size_t));
    
	printf("memory alignment test\n");

#if !(defined(__hpux))
    i = *(int*)(myVal +1);

    if (*(char*)&wValue == 0x12) {
        printf("Secure C On Big-Endian\n");
        if (i != 0x34567891) {
            printf("!!!!!!!!!!!!!!!!\n you machine need multi bytes value to be aligned!\n!!!!!!!!!!!!");
        }
    }else{
        printf("Secure C On Little-Endian\n");
        if (i != 0x91785634) {
            printf("!!!!!!!!!!!!!!!!\n you machine need multi bytes value to be aligned!\n!!!!!!!!!!!!");
        }
    }
#endif

	printf("memcpy_s on NULL src, ret = %d\n", memcpy_s(myVal, 0, NULL, 12) );
	printf("memset_s on NULL dest, ret = %d\n", memset_s(NULL, 20, 0, 12) );
	printf("ret = %p  %p\n", COMP_MEMCPY(myVal, 6, &wValue, 6), myVal);
    
    if (testStrFunc)
    {
#ifdef WITH_PERFORMANCE_ADDONS
        printf("test str* function at length %d\n", BASIC_STR_LEN);
        /*string function performance test*/
           strcpyConstPerformanceTest();
           strcpyPerformanceTest();

        strcatConstPerformanceTest();
        strcatPerformanceTest();    

        strncpyConstPerformanceTest();
        strncpyPerformanceTest();

        strncatConstPerformanceTest();
        strncatPerformanceTest();


        printf("\n\n");
        memcpyFixLenPerfTest32(10);
        memcpyFixLenPerfTest48(10);
        memcpyFixLenPerfTest64(10);
        memcpyFixLenPerfTest128(10);
        memcpyFixLenPerfTest197(10);
        memcpyFixLenPerfTest256(10);
        memcpyFixLenPerfTest512(10);
        memcpyFixLenPerfTest1024(10);
#endif
    }

    //printf("begin test memcpy and memset ...\n");
	ThreeMemcpyPerformanceTest();
 	ThreeMemsetPerformanceTest(); 
  
    printf("begin test sprintf_s ...\n");
    sprintf_test(5*10000);
    sprintfPerformanceTest1121();

    i = 0;
#ifdef TEST_MEMCPY_BENCHMARK
	printf("begin test memcpy and memset benchmark ...\n");
	fooCalc1 (&i); 
	fooCalc1 (&i); 
    
	GET_START_TS
	for(j = 0; j < LOOPS; ++j) {
    	fooCalc1 (&i); 
    	fooCalc2 (&i); 
    	fooCalc3 (&i); 
    	fooCalc4 (&i); 
    	fooCalc5 (&i); 
    	fooCalc6 (&i); 
    	fooCalc7 (&i); 
    	fooCalc8 (&i); 
    }
	GET_END_TS 
	cost_time = CALC_INTERVAL;
	printf("(memcpy+memset):        %6d \n", (int)cost_time);
	cost_sys = cost_time;

	fooCalc9 (&i); 
	fooCalc10 (&i); 
	i = *(int*)(myVal +1);
	GET_START_TS
	for(j = 0; j < LOOPS; ++j) {
    	fooCalc9 (&i); 
    	fooCalc10 (&i); 
    	fooCalc11 (&i); 
    	fooCalc12 (&i); 
    	fooCalc13 (&i); 
    	fooCalc14 (&i); 
    	fooCalc15 (&i); 
    	fooCalc16 (&i); 
    }
	GET_END_TS 
	cost_time = CALC_INTERVAL;
    cost_s = cost_time;    
	printf("(memcpy_s+memset_s)(_s/sys):%6d(%.4f)\n", (int)cost_s, (float)cost_s / cost_sys);

	fooCalc17 (&i); 
	fooCalc18 (&i); 
	i = *(int*)(myVal +1);
	GET_START_TS
	for(j = 0; j < LOOPS; ++j) {
    	fooCalc17 (&i); 
    	fooCalc18 (&i); 
    	fooCalc19 (&i); 
    	fooCalc20 (&i); 
    	fooCalc21 (&i); 
    	fooCalc22 (&i); 
    	fooCalc23 (&i); 
    	fooCalc24 (&i); 
     }
	GET_END_TS 
	cost_time = CALC_INTERVAL;
    cost_sp = cost_time;
	printf("(memcpy_sp+memset_sp)(sp/sys,sp/_s):%6d(%.4f, %.4f)\r\n", (int)cost_sp, (float)cost_sp / cost_sys,(float)cost_sp / cost_s);
#endif

#ifndef SECUREC_VXWORKS_PLATFORM
    wcscpyPerformanceTest();
    wcsncpyPerformanceTest();
    wcscatPerformanceTest();
    wcsncatPerformanceTest();
#endif
	printf("%d finished!\r\n", i);
    /* analyseBestMaxCopyLen(); */
	return 0;
}

