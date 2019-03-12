/*
memcpytest.c

*/
#include "securec.h"
#include "base_funcs.h"
/*#include <assert.h>*/
#include <string.h>
#include <stdlib.h>
#include <time.h>


#ifndef ULONGLONG
typedef UINT64T ULONGLONG;
#endif



#define FILLED_VAL 0XDC
#define SECURITY_TRUE    1
#define SECURITY_FALSE   0
#define LITTLE_BUF_SIZE  32
#define MB_SIZE          (0x00100000)


void TC_memset_Performance();
void copyInBytes(void* dest, size_t size)
{
    UINT8T* pDest = (UINT8T*)dest;
    while( size--) {
        *(pDest ++) = FILLED_VAL;
    }
}

void copyInWords(void* dest, size_t size)
{
    short* pDest = (short*)dest;
    while( size) {
        *pDest ++ = FILLED_VAL;
        size -= 2;
    }
}

void copyInDwords(void* dest, size_t size)
{
    long* pDest = (long*)dest;
    while( size) {
        *pDest ++ = FILLED_VAL;
        size -= 4;
    }
}

void copyInQwords(void* dest, size_t size)
{
    ULONGLONG* pDest = (ULONGLONG*)dest;
    while( size) {
        *pDest ++ = FILLED_VAL;
        size -= 8;
    }
}



/*gcc -lsecurec -L./lib -Wall t.c */ 

void TestMemcpyPerformance(void)
{
#if 0
    size_t bufSize = 1024 * 1024;
    void* bufPtr = NULL; /*lint !e2*/
    /*unsigned long long startTs = 0;*/
/*    float v1, v2, v3, v4;*/
    const unsigned int MAX_MEM_SIZE = 8 * 1024 * 1024;
    char *src = NULL;
    int loopCnt = 0; /*lint !e2*/

    /*i = sizeof (ULONGLONG);*/

    src = malloc(MAX_MEM_SIZE);
    if (src == NULL){
        return;
    }

/*    QueryPerformanceFrequency(&freq);*/
    printf("\n\nstatistic for copying used time by memcpy, memcpy_s\n");

    for( ; 0 &&  bufSize <= MAX_MEM_SIZE; bufSize *= 2 ) {
/*        bufPtr = malloc(bufSize);
        if (bufPtr == NULL) {
            printf("malloc failed!");
            break;
        }
        getStartTs(&startTs);
        for(loopCnt = 0; loopCnt < 1000; ++ loopCnt) {
            memcpy(bufPtr, src, bufSize);
        }
        v1 = calcTimeElapse(&startTs) ;

        getStartTs(&startTs);
        for(loopCnt = 0; loopCnt < 1000; ++ loopCnt) {
            memcpy_s(bufPtr,bufSize,src, bufSize);
        }
        v2 = calcTimeElapse(&startTs) ;



        getStartTs(&startTs);
        copyInBytes(bufPtr, bufSize);
        v1 = calcTimeElapse(&startTs) ;

        getStartTs(&startTs);
        copyInWords(bufPtr, bufSize);
        v2 = calcTimeElapse(&startTs) ;

        getStartTs(&startTs);
        copyInDwords(bufPtr, bufSize);
        v3 = calcTimeElapse(&startTs) ;

        getStartTs(&startTs);
        copyInQwords(bufPtr, bufSize);
        v4 = calcTimeElapse(&startTs) ;
        printf("%10u mem, copying use %f  %f  %f  %f\n",bufSize, v1, v2, v3, v4);

        printf("%10u mem, copying use %f  %f \n",bufSize, v1, v2);
        free(bufPtr);
*/    
    
    }
#endif
}


