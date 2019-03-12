/*
testutil.c

*/
#include <assert.h>
#include <stddef.h>
#include "testutil.h"

#define EPSINON 0.00001

/**
    verify that the float value is equal to expected value
*/
int assertFloatEqu(float v, float expectedVal)
{
    float  x = v - expectedVal;
    //assert((x >= - EPSINON) && (x <= EPSINON) );
    if(!((x >= - EPSINON) && (x <= EPSINON) ))
    {    
        printf("error\n");
        return -1;
    }
    return 0;
}

/**
    get string length
*/
size_t  slen (const char * str)
{
    const char *eos = str;

    while( *eos++ ) ;

    return( eos - str - 1 );
}

size_t  wslen (const wchar_t * str)
{
    const wchar_t *eos = str;

    while( *eos++ ) ;

    return( eos - str - 1 );
}

int  my_wcscmp (const wchar_t * src, const wchar_t * dst    )
{
    int ret = 0 ;

    while( ! (ret = (int)(*src - *dst)) && *dst)
        ++src, ++dst;

    if ( ret < 0 )
        ret = -1 ;
    else if ( ret > 0 )
        ret = 1 ;

    return( ret );
}

int is64Bits(void)
{
    return sizeof(void*) == 8 ? 1 : 0; /*lint !e506*/
}
int is32Bits(void)
{
    return sizeof(void*) == 4 ? 1 : 0; /*lint !e506*/
}

#ifndef SECUREC_VXWORKS_PLATFORM
UINT64T GetCurMilliSecond(void)
{
#if defined(_WIN32) ||  defined(_WIN64)
    return clock();
#else
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (tv.tv_sec*1000*1000+tv.tv_usec)/1000;
#endif
}
#endif

