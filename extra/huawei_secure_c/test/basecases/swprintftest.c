/******************************************************************************ddd
Author        :
Created       : 2015/2/1
Last Modified :
Description   : test wide 
Function List :

History       :
1.Date        : 2015/2/1
Author      :
Modification: Created file

******************************************************************************/
#include "securec.h"
#include "base_funcs.h"
#include "testutil.h"
#include <locale.h>
#include <assert.h>
#include <wchar.h>

#ifndef SECUREC_VXWORKS_PLATFORM

#ifdef __GNUC__ 

#define CSET_GBK    "GBK" 
#define CSET_UTF8   "UTF-8" 
#define LC_NAME_zh_CN   "zh_CN" 

#elif defined(_MSC_VER) 

#define CSET_GBK    "936" 
#define CSET_UTF8   "65001" 
#define LC_NAME_zh_CN   "Chinese_People's Republic of China" 

#endif 

#define LC_NAME_zh_CN_GBK       LC_NAME_zh_CN "." CSET_GBK 
#define LC_NAME_zh_CN_UTF8      LC_NAME_zh_CN "." CSET_UTF8 

#ifdef __GNUC__ 
#define LC_NAME_zh_CN_DEFAULT   LC_NAME_zh_CN_UTF8 
#elif defined(_MSC_VER) 
#define LC_NAME_zh_CN_DEFAULT   LC_NAME_zh_CN_GBK 
#endif 

extern void assertMeetExpectedStr(const char* formattedStr, const char* expected, unsigned int funcRet, int lineId );

void test_sprintf_s_wString(void)
{
    char buffer[200]={0};
    int iRet = -1;

/*
    iRet = sprintf_s( buffer, 4, "%s", L"111");
    assert(iRet == 3);
    assert(0 == strcmp(buffer, "111") );

    iRet = sprintf_s( buffer, 4, "%hs", L"222");
    assert(iRet == 3);
    assert(0 == strcmp(buffer, "222") );
*/

    iRet = sprintf_s( buffer, 4, "%ls", L"333");
    assert(iRet == 3);
    assert(0 == strcmp(buffer, "333") );

#if(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = sprintf_s( buffer, 4, "%ws", L"444");
    assert(iRet == 3);
    assert(0 == strcmp(buffer, "444") );
#endif

    iRet = sprintf_s( buffer, 4, "%S", L"555");
    assert(iRet == 3);
    assert(0 == strcmp(buffer, "555") );

/*  secure not support
#if!(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = sprintf_s( buffer, 4, "%hS", L"666");
    assert(iRet == 3);
    assert(0 == strcmp(buffer, "666") );
#endif
*/

    iRet = sprintf_s( buffer, 4, "%lS", L"777");
    assert(iRet == 3);
    assert(0 == strcmp(buffer, "777") );

}

void test_swprintf_s_wString(void)
{
    wchar_t wBuf[200]={0};
    char    *string = "computer";
    wchar_t *wstring = L"Unicode";
    int iRet = -1;

#if(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = swprintf_s( wBuf, 4, L"%s", L"111");
    assertMeetExpectedWstr(wBuf, L"111", iRet, __LINE__);
#endif

/*
    iRet = swprintf_s( wBuf, 4, L"%hs", L"222");
    assertMeetExpectedWstr(wBuf, L"222", iRet, __LINE__);
*/

    iRet = swprintf_s( wBuf, 4, L"%ls", L"333");
    assertMeetExpectedWstr(wBuf, L"333", iRet, __LINE__);

#if(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = swprintf_s( wBuf, 4, L"%ws", L"444");
    assertMeetExpectedWstr(wBuf, L"444", iRet, __LINE__);
#endif

/*
#if!(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = swprintf_s( wBuf, 4, L"%S", L"555");
    assertMeetExpectedWstr(wBuf, L"555", iRet, __LINE__);

    iRet = swprintf_s( wBuf, 4, L"%hS", L"666");
    assertMeetExpectedWstr(wBuf, L"666", iRet, __LINE__);
#endif*/

    iRet = swprintf_s( wBuf, 4, L"%lS", L"777");
    assertMeetExpectedWstr(wBuf, L"777", iRet, __LINE__);
}

/*
    iRet = sprintf( buffer, "%c", wc);
    printf("%d,%s\n",iRet,buffer);
    memset(buffer,0,sizeof(buffer));
    iRet = sprintf_s( buffer, 4, "%c", wc);
    printf("%d,%s\n",iRet,buffer);
    
    return;*/

void test_sprintf_s_wchar(void)
{
    char buffer[200]={0};
    int iRet = -1;
    char std[] = "中";
    wchar_t wc = L'中';

    char* oriLocale = NULL;
    char* newLocale = NULL;
    char oldLocal[100] = {0};
    oriLocale = setlocale(LC_ALL, NULL);
    if (oriLocale!=NULL)
    {
        strcpy_s(oldLocal,100,oriLocale);
        oriLocale = oldLocal;
    }
    newLocale = setlocale(LC_ALL, LC_NAME_zh_CN_DEFAULT);
    if(NULL == newLocale){
        printf("setlocale() with %s failed!!\n", LC_NAME_zh_CN_DEFAULT); 
        (void)setlocale(LC_ALL, oriLocale); 
        return;
    }
/*
    iRet = sprintf_s( buffer, 4, "%c",  wc);
    assert(iRet == 2);
    assert(0 == strcmp(buffer, std) );
    memset(buffer,0,sizeof(buffer));

    iRet = sprintf_s( buffer, 4, "%hc", wc);
    assert(iRet == 2);
    assert(0 == strcmp(buffer, std) );
    memset(buffer,0,sizeof(buffer));*/

    iRet = sprintf_s( buffer, 4, "%lc", wc);
    assert(iRet == 2);
    assert(0 == strcmp(buffer, std) );
    memset(buffer,0,sizeof(buffer));

#if(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = sprintf_s( buffer, 4, "%wc", wc);
    assert(iRet == 2);
    assert(0 == strcmp(buffer, std) );
    memset(buffer,0,sizeof(buffer));
#endif

    iRet = sprintf_s( buffer, 4, "%C", wc);
    assert(iRet == 2);
    assert(0 == strcmp(buffer, std) );
    memset(buffer,0,sizeof(buffer));

#if!(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = sprintf_s( buffer, 4, "%hC", wc);
    assert(iRet == 2);
    assert(0 == strcmp(buffer, std) );
    memset(buffer,0,sizeof(buffer));
#endif

    iRet = sprintf_s( buffer, 4, "%lC", wc);
    assert(iRet == 2);
    assert(0 == strcmp(buffer, std) );
    memset(buffer,0,sizeof(buffer));

    (void)setlocale(LC_ALL, oriLocale);    /*restore original locale*/

}

void test_swprintf_s_wchar(void)
{
    wchar_t wBuf[10]={0};
    int iRet = -1;

    wchar_t std[] = L"中";
    wchar_t wc = L'中';

    char* oriLocale = NULL;
    char* newLocale = NULL;
    char oldLocal[100] = {0};
    oriLocale = setlocale(LC_ALL, NULL);
    if (oriLocale!=NULL)
    {
        strcpy_s(oldLocal,100,oriLocale);
        oriLocale = oldLocal;
    }
    newLocale = setlocale(LC_ALL, LC_NAME_zh_CN_DEFAULT);

#if(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = swprintf_s( wBuf, 4, L"%c", wc);
    assertMeetExpectedWstr(wBuf, std, iRet, __LINE__);
    wmemset(wBuf,0,10);
#endif

/*
    iRet = swprintf_s( wBuf, 4, L"%hc", wc);
    assertMeetExpectedWstr(wBuf, std, iRet, __LINE__);
    wmemset(wBuf,0,10);*/


    iRet = swprintf_s( wBuf, 4, L"%lc", wc);
    assertMeetExpectedWstr(wBuf, std, iRet, __LINE__);
    wmemset(wBuf,0,10);

#if(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = swprintf_s( wBuf, 4, L"%wc", wc);
    assertMeetExpectedWstr(wBuf, std, iRet, __LINE__);
    wmemset(wBuf,0,10);
#endif


#if!(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = swprintf_s( wBuf, 4, L"%C", wc);
    assertMeetExpectedWstr(wBuf, std, iRet, __LINE__);
    wmemset(wBuf,0,10);

    iRet = swprintf_s( wBuf, 4, L"%hC", wc);
    assertMeetExpectedWstr(wBuf, std, iRet, __LINE__);
    wmemset(wBuf,0,10);
#endif

    iRet = swprintf_s( wBuf, 4, L"%lC", wc);
    assertMeetExpectedWstr(wBuf, std, iRet, __LINE__);
    wmemset(wBuf,0,10);

    (void)setlocale(LC_ALL, oriLocale);    /*restore original locale*/
}

#endif
