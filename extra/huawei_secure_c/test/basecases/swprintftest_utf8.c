#include "securec.h"
#include "base_funcs.h"
#include <string.h>
#include <locale.h>
#include <assert.h>

void assertMeetExpectedWstr(const wchar_t* formattedStr, const wchar_t* expected, unsigned int funcRet, int lineId );

/*not win ,not vxworks*/
#if ( !(defined(SECUREC_VXWORKS_PLATFORM)) && !(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER)) ) 

void test_vswprintf_s_utf8(void)
{
    char* oriLocale = NULL;  
    char* newLocale = NULL; 
    char oldLocal[100] = {0};
    oriLocale = setlocale(0, NULL);
    newLocale = setlocale(0,"zh_CN.UTF-8");
    if (oriLocale!=NULL)
    {
        strcpy_s(oldLocal,100,oriLocale);
        oriLocale = oldLocal;
    } 
    if ( NULL == newLocale ) 
    { 
        printf("setlocale() with ch failed!!\n");
        return; 
    }

    wchar_t stdbuf[256]=L"中文";
    wchar_t secbuf[256];
    int rets;
    
    memset(secbuf, 0, sizeof(secbuf));

    rets = indirect_swprintf(secbuf, 256, L"%s", "中文");
/*       
        wprintf(L"%ls\n", stdbuf);
        wprintf(L"%d\n",stdbuf[0]);
        wprintf(L"%d\n",stdbuf[1]);
        wprintf(L"%d\n",stdbuf[2]);
        wprintf(L"%d\n",stdbuf[3]);
        wprintf(L"%d\n",stdbuf[4]);

        wprintf(L"%ls\n", secbuf);
        wprintf(L"%d\n",secbuf[0]);
        wprintf(L"%d\n",secbuf[1]);
        wprintf(L"%d\n",secbuf[2]);
        wprintf(L"%d\n",secbuf[3]);
        wprintf(L"%d\n",secbuf[4]);
       
        fputws (L"11sys:", stdout );
        fputws ( stdbuf, stdout );
        fputws ( L"\n", stdout );
        fputws (L"sec:", stdout );
        fputws ( secbuf, stdout );
        fputws ( L"\n", stdout );       
*/

    (void)setlocale(0, oriLocale);    /*restore original locale*/

    assertMeetExpectedWstr(stdbuf, secbuf, rets, __LINE__);
}

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
    oriLocale = setlocale(0, NULL);
    newLocale = setlocale(0,"zh_CN.UTF-8");
    if (oriLocale!=NULL)
    {
        strcpy_s(oldLocal,100,oriLocale);
        oriLocale = oldLocal;
    }
    if ( NULL == newLocale )
    {
        printf("setlocale() with ch failed!!\n");
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
    assert(iRet == 3);
    assert(0 == strcmp(buffer, std) );
    memset(buffer,0,sizeof(buffer));

#if(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = sprintf_s( buffer, 4, "%wc", wc);
    assert(iRet == 2);
    assert(0 == strcmp(buffer, std) );
    memset(buffer,0,sizeof(buffer));
#endif

    iRet = sprintf_s( buffer, 4, "%C", wc);
    assert(iRet == 3);
    assert(0 == strcmp(buffer, std) );
    memset(buffer,0,sizeof(buffer));

/* secure not suppot
#if!(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = sprintf_s( buffer, 4, "%hC", wc);
    assert(iRet == 3);
    assert(0 == strcmp(buffer, std) );
    memset(buffer,0,sizeof(buffer));
#endif      */

    iRet = sprintf_s( buffer, 4, "%lC", wc);
    assert(iRet == 3);
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
    oriLocale = setlocale(0, NULL);
    newLocale = setlocale(0,"zh_CN.UTF-8");
    if (oriLocale!=NULL)
    {
        strcpy_s(oldLocal,100,oriLocale);
        oriLocale = oldLocal;
    }
    if ( NULL == newLocale )
    {
        printf("setlocale() with ch failed!!\n");
        return;
    }

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

/*  secure not support
#if!(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = swprintf_s( wBuf, 4, L"%C", wc);
    assertMeetExpectedWstr(wBuf, std, iRet, __LINE__);
    wmemset(wBuf,0,10);
    iRet = swprintf_s( wBuf, 4, L"%hC", wc);
    assertMeetExpectedWstr(wBuf, std, iRet, __LINE__);
    wmemset(wBuf,0,10);
#endif
*/
    iRet = swprintf_s( wBuf, 4, L"%lC", wc);
    assertMeetExpectedWstr(wBuf, std, iRet, __LINE__);
    wmemset(wBuf,0,10);

    (void)setlocale(LC_ALL, oriLocale);    /*restore original locale*/
}

#endif

