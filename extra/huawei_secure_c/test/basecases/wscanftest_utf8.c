#include "securec.h"
#include "base_funcs.h"
#include <string.h>
#include <locale.h>
#include <assert.h>


/*not win ,not vxworks*/
#if ( !(defined(SECUREC_VXWORKS_PLATFORM)) && !(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER)) ) 

/* wscanf_s %S */
void test_wscanf_3(void)
{
    #define DEST_BUFFER_SIZE  30

    int conv= 0;
    wchar_t wDest[DEST_BUFFER_SIZE] = {0};
  /*  wchar_t wDest2[DEST_BUFFER_SIZE] = L"中文";*/

    char Dest[DEST_BUFFER_SIZE] = {0};

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

    conv = swscanf_s(L"中文",L"%ls", wDest, DEST_BUFFER_SIZE);
    assert(conv == 1 );
    assert(my_wcscmp(wDest, L"中文") == 0);
/*   
    wprintf(L"%d\n",wDest[0]);
    wprintf(L"%d\n",wDest[1]);
    wprintf(L"%d\n",wDest[2]);
    wprintf(L"%d\n",wDest[3]);

    wprintf(L"%d\n",wDest2[0]);
    wprintf(L"%d\n",wDest2[1]);
    wprintf(L"%d\n",wDest2[2]);
    wprintf(L"%d\n",wDest2[3]);
*/
    (void)setlocale(0, oriLocale); 
}

void test_sscanf_s_wString(void)
{
    wchar_t wBuf[200]={0};
    int iRet = -1;

/*
    iRet = sscanf_s( "111", "%s", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"111", 3, __LINE__);

    iRet = sscanf_s( "222", "%hs", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"222", 3, __LINE__);
*/

    iRet = sscanf_s( "333", "%ls", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"333", 3, __LINE__);

#if(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = sscanf_s( "444", "%ws", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"444", 3, __LINE__);
#endif

    iRet = sscanf_s( "555", "%S", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"555", 3, __LINE__);

/*
#if!(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = sscanf_s( "666", "%hS", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"666", 3, __LINE__);
#endif*/


    iRet = sscanf_s( "777", "%lS", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"777", 3, __LINE__);

    return;
}

void test_swscanf_s_wString(void)
{
    wchar_t wBuf[200]={0};
    int iRet = -1;

#if(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = swscanf_s( L"111", L"%s", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"111", 3, __LINE__);
#endif

/*
    iRet = swscanf_s( L"222", L"%hs", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"222", 3, __LINE__);
*/

    iRet = swscanf_s( L"333", L"%ls", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"333", 3, __LINE__);

#if(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = swscanf_s( L"444", L"%ws", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"444", 3, __LINE__);
#endif

#if!(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = swscanf_s( L"555", L"%S", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"555", 3, __LINE__);
/*
    iRet = swscanf_s( L"666", L"%hS", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"666", 3, __LINE__);
*/

#endif

    iRet = swscanf_s( L"777", L"%lS", wBuf, 40);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, L"777", 3, __LINE__);

    return;
}

void test_sscanf_s_wChar(void)
{
    char buffer[10]="中";
    wchar_t wBuf[10]={0};
    wchar_t wStd[] = L"中";
    int iRet = -1;
    
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
    iRet = sscanf_s( buffer, "%c", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);

    iRet = sscanf_s( buffer, "%hc", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);
*/

    iRet = sscanf_s( buffer, "%lc", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);

#if(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = sscanf_s( buffer, "%wc", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);
#endif

    iRet = sscanf_s( buffer, "%C", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);

/*
#if!(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = sscanf_s( buffer, "%hC", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);
#endif*/


    iRet = sscanf_s( buffer, "%lC", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);

    return;
}

void test_swscanf_s_wChar(void)
{
    wchar_t wSource[10]=L"中";
    wchar_t wBuf[10]={0};
    wchar_t wStd[] = L"中";
    int iRet = -1;
    
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
    iRet = swscanf_s( wSource, L"%c", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);
#endif

/*
    iRet = swscanf_s( wSource, L"%hc", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);
*/

    iRet = swscanf_s( wSource, L"%lc", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);

#if(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = swscanf_s( wSource, L"%wc", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);
#endif

#if!(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
    iRet = swscanf_s( wSource, L"%C", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);
/*
    iRet = swscanf_s( wSource, L"%hC", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);
*/
#endif

    iRet = swscanf_s( wSource, L"%lC", wBuf, 8);
    assert(iRet == 1);
    assertMeetExpectedWstr(wBuf, wStd, iRet, __LINE__);

    return;
}

#endif


