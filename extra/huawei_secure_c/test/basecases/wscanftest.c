
#include "securec.h"
#include "base_funcs.h"
#include "testutil.h"
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#if !(defined(SECUREC_VXWORKS_PLATFORM))
#include <wchar.h>
#endif
#include <string.h>
#include <locale.h>

/* vxworks platform not support the wchar opporation,this file,
   so in this ploatform,all of contents in this file do not need to run
 */
#ifndef SECUREC_VXWORKS_PLATFORM
#define EPSINON 0.00001
#define DEST_BUFFER_SIZE  20
#define SRC_BUFFER_SIZE  200

#if !defined (COUNTOF)
    #define COUNTOF(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

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

void test_wscanf(void)
{
    int ret = 0,  conv= 0,iv = 0;
    float fv = 0;
    wchar_t wDest[DEST_BUFFER_SIZE] = {0};
  int rc;
    printf("do you want to test wscanf? (y/n)");
    ret = getchar();
    ret = tolower(ret);

    while (ret == 'y'){
        
        printf("please input integer, float and string\n");
        conv = wscanf_s(L"%d%f%100s", &iv, &fv, wDest, DEST_BUFFER_SIZE);
        rc = wprintf(L"convert %d items, you input value are %d  %f %.100s \n", conv, iv, fv, wDest);
        assert(rc == EOK);
        printf("continue test scanf? (y, n)");
        ret = tolower( getchar() );
    }
}

void test_wscanf2(void)
{
    int ret = 0;
    int      i,     result;
    float    fp;
    char     c,
        s[80];
    wchar_t  wc, ws[80];
  int rc;
    printf("do you want to test wscanf? (y/n)");
    ret = tolower(getchar());

    while (ret == 'y'){


        printf("%s", "input format: %d %f %hc %lc %S %ls\n");

        result = wscanf_s( L"%d %f %hc %lc %S %ls", &i, &fp, &c, 1,
            &wc, 1, s, COUNTOF(s), ws, COUNTOF(ws) );

        rc= wprintf( L"The number of fields input is %d\n", result );
    assert(rc == EOK);
        rc = wprintf( L"The contents are: %d %f %C %c %hs %s\n", i, fp,
            c, wc, s, ws);
    assert(rc == EOK);

        printf("continue test wscanf? (y, n)");
        ret = tolower( getchar() );
    }
}


/* windows test wscanf_s chinese + %s/%S */
void test_wscanf_3(void)
{
    #define DEST_BUFFER_SIZE  30

    int conv= 0;
    wchar_t wDest[DEST_BUFFER_SIZE] = {0};
    char Dest[DEST_BUFFER_SIZE] = {0};

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
    if ( NULL == newLocale )
    {
        printf("setlocale() with ch failed!!\n");
        return;
    }

    conv = swscanf_s(L"中文",L"%s", wDest, DEST_BUFFER_SIZE);
    assert(conv == 1 );
    assert(my_wcscmp(wDest, L"中文") == 0);

    conv = swscanf_s(L"中文",L"%S",Dest, DEST_BUFFER_SIZE);
    assert(conv == 1 );
    assert(strcmp(Dest, "中文") == 0);

/*
    wprintf(L"%d\n",wDest[0]);
    wprintf(L"%d\n",wDest[1]);
    wprintf(L"%d\n",wDest[2]);
    wprintf(L"%d\n",wDest[3]);
    wprintf(L"%d\n",wDest2[0]);
    wprintf(L"%d\n",wDest2[1]);
    wprintf(L"%d\n",wDest2[2]);
    wprintf(L"%d\n",wDest2[3]);*/

    (void)setlocale(LC_ALL, oriLocale);    /*restore original locale*/

}

int indirect_wscanf(const wchar_t* format, ...)
{
    va_list args;
    int ret = 0;
    
    va_start( args, format );
    ret = vwscanf_s( format, args );
    va_end(args);
    return ret;
    
}
void test_vwscanf(void)
{
    int ret = 0;
    int      i,     result;
    float    fp;
    char     c,
        s[80];
    wchar_t  wc,
        ws[80];
  int rc;
    printf("do you want to test vwscanf? (y/n)\n");
    ret = getchar();
    ret = tolower(ret);

    while (ret == 'y'){

        printf("%s", "input format: %d %f %hc %lc %S %ls\n");

        result = indirect_wscanf( L"%d %f %hc %lc %S %ls", &i, &fp, &c, 1,
            &wc, 1, s, COUNTOF(s), ws, COUNTOF(ws) );

        rc= wprintf( L"The number of fields input is %d\n", result );
        assert(rc == EOK);
    rc = wprintf( L"The contents are: %d %f %C %c %hs %s\n", i, fp,
            c, wc, s, ws);
    assert(rc == EOK);


        printf("continue test vwscanf? (y, n)\n");
        ret = tolower( getchar() );
    }
}
/*
void TC_05()
{
    FILE *stream;
    int iRet;
    int iv;
    int a, b, c, l;
    wchar_t buf[1024];

    //big.out   little.txt
    if( (stream = fopen( "d:/big.out", "r+" )) == NULL )
    {
        wprintf( L"The file fscanf1.out was not opened\n" );
    }
    else
    {

    //    iRet= fwscanf( stream, L"%s", buf,1024);

        iRet= fwscanf( stream, L"%sd", &iv);

        wprintf( L"%s\r\n", &buf[2]);
        fclose( stream );
    }

}
*/
#define TEST_WSTR L"1111111111.000000000011111111112222222222333333333344444444\
4455555555556666666666777777777788888888889999999999000000000011111111112222222\
2223333333333444444444455555555556666666666777777777788888888889999999999000000\
0000111111111122222222223333333333444444444455555555556666666666777777777788888\
8888899999999990000000000111111111122222222223333333333444444444455555555556666\
6666667777777777888888888899999999990000000000111111111122222222223333333333444\
44444445555555555666666666677777777778888888888999999999900000000001111111111222\
22222223333333333444444444455555555556666666666777777777788888888889999999999000\
00000001111111111222222222233333333334444444444555555555566666666667777777777888\
8888888999999999900000000001111111111222222222233333333334444444444555555555566\
6666666677777777778888888888999999999922222222223333333333444444444455555555556\
666666666777777777788888888889999999999"

#if !(defined(SECUREC_VXWORKS_PLATFORM))
void testSwscanf(void)
{
    wchar_t wDest[DEST_BUFFER_SIZE] = {0}; /*lint !e532*/
    wchar_t wBuf[48];
    int a, b ,c = 0, conv;
    float fv;
    const wchar_t *ws = L"蝴蝶测试工具，好不好用呢？谁用谁知道啊！";
    wchar_t wStr[] = L"123 5689.4 asdfqwer";
    //int rc;

    (void)swscanf_s(L"2006:03:18", L"%d:%d:%d", &a, &b, &c);
    assert(a == 2006 && b == 3 && c ==18);

    (void)swscanf_s(L"123456 ",L"%s", wDest, DEST_BUFFER_SIZE);
    assert(my_wcscmp(wDest, L"123456") == 0);

    (void)swscanf_s(L"123456 ",L"%4s",wDest, DEST_BUFFER_SIZE);
    assert(my_wcscmp(wDest, L"1234") == 0);

    (void)swscanf_s(L"123456 abcdedf",L"%[^ ]",wDest, DEST_BUFFER_SIZE);
    assert(my_wcscmp(wDest, L"123456") == 0);

    a = swscanf_s(ws, L"%s", wBuf , sizeof(wBuf) / sizeof(wchar_t));
    assert(a == 1);
    assert(0 == my_wcscmp(wBuf, ws));

    a = swscanf_s(L"34.12454",L"%f",&fv);
    assert(a == 1);
    assertFloatEqu(fv, 34.12454f);

        conv = swscanf_s(TEST_WSTR, L"%f",  &fv);
    assertFloatEqu(fv, 1111111111.0f);
    assert(conv == 1);

    conv = swscanf_s(wStr, L"%d%f%100s", &b, &fv, wDest, DEST_BUFFER_SIZE );
    assert(conv == 3 );
    assert(my_wcscmp(wDest, L"asdfqwer") == 0);
    assert(b == 123 );
    assertFloatEqu(fv, 5689.4f);

    wDest[1]=L'\0';
    *wDest=L'a';
    conv = swscanf_s(L"", L"%s", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"") == 0);
/*
    *wDest=L'a';
    conv = swscanf_s(L"\n", L"%s", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"") == 0);
*/
    *wDest=L'a';
    conv = swscanf_s(L"", L"%10s", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"") == 0);

    *wDest=L'a';
    conv = swscanf_s(L"", L"%hs", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(*(char *)wDest == 0);


    *wDest=L'a';
    conv = swscanf_s(L"", L"%ls", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"") == 0);


    *wDest=L'a';
    conv = swscanf_s(L"", L"%S", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(*(char *)wDest == 0);

    *wDest=L'a';
    conv = swscanf_s(L"", L"%d", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"a") == 0);

    *wDest=L'a';
    conv = swscanf_s(L"", L"%[]", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"a") == 0);

#if !(defined(_WIN32) || defined(_WIN64))
    *wDest=L'a';
    conv = swscanf_s(L"", L"%{a]", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"a") == 0);
#endif

     *wDest=L'a';
    conv = swscanf_s(L"", L"%[^]a]", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"") == 0);

     *wDest=L'a';
    conv = swscanf_s(L"", L"aa%s", wDest, 0 );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"a") == 0);

     *wDest=L'a';
    conv = swscanf_s(L"", L"", wDest, 0 );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"a") == 0);
    
} /*lint !e533*/


int indirect_swscanf(const wchar_t* str, const wchar_t* format, ...)
{
    va_list args;
    int ret = 0;
    
    va_start( args, format );
    ret = vswscanf_s(str, format, args ) ;
    va_end(args);
    return ret;
    
}
void test_vswscanf(void)
{
    wchar_t wDest[DEST_BUFFER_SIZE] = {0};
    int a, b ,c = 0;

    (void)indirect_swscanf(L"2006:03:18", L"%d:%d:%d", &a, &b, &c);
    assert(a == 2006 && b == 3 && c ==18);

    (void)indirect_swscanf(L"123456 ",L"%s", wDest, DEST_BUFFER_SIZE);
    assert(my_wcscmp(wDest, L"123456") == 0);

    (void)indirect_swscanf(L"123456 ",L"%4s",wDest, DEST_BUFFER_SIZE);
    assert(my_wcscmp(wDest, L"1234") == 0);

    (void)indirect_swscanf(L"123456 abcdedf",L"%[^ ]",wDest, DEST_BUFFER_SIZE);
    assert(my_wcscmp(wDest, L"123456") == 0);
}


void test_fwscanf(void)
{
    FILE *stream;
    long l;
    float fp;
    wchar_t s[81];
    wchar_t c;
    int rc; 
    if( (stream = fopen( "./fwscanf.out", "wb+" )) == NULL )
    {
        printf( "The file fwscanf.out was not opened\n" );
    }
    else
    {
    
        l = fwrite(L"a-string 65000 3.14159x",24 * sizeof(wchar_t), 1, stream);
    
        /* Set pointer to beginning of file: */
        if ( fseek( stream, 0L, SEEK_SET ) )
        {
            rc = wprintf( L"fseek failed\n" );
            assert(rc == EOK);
        }
        
        /* Read data back from file: */
        (void)fwscanf_s( stream, L"%s", s, 81 );
        (void)fwscanf_s( stream, L"%ld", &l );
        (void)fwscanf_s( stream, L"%f", &fp );
        (void)fwscanf_s( stream, L"%c", &c, 1 );

        assert( my_wcscmp(s, L"a-string") == 0);
        assert(l == 65000);
        assertFloatEqu(fp, 3.14159F);
        assert(c == 'x');

        fclose( stream );
        
    }
}


int indirect_fwscanf(FILE* f, const wchar_t* format, ...)
{
    va_list args;
    int ret = 0;
    
    va_start( args, format );
    ret = vfwscanf_s(f, format, args ) ;
    va_end(args);
    return ret;
    
}
void test_vfwscanf(void)
{
    FILE *stream;
    long l;
    float fp;
    wchar_t s[81];
    wchar_t c;
    int rc;
    if( (stream = fopen( "./vfwscanf.out", "wb+" )) == NULL )
    {
        rc = wprintf( L"The file vfwscanf.out was not opened\n" );
    assert(rc == EOK);
    }
    else
    {
        l = fwrite(L"a-string 65000 3.14159x", 24 * sizeof(wchar_t), 1, stream);
    
        /* Set pointer to beginning of file: */
        if ( fseek( stream, 0L, SEEK_SET ) )
        {
            rc = wprintf( L"fseek failed\n" );
            assert(rc == EOK);
        }
        
        /* Read data back from file:  */
        (void)indirect_fwscanf(stream,L"%s %ld %f%c", s, 81,  &l, &fp,  &c, 1 );    
        assert( my_wcscmp(s, L"a-string") == 0);
        assert(l == 65000);
        assertFloatEqu(fp, 3.14159F);
        assert(c == 'x');
        
        fclose( stream );
        
    }
}

void testfwscanf_read1K(void)
{
    char buf[1024+2] = {0};
    int ret = 0;
    FILE *file = NULL;
    int len = 0;
    
    file = fopen(FSCANF_FILES_PATH("fwscanf1kLittleEndian2"), "rb");
    if(NULL == file)
    {
        printf("File %s open fail!\n", FSCANF_FILES_PATH("fwscanf1kLittleEndian2"));
        return;
    }

    ret = fwscanf_s(file, L"%1025hs", buf,1026);
    len = strlen(buf);
    printf("fwscanf_s  1K ret %d,buf len is %d\n", ret,len);
    assert(ret == 1);
    assert(buf[0] == 'x');
    assert(buf[1024] == 'x');
    fclose(file);
    return;
}

void testswscanf_branches(void)
{
    if (sizeof(void*) == sizeof(INT64T)) 
    {
        INT64T d1 = 0,d2 = 0;
        swscanf_s(L"123,123",L"%Id,%Iu",&d1,&d2);
        assert(d1 == 123);
        assert(d2 == 123);
    }
    else
    {
        INT32T d1 = 0,d2 = 0;
        swscanf_s(L"123,123",L"%Id,%Iu",&d1,&d2);
        assert(d1 == 123);
        assert(d2 == 123);
    }
}
#endif
#endif

#ifndef SECUREC_VXWORKS_PLATFORM

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
    oriLocale = setlocale(LC_ALL, NULL);
    if (oriLocale!=NULL)
    {
        strcpy_s(oldLocal,100,oriLocale);
        oriLocale = oldLocal;
    }
    newLocale = setlocale(LC_ALL, LC_NAME_zh_CN_DEFAULT);
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
    oriLocale = setlocale(LC_ALL, NULL);
    if (oriLocale!=NULL)
    {
        strcpy_s(oldLocal,100,oriLocale);
        oriLocale = oldLocal;
    }
    newLocale = setlocale(LC_ALL, LC_NAME_zh_CN_DEFAULT);
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