#include "securec.h"
#include "base_funcs.h"
#include "testutil.h"
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#ifndef SECUREC_VXWORKS_PLATFORM
#include <wchar.h>
#endif
#include <string.h>
#include <locale.h>

#define EPSINON 0.00001
#define DEST_BUFFER_SIZE  20
#define SRC_BUFFER_SIZE  200

#if !defined (COUNTOF)
    #define COUNTOF(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

/*
int strcmp (   const char * src,   const char * dst  )
{
    int ret = 0 ;

    while( ! (ret = *(uint8_t *)src - *(uint8_t*)dst) && *dst)
        ++src, ++dst;

    if ( ret < 0 )
        ret = -1 ;
    else if ( ret > 0 )
        ret = 1 ;

    return( ret );
}

*/

#define EPSINON 0.00001
static int Equal_l(double x,double y)
{
    double diff = x - y;
    if(diff >= -EPSINON && diff <= EPSINON)
        return 1;
    else if( (x * y >0) && (1.0/x >= -EPSINON) && (1.0/x <= EPSINON) 
        && (1.0/y >= -EPSINON) && (1.0/y <= EPSINON))
        return 1;
    else
        return 0;
}
#ifdef SECUREC_SUPPORT_STRTOLD
static int Equal_ll(long double x,long double y)
{
    double diff = x - y;
    if(diff >= -EPSINON && diff <= EPSINON)
        return 1;
    else if( (x * y >0) && (1.0/x >= -EPSINON) && (1.0/x <= EPSINON) 
        && (1.0/y >= -EPSINON) && (1.0/y <= EPSINON))
        return 1;
    else
        return 0;
}
#endif
void test_scanf(void)
{
    int ret = 0, j = 0, conv= 0,iv = 0;
    float fv = 0;
    char dest[DEST_BUFFER_SIZE] = {0};
    #ifndef SECUREC_VXWORKS_PLATFORM  
    wchar_t wDest[DEST_BUFFER_SIZE] = {0};
    #endif

    printf("do you want to test scanf? (y/n)");
    ret = getchar();
    ret = tolower(ret);

    while (ret == 'y'){
        
        printf("please input integer float string\n");
        
        if ( j % 2 == 0) {
            conv = scanf_s("%d%f%100s", &iv, &fv, dest, DEST_BUFFER_SIZE);
            printf("convert %d items, you input value are %d  %f %.100s \n", conv, iv, fv, dest);
        }else{
    #ifndef SECUREC_VXWORKS_PLATFORM
            conv = wscanf_s(L"%d%f%100s", &iv, &fv, wDest, DEST_BUFFER_SIZE);
            #if __STDC_VERSION__ >= 199901L
            int rc = wprintf(L"convert %d items, you input value are %d  %f %.100s \n", conv, iv, fv, wDest);
            assert(rc == EOK);
            #endif
    #endif
        }
        
        
        ++j;
        
        printf("continue test scanf? (y, n)");
        ret = tolower( getchar() );
    }
}

int indirect_scanf(const char* format, ...)
{
    va_list args;
    int ret = 0;
    
    va_start( args, format );
    ret = vscanf_s( format, args ) ;
    va_end(args);
    return ret;
    
}
void clearStdinBuffer(void)
{
/*    int ret = 0;
    while( (ret =  fgetc(stdin)) != '\n' ){
    //    printf("%c", ret);
    }
    char buf[5];
    while (gets_s(buf, 5) != NULL && slen(buf) > 0 ){
    }
    */
}
void test_vscanf(void)
{
    int ret = 0, conv= 0,iv = 0;
    float fv = 0;
    char dest[DEST_BUFFER_SIZE] = {0};
/*#ifndef SECUREC_VXWORKS_PLATFORM
    wchar_t wDest[DEST_BUFFER_SIZE] = {0};
#endif*/

    printf("do you want to test vscanf? (y/n)");
    ret = getchar();
    ret = tolower(ret);

    while (ret == 'y'){
        
        printf("input format:  %s\n", "%d%f%100s");
        
        conv = indirect_scanf("%d%f%100s", &iv, &fv, dest, DEST_BUFFER_SIZE);
        printf("convert %d items, you input value are %d  %f %.100s \n", conv, iv, fv, dest);
        
        if (conv <= 0){
            clearStdinBuffer();

        }
        printf("continue test vscanf? (y, n)");
        ret = tolower( getchar() );
    }
}

#ifndef SECUREC_VXWORKS_PLATFORM
void test_wscanf(void)
{
    int ret = 0;
    int      i,     result;
    float    fp;
    char     c,
        s[80];
    wchar_t  wc,
        ws[80];

    printf("do you want to test wscanf? (y/n)");
    ret = tolower(getchar());

    while (ret == 'y'){


        printf("%s", "input format: %d %f %hc %lc %S %ls\n");

        result = wscanf_s( L"%d %f %hc %lc %S %ls", &i, &fp, &c, 1,
            &wc, 1, s, COUNTOF(s), ws, COUNTOF(ws) );

        #if __STDC_VERSION__ >= 199901L
        int rc = wprintf( L"The number of fields input is %d\n", result );
        assert(rc == EOK);
        rc = wprintf( L"The contents are: %d %f %C %c %hs %s\n", i, fp,
            c, wc, s, ws);
        assert(rc == EOK);
        #endif

        printf("continue test wscanf? (y, n)");
        ret = tolower( getchar() );
    }
}
#endif

#ifndef SECUREC_VXWORKS_PLATFORM
int indirect_wscanf(const wchar_t* format, ...)
{
    va_list args;
    int ret = 0;
    
    va_start( args, format );
    ret = vwscanf_s( format, args );
    va_end(args);
    return ret;
    
}
#endif
#ifndef SECUREC_VXWORKS_PLATFORM
void test_vwscanf(void)
{
    int ret = 0;
    int      i,     result;
    float    fp;
    char     c,
        s[80];
    wchar_t  wc,
        ws[80];

    printf("do you want to test vwscanf? (y/n)\n");
    ret = getchar();
    ret = tolower(ret);

    while (ret == 'y'){

        printf("%s", "input format: %d %f %hc %lc %S %ls\n");

        result = indirect_wscanf( L"%d %f %hc %lc %S %ls", &i, &fp, &c, 1,
            &wc, 1, s, COUNTOF(s), ws, COUNTOF(ws) );

        #if __STDC_VERSION__ >= 199901L
        int rc = wprintf( L"The number of fields input is %d\n", result );
        assert(rc == EOK);
        rc = wprintf( L"The contents are: %d %f %C %c %hs %s\n", i, fp, c, wc, s, ws);
        assert(rc == EOK);
        #endif

        printf("continue test vwscanf? (y, n)\n");
        ret = tolower( getchar() );
    }
}
#endif
#define TEST_STR "11111111112222222222333333333344444444445555555555666666666677777777778888888888999999\
99990000000000.0000000000111111111122222222223333333333444444444455555555556666666666777777777788888888\
889999999999000000000011111111112222222222333333333344444444445555555555666666666677777777778888888888\
999999999900000000001111111111222222222233333333334444444444555555555566666666667777777777888888888899\
9999999900000000001111111111222222222233333333334444444444555555555566666666667777777777888888888899999\
999990000000000111111111122222222223333333333444444444455555555556666666666777777777788888888889999999\
999000000000011111111112222222222333333333344444444445555555555666666666677777777778888888888999999999\
9000000000011111111112222222222333333333344444444445555555555666666666677777777778888888888999999999900\
00000000111111111122222222223333333333444444444455555555556666666666777777777788888888889999999999"
#define TEST_STR2 "1111111111.0000000000111111111122222222223333333333444444444455555555556666666666777\
7777777888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666777777\
7777888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666777777777\
7888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666777777777788\
88888888999999999900000000001111111111222222222233333333334444444444555555555566666666667777777777888888\
8888999999999900000000001111111111222222222233333333334444444444555555555566666666667777777777888888888\
8999999999900000000001111111111222222222233333333334444444444555555555566666666667777777777888888888899\
9999999900000000001111111111222222222233333333334444444444555555555566666666667777777777888888888899999\
9999922222222223333333333444444444455555555556666666666777777777788888888889999999999" 
#define TEST_WSTR L"1111111111.0000000000111111111122222222223333333333444444444455555555556666666666777\
7777777888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666777777\
777788888888889999999999000000000011111111112222222222333333333344444444445555555555666666666677777777\
7788888888889999999999000000000011111111112222222222333333333344444444445555555555666666666677777777778\
88888888899999999990000000000111111111122222222223333333333444444444455555555556666666666777777777788888\
8888899999999990000000000111111111122222222223333333333444444444455555555556666666666777777777788888888\
889999999999000000000011111111112222222222333333333344444444445555555555666666666677777777778888888888\
999999999900000000001111111111222222222233333333334444444444555555555566666666667777777777888888888899\
9999999922222222223333333333444444444455555555556666666666777777777788888888889999999999"


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
#else 
    #define LC_NAME_zh_CN_DEFAULT   "zh_CN.UTF-8" 
#endif 
/*
void TC_01()
{
    char buf[] ="21341234 123 4123412 -1";
    int point=0,orginvalue=0;
    int hLLT_Result = sscanf_s(buf,"%p",&point);
    int orgin_Result = sscanf(buf,"%p",&orginvalue);

    assert(orgin_Result == hLLT_Result);
    assert(point == orginvalue);
}    
void TC_02()
{
    char buf[] ="21341234 123 4123412 -1";
    int point=0,orginvalue=0;

    int hLLT_Result = sscanf_s(buf,"%Fp",&point);
    int orgin_Result = sscanf(buf,"%Fp",&orginvalue);

    assert(orgin_Result == hLLT_Result);
    assert(point == orginvalue);
}
void TC_03()
{
    char buf[128]={0},orginss[128]={0};

    int hLLT_Result = sscanf_s("452345jwertjlkqwe;rt35",
            "%ws",
            buf,sizeof(buf));
    int orgin_Result = sscanf("452345jwertjlkqwe;rt35",
            "%ws",
            orginss);
    assert(orgin_Result == hLLT_Result);
    assert(0 == strcmp(orginss,buf));
}

void TC_04()
{
    char buf[128]={0},orginss[128]={0};

    int hLLT_Result = sscanf_s("hello, world",
            "%S",
            buf,sizeof(buf));
    int orgin_Result = sscanf("hello, world",
            "%S",
            orginss);
    assert(orgin_Result == hLLT_Result);
    assert(0 == strcmp(orginss,buf));
}
 
void TC_05()
{
    FILE *stream;
    int rc;
    int iRet;
    int iv;
    int a, b, c, l;
#ifndef SECUREC_VXWORKS_PLATFORM
    wchar_t buf[1024];
#endif

    //big.out   little.txt
    if( (stream = fopen( "d:/big.out", "r+" )) == NULL )
    {
#ifndef SECUREC_VXWORKS_PLATFORM
        rc = wprintf( L"The file fscanf1.out was not opened\n" );
    assert(rc == EOK);
#endif
    }
    else
    {
   
//#ifndef SECUREC_VXWORKS_PLATFORM
    //iRet= fwscanf( stream, L"%s", buf,1024);
//#endif

#ifndef SECUREC_VXWORKS_PLATFORM
        iRet= fwscanf( stream, L"%sd", &iv);
        rc = wprintf( L"%s\r\n", &buf[2]);
    assert(rc == EOK);
        fclose( stream );
#endif
    }
}
*/
void scanf_gbk(void)
{
    char* oriLocale = NULL;    
    char* newLocale = NULL;  
#ifndef SECUREC_VXWORKS_PLATFORM
    const wchar_t *ws = L"蝴蝶测试工具，好不好用呢？谁用谁知道啊！";
    wchar_t wBuf[128]={0};
#endif
    const char* as = "蝴蝶测试工具，好不好用呢？谁用谁知道啊！";
    char atmp[88]={0};
    int ret = 0;
/*
    TC_01();
    TC_02();
    TC_03();
    TC_04();
    TC_05();
*/
    ret = MB_CUR_MAX;
    oriLocale = setlocale(LC_ALL, NULL);


    newLocale = setlocale(LC_ALL, LC_NAME_zh_CN_DEFAULT);
    if ( NULL == newLocale ) 
    { 
        printf("setlocale() with %s failed.\n", LC_NAME_zh_CN_DEFAULT); 
    } 
    else 
    { 
        printf("setlocale() with %s succeed.\n", LC_NAME_zh_CN_DEFAULT); 
        ret = MB_CUR_MAX;
#ifndef SECUREC_VXWORKS_PLATFORM
        ret = wctomb(atmp, ws[0] );        
        ret = sscanf_s( as, "%S", wBuf , sizeof(wBuf) / sizeof(wchar_t) );
        assert(ret == 1);
        assert(0 == my_wcscmp(wBuf, ws));
        

#endif    
        ret = sscanf_s( as, "蝴蝶%s", atmp , sizeof(atmp));
        assert(ret == 1);
        assert(0 == strcmp(atmp, "测试工具，好不好用呢？谁用谁知道啊！"));
        
    }

    (void)setlocale(LC_ALL, oriLocale);    /*restore original locale*/
    ret = MB_CUR_MAX;

    ret = sscanf_s( as, "%s", atmp , sizeof(atmp));
    assert(ret == 1);
    assert(0 == strcmp(atmp, as));
#ifndef SECUREC_VXWORKS_PLATFORM
    ret = swscanf_s(ws, L"%ls", wBuf , sizeof(wBuf) / 2);
    assert(ret == 1);
    assert(0 == my_wcscmp(wBuf, ws));
#endif


}
int vfscf(FILE *pf, const char *fmt, ...)
{
    va_list argptr;
    int cnt;

    va_start(argptr, fmt);
    cnt = vfscanf_s(pf, fmt, argptr);
    va_end(argptr);
    return(cnt);
}

 typedef struct _MY_INT64{
        unsigned long LowPart;
        long HighPart;
    }MY_INT64;

void test_sscanf(void)
{

    char dest[DEST_BUFFER_SIZE] = {0};
    char dest2[DEST_BUFFER_SIZE] = {0};
#ifndef SECUREC_VXWORKS_PLATFORM
    wchar_t wDest[DEST_BUFFER_SIZE] = {0};
    wchar_t wStr[] = L"123 5689.4 asdfqwer";
#endif
    /*char inputStr[] = "123 567.4 asdfqwer";*/
    

    char src[SRC_BUFFER_SIZE] = "abcd";
    /*char str[512] = {0};*/

    int iv = 0xFF,     ret ;
    float fv = 0;
    int conv = 0;
   /* unsigned short wv = iv;
    char* pTest = dest;*/
    unsigned int  ui = 0;
    int a, b ,c,d = 0;
    char  tokenstring[] = "15 12 14...";
    /*char  s[81] = {0};*/
    char  ch;
    int   i;
    /*float fp = 0.0f;*/
    double dbValue;
    long double dblVal;
    char sztime1[32] = {0};
    char sztime2[32] = {0};

    /*int j = 0;*/
    int inumber = 9000;
    int iRet = 0;
    FILE *ffp;
    INT64T val64;
    char *clearfmts[] = 
    {
        "%s %d",
        "%10s %d",     
        "%hs %d",
        "%[a] %d",
        "%[^]a] %d",
        "%c %d",
        NULL
    };
    char *clearfmts4white[] = 
    {
        "%s %d",
        "%10s %d",     
        "%hs %d",
        NULL
    };

    conv = sscanf_s("3.456789","%lg",&dbValue);
    assert(conv == 1);
    assertFloatEqu((float)dbValue, 3.456789f);

#ifndef SECUREC_VXWORKS_PLATFORM
    conv = sscanf_s("3.456789","%Lg",&dblVal);
    assert(conv == 1);
    assertFloatEqu((float)dblVal, 3.456789f);
#endif

/*    conv = sscanf_s("3.456789","%llg",&dblVal);
    assert(conv == 1);
    assertFloatEqu(dblVal, 3.456789f);
*/

    conv = sscanf_s("34.12454","%f",&fv);
    assertFloatEqu(fv, 34.12454f);
#ifndef SECUREC_VXWORKS_PLATFORM
    conv = swscanf_s(L"34.12454",L"%f",&fv);
    assertFloatEqu(fv, 34.12454f);
#endif

    if( !setlocale(LC_ALL, LC_NAME_zh_CN_DEFAULT) ) {
        printf("setlocale failed\n" );    
    }
    else{
        conv = sscanf_s("a中a23elp2345","a中%s", dest, DEST_BUFFER_SIZE);
        assert(conv == 1);
        assert( strcmp(dest, "a23elp2345") == 0);

        conv = sscanf_s("a中a23elp2345中国","a中%s", dest, DEST_BUFFER_SIZE);
        assert(conv == 1);
        assert( strcmp(dest, "a23elp2345中国") == 0);
        
#ifndef SECUREC_VXWORKS_PLATFORM
        memset(src,0,sizeof(src));
        strcpy(src,"好");
        src[strlen(src)]=0x81;/*test mbtowc */
        (void)sscanf_s(src,"%ls",wDest,sizeof(wDest)/sizeof(wchar_t));
        assert(my_wcscmp(wDest, L"好?") == 0);
#endif
    }

    conv = sscanf_s("9223372036854775807", "%lld", &val64);
    /*assert(sizeof(MY_INT64) == 8);*/
    assert(conv == 1);
    /*printf("%I64u/n", *(__int64*)&val64);*/

    conv = sscanf_s( "3.1415gh", "%f", &fv );
    assert(conv == 1);
    assertFloatEqu(fv, 3.1415f);

    conv = sscanf_s("123asd45678abcd  12323", "%s",  dest, DEST_BUFFER_SIZE);
    assert(conv == 1);
    ffp = tmpfile();

    if (ffp == NULL)
    {
        printf("tmpfile() fail");
    }else{

        fprintf(ffp,"%d\n",inumber);
        rewind(ffp);
        iRet = vfscf(ffp, "%d",&inumber);
        fclose(ffp);
        assert(iRet == 1);
        assert(inumber == 9000);
    }

    conv = sscanf_s("123asdfasdf1123 123","%s", dest, -1);
    assert(conv == 0);

    (void)strcpy_s(dest,DEST_BUFFER_SIZE, "asdfqwer");
    conv = sscanf_s("123asdfasdf1123","%[a-z",dest, DEST_BUFFER_SIZE);
    assert(conv == 0);
    assert( strcmp(dest, "") == 0);

    conv = sscanf_s(TEST_STR, "%f",  &fv);
    assert(conv == 1);

    conv = sscanf_s(TEST_STR2, "%f",  &fv);
    assertFloatEqu(fv, 1111111111.0f);
    assert(conv == 1);

    conv = sscanf_s("32145.1415926", "%f",  &fv);
    assert(conv == 1);

    (void)strcpy_s(src, DEST_BUFFER_SIZE, "123 567.4 asdfqwer");
    conv = sscanf_s(src, "%d%f%s", &iv, &fv, dest,DEST_BUFFER_SIZE);
    assert(conv == 3);
    assert( strcmp(dest, "asdfqwer") == 0);
    assert( iv == 123 );
    assertFloatEqu(fv, 567.4f);
#ifndef SECUREC_VXWORKS_PLATFORM
    conv = swscanf_s(TEST_WSTR, L"%f",  &fv);
    assertFloatEqu(fv, 1111111111.0f);
    assert(conv == 1);

    conv = swscanf_s(wStr, L"%d%f%100ls", &iv, &fv, wDest, DEST_BUFFER_SIZE );
    assert(conv == 3 );
    assert(my_wcscmp(wDest, L"asdfqwer") == 0);
    assert(iv == 123 );
    assertFloatEqu(fv, 5689.4f);
#endif

    ret = sscanf_s("", "%10s", dest, DEST_BUFFER_SIZE);    
    assert(ret == -1);

    ret = sscanf_s("123", "%10s", dest, DEST_BUFFER_SIZE);    
    assert(strcmp(dest, "123") == 0);

    /*2014 add test case*/
    ret = sscanf_s("12345678", "%3s", NULL, DEST_BUFFER_SIZE);    
    assert( ret == -1);

    ret = sscanf_s("12345678", "%3s", dest, DEST_BUFFER_SIZE);    
    assert(strcmp(dest, "123") == 0);

    (void)sscanf_s("123", "%8s",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123") == 0);

    (void)sscanf_s("31.415926358", "%f",&fv);
    assertFloatEqu(fv, 31.415926358f);

    (void)sscanf_s("31.415926358", "%4f",&fv);
    assertFloatEqu(fv, 31.4f);

    (void)sscanf_s("31.415926358", "%6f",&fv);
    assertFloatEqu(fv, 31.415f);

    (void)sscanf_s("2147483647", "%d",&d);
    assert(d == 2147483647);
        
    (void)sscanf_s("2147483648", "%d",&d);
#if (defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    assert(d == (-2147483647L - 1));
#else
#if defined(SECUREC_ON_64BITS)
    assert(d == -2147483648L);
#else 
    assert(d == 2147483647L);
#endif
#endif


    (void)sscanf_s("2147483648", "%u",&ui);
    assert(ui == 2147483648UL);

    ret = sscanf_s("10 0x1b aaaaaaaa bbbbbbbb","%d %x %5[a-z] %*s %f",&d,&a,dest, DEST_BUFFER_SIZE,dest, DEST_BUFFER_SIZE);
    assert(ret == 3);
    assert(d ==10);
    assert(a ==27);
    assert(strcmp(dest, "aaaaa") == 0);

    (void)sscanf_s("-2147483648", "%d",&d);
    assert(d == (-2147483647-1));
    
#if (defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    (void)sscanf_s("3147483647", "%d",&d);
    assert(d == -1147483649);
#else
#if defined(SECUREC_ON_64BITS)
    (void)sscanf_s("3147483647", "%d",&d);
    assert(d == -1147483649);
#else 
    (void)sscanf_s("3147483647", "%d",&d);
    assert(d == 2147483647L);
#endif
#endif    

    (void)sscanf_s("789456", "%i",&d);
    assert(d == 789456);


    (void)sscanf_s("1234567890", "%1s", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "1") == 0);

    (void)sscanf_s("2006:03:18", "%d:%d:%d", &a, &b, &c);
    assert(a == 2006 && b == 3 && c ==18);

    (void)sscanf_s("1234567890", "%2s%3s", dest, DEST_BUFFER_SIZE,dest2, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "12") == 0);
    assert(strcmp(dest2, "345") == 0);

    ret = sscanf_s("hello, world", "%*s%s", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "world") == 0);

    ret = sscanf_s("wpc:123456", "%127[^:]:%127[^ ]", dest, DEST_BUFFER_SIZE, dest2, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "wpc") == 0);
    assert(strcmp(dest2, "123456") == 0);

    memset(dest, 0, DEST_BUFFER_SIZE);
    (void)sscanf_s("abc-123", "%[]a-z0-9_-.]", dest, DEST_BUFFER_SIZE);
#if (defined(_WIN32) || defined(_WIN64))
    assert(strcmp(dest, "abc") == 0);
#else
    assert(strcmp(dest, "abc-123") == 0);
#endif

    memset(dest, 0, DEST_BUFFER_SIZE);
    (void)sscanf_s("abc-123", "%[a-z0-9_-.", dest, DEST_BUFFER_SIZE);
    assert(strlen(dest) == 0);
    
    memset(dest, 0, DEST_BUFFER_SIZE);
    (void)sscanf_s("abc-123", "%{a-z0-9-]", dest, DEST_BUFFER_SIZE);
#if (defined(_WIN32) || defined(_WIN64))
    assert(strcmp(dest, "abc-123") == 0);
#else
    assert(strlen(dest) == 0);
#endif

    ret = sscanf("2006:03:18 - 2006:04:18", "%[0-9:] - %[0-9:]", sztime1, sztime2); 
    assert(2 == ret);
    assert(strcmp(sztime1, "2006:03:18") == 0);
    assert(strcmp(sztime2, "2006:04:18") == 0);

    (void)sscanf_s("0001A", "%4x", &iv);
    assert(iv == 1);

    (void)sscanf_s("0001A", "%x", &iv);
    assert(iv == 26);

    (void)sscanf_s("123456 ", "%4s", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "1234") == 0);

    (void)sscanf_s("a", "%4s", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "a") == 0);

    (void)sscanf_s("123456abcdedfBCDEF", "%[1-9a-z]", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456abcdedf") == 0);

    (void)sscanf_s("123456abcdedfBCDEF","%[1-9A-Z]",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456") == 0);

    (void)sscanf_s("123456abcdedfBCDEF", "%[^A-Z]", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456abcdedf") == 0);

    ret = sscanf_s("iios/12DDWDFF@122", "%*[^/]/%[^@]", dest, DEST_BUFFER_SIZE);
    assert(1 == ret);
    assert(strcmp(dest, "12DDWDFF") == 0);

    ret = sscanf_s("hello, world", "%*s%s",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "world") == 0);

    ret = sscanf_s("parent 2","%*s%d",&d);            /*Can Parse Correctly*/
    assert(1 == ret);
    assert(d == 2);

    (void)sscanf_s("parent25","parent%d",&d);            /* result 25 returned*/
    assert(d == 25);

    ret = sscanf_s("parent2","%*s%d",&d);          /*Cannot parse because %s is assigned "parent2"*/
    assert(ret == 0);


    ret = sscanf_s("parent2","%*6s%d",&d);         /*Can Parse Corrently Because width specified*/
    assert(ret == 1);
    assert(d == 2);

    ret = sscanf_s("parent2","%*[a-z]%d",&d);      /*Parse Correctly use WildCard*/
    assert(ret == 1);
    assert(d == 2);

    ret =  sscanf_s("parent2parent","%*[a-z]%d",&d);    /*Parse Correctly use WildCard*/
    assert(ret == 1);
    assert(d == 2);

    (void)sscanf_s("parent22parent","%*[a-z]%1d",&d);    /*result 2 returned*/
    assert(d == 2);

    (void)sscanf_s("asd/35@32","%*[^/]/%d",&d);        /*result 35 returned*/
    assert(d == 35);


    (void)sscanf_s( "iios/12DDWDFF@122", "%*[^/]/%[^@]", dest,DEST_BUFFER_SIZE); 
    assert(strcmp(dest, "12DDWDFF") == 0);


    (void)sscanf_s("123456 ","%s", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456") == 0);

    (void)sscanf_s("123456 ","%4s",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "1234") == 0);

    (void)sscanf_s("123456 abcdedf","%[^ ]",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456") == 0);

    (void)sscanf_s("123456abcdedfBCDEF","%[1-9a-z]",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456abcdedf") == 0);


    (void)sscanf_s("123456abcdedfBCDEF","%[^A-Z]",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456abcdedf") == 0);


    (void)sscanf_s( tokenstring, "%80s", dest, DEST_BUFFER_SIZE ); 
    assert(strcmp(dest, "15") == 0);

    (void)sscanf_s( tokenstring, "%c", &ch, sizeof(char) ); 
    assert(ch == '1');

    (void)sscanf_s( tokenstring, "%d", &i );  
    assert(i == 15);

    (void)sscanf_s( tokenstring, "%f", &fv ); 
    assertFloatEqu(fv, 15.0f);

    (void)sscanf_s("2006:03:18-2006:04:18", "%[0-9,:]-%[0-9,:]", dest,DEST_BUFFER_SIZE, dest2, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "2006:03:18") == 0);
    assert(strcmp(dest2, "2006:04:18") == 0);
    
    for(i = 0,d = 10;clearfmts[i] != NULL;++i)
    {
        memset(dest,0xA,sizeof(dest));
        (void)sscanf_s( "", clearfmts[i], dest, DEST_BUFFER_SIZE,&d);  
        assert(*dest == '\0');
        assert(d == 10);
    }
#ifdef SECUREC_VXWORKS_PLATFORM
    for(i = 0,d = 10;clearfmts4white[i] != NULL;++i)
    {
        memset(dest,0xA,sizeof(dest));
        (void)sscanf_s( "\n", clearfmts4white[i], dest, DEST_BUFFER_SIZE,&d);  
        assert(*dest == '\0');
        assert(d == 10);
    }
#endif
    memset(dest,0x0,sizeof(dest));
    d=10;
    (void)sscanf_s( "\n", "%[\n] %d", dest, DEST_BUFFER_SIZE,&d);  
    assert(*dest == 0xA);
    assert(d == 10);

    memset(dest,0x0,sizeof(dest));
    d=10;
    (void)sscanf_s( "\n", "%c %d", dest, DEST_BUFFER_SIZE,&d);  
    assert(*dest == 0xA);
    assert(d == 10);
    
    memset(dest,0xB,sizeof(dest));
    d=10;
    (void)sscanf_s( "\n", "%[a] %d", dest, DEST_BUFFER_SIZE,&d);  
    assert(*dest == 0xB);
    assert(d == 10);
    
    memset(dest,0xA,sizeof(dest));
    d=10;
    (void)sscanf_s( "", "%[] %d", dest, DEST_BUFFER_SIZE,&d);  
    assert(*dest == 0xA);
    assert(d == 10);

    d=10;
    (void)sscanf_s( "", "n%s %d", NULL, DEST_BUFFER_SIZE,&d);  
    assert(d == 10);
    
    d=10;
    (void)sscanf_s( "", "", NULL, DEST_BUFFER_SIZE,&d);  
    assert(d == 10);

#if !(defined(_WIN32) || defined(_WIN64))
    memset(dest,0xA,sizeof(dest));
    (void)sscanf_s("","%{a] %d", dest, DEST_BUFFER_SIZE,&d);  
    assert(*dest == 0xA);
    assert(d == 10);
#endif

    memset(dest,0xA,sizeof(dest));
    (void)sscanf_s("", "%[] %d", dest, DEST_BUFFER_SIZE,&d);  
    assert(*dest == 0xA);
    assert(d == 10);

    memset(dest,0xA,sizeof(dest));
    (void)sscanf_s("", "%d %d", dest, DEST_BUFFER_SIZE,&d);  
    assert(*dest == 0xA);
    assert(d == 10);

#ifndef SECUREC_VXWORKS_PLATFORM
    d = 10;
    memset(wDest,0xA,sizeof(wDest));
    (void)sscanf_s("", "%ls %d", wDest, DEST_BUFFER_SIZE,&d);  
    assert(my_wcscmp(wDest, L"") == 0);
    assert(d == 10);

    memset(wDest,0xA,sizeof(wDest));
    (void)sscanf_s("", "%S %d", wDest, DEST_BUFFER_SIZE,&d);  
    assert(my_wcscmp(wDest, L"") == 0);
    assert(d == 10);

#endif

   
    conv = sscanf_s("3.456789","%lg",&dblVal);
    assert(conv == 1);

    if (sizeof(void*) == sizeof(INT64T)) 
    {
        INT64T d1,d2;
        sscanf_s("123,123","%Id,%Iu",&d1,&d2);
        assert(d1 == 123);
        assert(d2 == 123);
    }
    else
    {
        INT32T d1,d2;
        sscanf_s("123,123","%Id,%Iu",&d1,&d2);
        assert(d1 == 123);
        assert(d2 == 123);
    }



#if (defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__UNIX)))
    {
        INT64T d1 = 0;
        int d2 = 0;
        short d3 = 0;
        long l1 = 0;

        sscanf_s("18446744073709551620","%lld",&d1);
        assert(d1 ==  9223372036854775807ULL);

        sscanf_s("9223372036854775808","%lld",&d1);
        assert(d1 ==  9223372036854775807ULL);

        sscanf_s("-18446744073709551620","%lld",&d1);
        assert(d1 ==  (-9223372036854775807LL - 1));

        sscanf_s("-9223372036854775809","%lld",&d1);
        assert(d1 ==  (-9223372036854775807LL - 1));

 
        sscanf_s("4294967300","%d",&d2); /*> MAX_32BITS_VALUE_DIV_TEN*/
        printf("%d\n",d2);

        sscanf_s("-4294967300","%d",&d2); /*> MAX_32BITS_VALUE_DIV_TEN*/
        printf("%d\n",d2);

        sscanf_s("2147483649","%d",&d2); /* > MIN_32BITS_NEG_VALUE*/
        printf("%d\n",d2);

        sscanf_s("-2147483649","%d",&d2);  
        printf("%d\n",d2);

        d3=0;
        sscanf_s("4294967300","%hd",&d3);
        printf("%hd\n",d3);

        d3=0;
        sscanf_s("-4294967300","%hd",&d3);  
        printf("%hd\n",d3);

        sscanf_s("4294967300","%ld",&l1);
        printf("%ld\n",l1);

        sscanf_s("-4294967300","%ld",&l1);  
        printf("%ld\n",l1);


        sscanf_s("2147483649","%ld",&l1);
        printf("%ld\n",l1);

        sscanf_s("-2147483649","%ld",&l1); 
        printf("%ld\n",l1);

    }
#endif

}

int indirect_sscanf(const char* str, const char* format, ...)
{
    va_list args;
    int ret = 0;
    
    va_start( args, format );
    ret = vsscanf_s(str, format, args ) ;
    va_end(args);
    return ret;
    
}
void test_vsscanf(void)
{

    char dest[DEST_BUFFER_SIZE] = {0};
    char dest2[DEST_BUFFER_SIZE] = {0};
#ifndef SECUREC_VXWORKS_PLATFORM
    wchar_t wDest[DEST_BUFFER_SIZE] = {0};
#endif
    /*char inputStr[] = "123 567.4 asdfqwer";*/
 #ifndef SECUREC_VXWORKS_PLATFORM
    wchar_t wStr[] = L"123 5689.4 asdfqwer";
#endif

    char src[SRC_BUFFER_SIZE] = "abcd";
    /*char str[512] = {0};*/

    int iv = 0xFF,     ret ;
    float fv = 0;
    int conv = 0;
    /*unsigned short wv = iv;
    char* pTest = dest;*/
    unsigned int  ui = 0;
    int a, b ,c,d = 0;
    char  tokenstring[] = "15 12 14...";
    /*char  s[81] = {0};*/
    char  ch;
    int   i;
    /*float fp = 0.0f;*/


    /*int j = 0;*/


    (void)strcpy_s(src, DEST_BUFFER_SIZE, "123 567.4 asdfqwer");
    conv = indirect_sscanf(src, "%d%f%s", &iv, &fv, dest,DEST_BUFFER_SIZE);
    assert(conv == 3);
    assert( strcmp(dest, "asdfqwer") == 0);
    assert( iv == 123 );
    assertFloatEqu(fv, 567.4f);

#ifndef SECUREC_VXWORKS_PLATFORM
    conv = swscanf_s(wStr, L"%d%f%100ls", &iv, &fv, wDest, DEST_BUFFER_SIZE );
    assert(conv == 3 );
    assert(my_wcscmp(wDest, L"asdfqwer") == 0);
    assert(iv == 123 );
    assertFloatEqu(fv, 5689.4f);
#endif

    ret = sprintf_s(dest, DEST_BUFFER_SIZE, "asdasd%s", (char *)NULL);
    /*assert(0);*/

    ret = indirect_sscanf("", "%10s", dest, DEST_BUFFER_SIZE);    
    assert(ret == -1);

    ret = indirect_sscanf("123", "%10s", dest, DEST_BUFFER_SIZE);    
    assert(strcmp(dest, "123") == 0);

    /*2014 add test case*/
    ret = indirect_sscanf("12345678", "%3s", NULL, DEST_BUFFER_SIZE);    
    assert( ret == -1);

    ret = indirect_sscanf("12345678", "%3s", dest, DEST_BUFFER_SIZE);    
    assert(strcmp(dest, "123") == 0);

    (void)indirect_sscanf("123", "%8s",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123") == 0);

    (void)indirect_sscanf("31.415926358", "%f",&fv);
    assertFloatEqu(fv, 31.415926358f);

    (void)indirect_sscanf("31.415926358", "%4f",&fv);
    assertFloatEqu(fv, 31.4f);

    (void)indirect_sscanf("31.415926358", "%6f",&fv);
    assertFloatEqu(fv, 31.415f);

    (void)indirect_sscanf("2147483647", "%d",&d);
    assert(d == 2147483647);
    
#if (defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    (void)indirect_sscanf("2147483648", "%d",&d);
    assert(d == (-2147483647L - 1));
#else
#if defined(SECUREC_ON_64BITS)
    (void)indirect_sscanf("2147483648", "%d",&d);
    assert(d == -2147483648L);
#else 
    (void)indirect_sscanf("2147483648", "%d",&d);
    assert(d == 2147483647L);
#endif
#endif

    (void)indirect_sscanf("2147483648", "%u",&ui);
    assert(ui == 2147483648UL);

    (void)indirect_sscanf("10 0x1b aaaaaaaa bbbbbbbb","%d %x %5[a-z] %*s %f",&d,&a,dest, DEST_BUFFER_SIZE,dest, DEST_BUFFER_SIZE);
    assert(d ==10);
    assert(a ==27);
    assert(strcmp(dest, "aaaaa") == 0);

    (void)indirect_sscanf("-2147483648", "%d",&d);
    assert(d == -2147483647-1);

#if (defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    (void)indirect_sscanf("3147483647", "%d",&d);
    assert(d == -1147483649);
#else
#if defined(SECUREC_ON_64BITS)
    (void)indirect_sscanf("3147483647", "%d",&d);
    assert(d == -1147483649);
#else 
    (void)indirect_sscanf("3147483647", "%d",&d);
    assert(d == 2147483647L);
#endif
#endif

    (void)indirect_sscanf("789456", "%i",&d);
    assert(d == 789456);


    (void)indirect_sscanf("1234567890", "%1s", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "1") == 0);

    (void)indirect_sscanf("2006:03:18", "%d:%d:%d", &a, &b, &c);
    assert(a == 2006 && b == 3 && c ==18);

    (void)indirect_sscanf("1234567890", "%2s%3s", dest, DEST_BUFFER_SIZE,dest2, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "12") == 0);
    assert(strcmp(dest2, "345") == 0);

    (void)indirect_sscanf("hello, world", "%*s%s", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "world") == 0);

    (void)indirect_sscanf("wpc:123456", "%127[^:]:%127[^ ]", dest, DEST_BUFFER_SIZE, dest2, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "wpc") == 0);
    assert(strcmp(dest2, "123456") == 0);


    (void)indirect_sscanf("0001A", "%4x", &iv);
    assert(iv == 1);

    (void)indirect_sscanf("0001A", "%x", &iv);
    assert(iv == 26);

    (void)indirect_sscanf("123456 ", "%4s", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "1234") == 0);

    (void)indirect_sscanf("a", "%4s", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "a") == 0);

    (void)indirect_sscanf("123456abcdedfBCDEF", "%[1-9a-z]", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456abcdedf") == 0);

    (void)indirect_sscanf("123456abcdedfBCDEF","%[1-9A-Z]",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456") == 0);

    (void)indirect_sscanf("123456abcdedfBCDEF", "%[^A-Z]", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456abcdedf") == 0);

    (void)indirect_sscanf("iios/12DDWDFF@122", "%*[^/]/%[^@]", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "12DDWDFF") == 0);

    (void)indirect_sscanf("hello, world", "%*s%s",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "world") == 0);

    (void)indirect_sscanf("parent 2","%*s%d",&d);            /*Can Parse Correctly*/
    assert(d == 2);

    (void)indirect_sscanf("parent25","parent%d",&d);            /* result 25 returned*/
    assert(d == 25);

    ret = indirect_sscanf("parent2","%*s%d",&d);          /*Cannot parse because %s is assigned "parent2"*/
    assert(ret == 0);


    ret = indirect_sscanf("parent2","%*6s%d",&d);         /*Can Parse Corrently Because width specified*/
    assert(ret == 1);
    assert(d == 2);

    ret = indirect_sscanf("parent2","%*[a-z]%d",&d);      /*Parse Correctly use WildCard*/
    assert(ret == 1);
    assert(d == 2);

    ret =  indirect_sscanf("parent2parent","%*[a-z]%d",&d);    /*Parse Correctly use WildCard*/
    assert(ret == 1);
    assert(d == 2);

    (void)indirect_sscanf("parent22parent","%*[a-z]%1d",&d);    /*result 2 returned*/
    assert(d == 2);

    (void)indirect_sscanf("asd/35@32","%*[^/]/%d",&d);        /*result 35 returned*/
    assert(d == 35);


    (void)indirect_sscanf( "iios/12DDWDFF@122", "%*[^/]/%[^@]", dest,DEST_BUFFER_SIZE); 
    assert(strcmp(dest, "12DDWDFF") == 0);


    (void)indirect_sscanf("123456 ","%s", dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456") == 0);

    (void)indirect_sscanf("123456 ","%4s",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "1234") == 0);

    (void)indirect_sscanf("123456 abcdedf","%[^ ]",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456") == 0);

    (void)indirect_sscanf("123456abcdedfBCDEF","%[1-9a-z]",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456abcdedf") == 0);


    (void)indirect_sscanf("123456abcdedfBCDEF","%[^A-Z]",dest, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "123456abcdedf") == 0);


    (void)indirect_sscanf( tokenstring, "%80s", dest, DEST_BUFFER_SIZE ); 
    assert(strcmp(dest, "15") == 0);

    (void)indirect_sscanf( tokenstring, "%c", &ch, sizeof(char) ); 
    assert(ch == '1');

    (void)indirect_sscanf( tokenstring, "%d", &i );  
    assert(i == 15);

    (void)indirect_sscanf( tokenstring, "%f", &fv ); 
    assertFloatEqu(fv, 15.0f);

    (void)indirect_sscanf("2006:03:18-2006:04:18", "%[0-9,:]-%[0-9,:]", dest,DEST_BUFFER_SIZE, dest2, DEST_BUFFER_SIZE);
    assert(strcmp(dest, "2006:03:18") == 0);
    assert(strcmp(dest2, "2006:04:18") == 0);

    {
#ifndef SECUREC_VXWORKS_PLATFORM
        wchar_t wch = 0,wch2 = 0;
        wchar_t wDest[DEST_BUFFER_SIZE] = {0};
        wchar_t wDest2[DEST_BUFFER_SIZE] = {0};
#endif
        char ch2 = 0;
        int o = 0,o2 = 0,u = 0,u2 = 0,x = 0,x2 = 0;
        short hd = 0,hd2 = 0;
        long int ld = 0 ,ld2 = 0;
        INT64T I64d = 0,I64d2 = 0,Ld = 0,Ld2 = 0,lld = 0,lld2 = 0;
        float f = 0,f2 = 0,e = 0,e2 = 0,g = 0,g2 = 0;
        double lf = 0.0,lf2 = 0.0;
        char *p = NULL,*p2 = NULL;

#ifdef SECUREC_SUPPORT_STRTOLD
        long double llf,llf2,Lf,Lf2;
        char *fmts_L_efg[] = 
        {
            "%Lf,%Lf %llf,%llf",
            "%Le,%Le %lle,%lle",
            "%Lg,%Lg %llg,%llg",
            NULL
        };
#endif
        char *fmts_dioux[] = 
        {
            "%hhd,%hhd %d,%d %hd,%hd %ld,%ld %lld,%lld %Ld,%Ld %I64d,%I64d",
            "%hhi,%hhi %i,%i %hi,%hi %li,%li %lli,%lli %Li,%Li %I64i,%I64i",     
            "%hho,%hho %o,%o %ho,%ho %lo,%lo %llo,%llo %Lo,%Lo %I64o,%I64o",
            "%hhu,%hhu %u,%u %hu,%hu %lu,%lu %llu,%llu %Lu,%Lu %I64u,%I64u",
            "%hhx,%hhx %x,%x %hx,%hx %lx,%lx %llx,%llx %Lx,%Lx %I64x,%I64x",
            NULL
        };
        char *fmts_efg[] = 
        {
            "%f,%f %lf,%lf",
            "%e,%e %le,%le",
            "%g,%g %lg,%lg",
    
            NULL
        };

 
        conv = indirect_sscanf("1,2 a,b 1,2 3,4 5,6 7,8 c,d 1.1e01,2.2e02 3.3,4.4 5.5,6.6 str1 str2"
                                ,"%p,%p %c,%c %d,%d %i,%i %o,%o %u,%u %x,%x %e,%e %f,%f %g,%g %s %s"
                                ,&p,&p2
                                ,&ch,sizeof(char),&ch2,sizeof(char)
                                ,&a,&b
                                ,&c,&d
                                ,&o,&o2
                                ,&u,&u2
                                ,&x,&x2
                                ,&e,&e2
                                ,&f,&f2
                                ,&g,&g2
                                ,dest,sizeof(dest)
                                ,dest2,sizeof(dest2));
        assert(conv == 22);
        assert(ch =='a');
        assert(ch2 =='b');
        assert(a == 1);
        assert(b == 2);
        assert(c == 3);
        assert(d == 4);
        assert(o == 5);
        assert(o2 == 6);
        assert(u == 7);
        assert(u2 == 8);
        assert(x == 0xc);
        assert(x2 == 0xd);
        assert(0 == assertFloatEqu(e,1.1e01f));
        assert(0 == assertFloatEqu(e2,2.2e02f));
        assert(0 == assertFloatEqu(f,3.3f));
        assert(0 == assertFloatEqu(f2,4.4f));
        assert(0 == assertFloatEqu(g, 5.5f));
        assert(0 == assertFloatEqu(g2,6.6f));
        assert(strcmp(dest, "str1") == 0);
        assert(strcmp(dest2, "str2") == 0);
        assert(p == (char *)1);
        assert(p2 == (char *)2);


        conv = indirect_sscanf("str2,str1,","%[^,],%[^,]",dest,sizeof(dest),dest2,sizeof(dest2));
        assert(conv == 2);
        assert(strcmp(dest, "str2") == 0);
        assert(strcmp(dest2, "str1") == 0);

#ifndef SECUREC_VXWORKS_PLATFORM
        conv = indirect_sscanf("a,b","%lc,%lc",&wch,sizeof(wch),&wch2,sizeof(wch2));
        assert(conv == 2);
        assert(wch == L'a');
        assert(wch2 == L'b');

        conv = indirect_sscanf("str1,str2,","%l[^,],%l[^,]",wDest,sizeof(wDest)/sizeof(wchar_t),wDest2,sizeof(wDest2)/sizeof(wchar_t));
        assert(conv == 2);
        assert(my_wcscmp(wDest, L"str1") == 0);
        assert(my_wcscmp(wDest2, L"str2") == 0);

        conv = indirect_sscanf("str2 str1","%ls %ls",wDest,sizeof(wDest)/sizeof(wchar_t),wDest2,sizeof(wDest2)/sizeof(wchar_t));
        assert(conv == 2);
        assert(my_wcscmp(wDest, L"str2") == 0);
        assert(my_wcscmp(wDest2, L"str1") == 0);
#endif
        for(i=0;fmts_dioux[i] != NULL;i++)
        {
            conv = indirect_sscanf("1,2 3,4 5,6 7,7 6,5 4,3 2,1"
                                    ,fmts_dioux[i]
                                    ,&ch,&ch2
                                    ,&a,&b
                                    ,&hd,&hd2
                                    ,&ld,&ld2
                                    ,&lld,&lld2
                                    ,&Ld,&Ld2
                                    ,&I64d,&I64d2);
            assert(conv == 14);
            assert(ch == 1);
            assert(ch2 == 2);
            assert(a == 3);
            assert(b == 4);
            assert(hd == 5);
            assert(hd2 == 6);
            assert(ld == 7);
            assert(ld2 == 7);
            assert(lld == 6);
            assert(lld2 == 5);
            assert(Ld == 4);
            assert(Ld2 == 3);
            assert(I64d == 2);
            assert(I64d2 == 1);
        }

        for(i=0;fmts_efg[i] != NULL;i++)
        {
            conv = indirect_sscanf("1.1,2.2 3.3,4.4"
                                    ,fmts_efg[i]
                                    ,&f,&f2
                                    ,&lf,&lf2
                                    );
            assert(conv == 4);
            assertFloatEqu(f,1.1f);
            assertFloatEqu(f2,2.2f);
            assert(Equal_l(lf,3.3f));
            assert(Equal_l(lf2,4.4f));
        }

#ifdef SECUREC_SUPPORT_STRTOLD
        for(i=0;fmts_L_efg[i] != NULL;i++)
        {
            conv = indirect_sscanf("1.1,2.2 3.3,4.4"
                                    ,fmts_L_efg[i]
                                    ,&Lf,&Lf2
                                    ,&llf,&llf2
                                    );
            assert(conv == 4);
            assert(Equal_ll(Lf,1.1L));
            assert(Equal_ll(Lf2,2.2L));
            assert(Equal_ll(llf,3.3L));
            assert(Equal_ll(llf2,4.4L));
        }
#endif
    }
}

#ifndef SECUREC_VXWORKS_PLATFORM
void testSwscanf(void)
{
    wchar_t wDest[DEST_BUFFER_SIZE] = {0};
    int a, b ,c = 0,conv= 0;

    (void)swscanf_s(L"2006:03:18", L"%d:%d:%d", &a, &b, &c);
    assert(a == 2006 && b == 3 && c ==18);

    (void)swscanf_s(L"123456 ",L"%ls", wDest, DEST_BUFFER_SIZE);
    assert(my_wcscmp(wDest, L"123456") == 0);

    (void)swscanf_s(L"123456 ",L"%4ls",wDest, DEST_BUFFER_SIZE);
    assert(my_wcscmp(wDest, L"1234") == 0);

    (void)swscanf_s(L"123456 abcdedf",L"%l[^ ]",wDest, DEST_BUFFER_SIZE);
    assert(my_wcscmp(wDest, L"123456") == 0);

    *wDest=L'a';
    c = swscanf_s(L"", L"%ls", wDest, DEST_BUFFER_SIZE );
    assert(c == -1 );
    assert(my_wcscmp(wDest, L"") == 0);
    

    wDest[1]=L'\0';
    *wDest=L'a';
    conv = swscanf_s(L"", L"%ls", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"") == 0);
/*
    *wDest=L'a';
    conv = swscanf_s(L"\n", L"%ls", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"") == 0);
*/
    *wDest=L'a';
    conv = swscanf_s(L"", L"%10ls", wDest, DEST_BUFFER_SIZE );
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
    conv = swscanf_s(L"", L"%l[]", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"a") == 0);

#if !(defined(_WIN32) || defined(_WIN64))
    *wDest=L'a';
    conv = swscanf_s(L"", L"%l{a]", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"a") == 0);
#endif

     *wDest=L'a';
    conv = swscanf_s(L"", L"%l[^]a]", wDest, DEST_BUFFER_SIZE );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"") == 0);

     *wDest=L'a';
    conv = swscanf_s(L"", L"aa%ls", wDest, 0 );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"a") == 0);

    *wDest=L'a';
    conv = swscanf_s(L"", L"", wDest, 0 );
    assert(conv == -1 );
    assert(my_wcscmp(wDest, L"a") == 0);
}
#endif
#ifndef SECUREC_VXWORKS_PLATFORM
int indirect_swscanf(const wchar_t* str, const wchar_t* format, ...)
{
    va_list args;
    int ret = 0;
    
    va_start( args, format );
    ret = vswscanf_s(str, format, args ) ;
    va_end(args);
    return ret;
    
}
#endif
#ifndef SECUREC_VXWORKS_PLATFORM
void test_vswscanf(void)
{
    wchar_t wDest[DEST_BUFFER_SIZE] = {0};
    int a, b ,c = 0;

    (void)indirect_swscanf(L"2006:03:18", L"%d:%d:%d", &a, &b, &c);
    assert(a == 2006 && b == 3 && c ==18);

    (void)indirect_swscanf(L"123456 ",L"%ls", wDest, DEST_BUFFER_SIZE);
    assert(my_wcscmp(wDest, L"123456") == 0);

    (void)indirect_swscanf(L"123456 ",L"%4ls",wDest, DEST_BUFFER_SIZE);
    assert(my_wcscmp(wDest, L"1234") == 0);

    (void)indirect_swscanf(L"123456 abcdedf",L"%l[^ ]",wDest, DEST_BUFFER_SIZE);
    assert(my_wcscmp(wDest, L"123456") == 0);
}
#endif
void testfscanf(void)
{

    char filename[256];
    char dest[DEST_BUFFER_SIZE] = {0};
    char dest2[DEST_BUFFER_SIZE] = {0};
    int fileId = 0;
    FILE* pf;
    char  ch;
    float fv = 0;
    int a, b ,c,d = 0, iv=0, i =0;

    (void)sprintf_s(filename, 256, FSCANF_FILES_PATH("f%d.txt"),fileId );

    while( (pf =  fopen(filename,"r")) != NULL){
        switch(fileId){
            case 0:
                (void)fscanf_s(pf, "%d:%d:%d", &a, &b, &c);
                assert(a == 2006 && b == 3 && c ==18);
                break;

            case 1:
                (void)fscanf_s(pf, "%2s%3s", dest, DEST_BUFFER_SIZE,dest2, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "12") == 0);
                assert(strcmp(dest2, "345") == 0);
                break;

            case 2:
                (void)fscanf_s(pf, "%*s%s", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "world") == 0);
                break;
            case 3:
                (void)fscanf_s(pf, "%127[^:]:%127[^ ]", dest, DEST_BUFFER_SIZE, dest2, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "wpc") == 0);
                assert(strcmp(dest2, "123456") == 0);
                break;
            case 4:
                (void)fscanf_s(pf, "%4x", &iv);
                assert(iv == 1);
                break;
            case 5:
                (void)fscanf_s(pf, "%x", &iv);
                assert(iv == 26);
                break;
            case 6:
                (void)fscanf_s(pf, "%4s", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "1234") == 0);
                break;
            case 7:
                (void)fscanf_s(pf, "%4s", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "a") == 0);
                break;
            case 8:
                (void)fscanf_s(pf, "%[1-9a-z]", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456abcdedf") == 0);
                break;
            case 9:
                (void)fscanf_s(pf, "%[1-9A-Z]",dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456") == 0);
                break;
            case 10:
                (void)fscanf_s(pf, "%[^A-Z]", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456abcdedf") == 0);
                break;
            case 11:
                (void)fscanf_s(pf, "%*[^/]/%[^@]", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "12DDWDFF") == 0);
                break;
            case 12:
                (void)fscanf_s(pf, "%*s%s",dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "world") == 0);
                break;
            case 13:
                (void)fscanf_s(pf,"%*s%d",&d);            /*Can Parse Correctly*/
                assert(d == 2);
                break;
            case 14:
                (void)fscanf_s(pf,"parent%d",&d);            /* result 25 returned*/
                assert(d == 25);
                break;
            case 15:
                (void)fscanf_s(pf,"%*[a-z]%1d",&d);    /*result 2 returned*/
                assert(d == 2);
                break;
            case 16:
                (void)fscanf_s(pf,"%*[^/]/%d",&d);        /*result 35 returned*/
                assert(d == 35);
                break;
            case 17:
                (void)fscanf_s(pf, "%*[^/]/%[^@]", dest,DEST_BUFFER_SIZE); 
                assert(strcmp(dest, "12DDWDFF") == 0);
                break;
            case 18:
                (void)fscanf_s(pf,"%s", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456") == 0);
                break;
            case 19:
                (void)fscanf_s(pf,"%4s",dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "1234") == 0);
                break;
            case 20:
                (void)fscanf_s(pf,"%[^ ]",dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456") == 0);
                break;
            case 21:
                (void)fscanf_s(pf, "%[1-9a-z]",dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456abcdedf") == 0);
                break;
            case 22:
                (void)fscanf_s(pf,"%[^A-Z]",dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456abcdedf") == 0);
                break;
            case 23:
                (void)fscanf_s(pf, "%80s", dest, DEST_BUFFER_SIZE ); 
                assert(strcmp(dest, "15") == 0);
                break;
            case 24:
                (void)fscanf_s(pf,  "%c", &ch, sizeof(char) ); 
                assert(ch == '1');
                break;
            case 25:
                (void)fscanf_s(pf,  "%d", &i );  
                assert(i == 15);
                break;
            case 26:
                (void)fscanf_s(pf,  "%f", &fv ); 
                assertFloatEqu(fv, 15.0f);
                break;
            case 27:
                (void)fscanf_s(pf,  "%[0-9,:]-%[0-9,:]", dest,DEST_BUFFER_SIZE, dest2, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "2006:03:18") == 0);
                assert(strcmp(dest2, "2006:04:18") == 0);
                break;
            case 28:
                break;

        }
        fclose(pf);

        fileId ++;
        (void)sprintf_s(filename, 256, FSCANF_FILES_PATH("f%d.txt"),fileId );
    }

    printf("fscanf test %d files\n", fileId);
    
}

#ifndef SECUREC_VXWORKS_PLATFORM
void test_fwscanf(void)
{
    FILE *stream;
    long l;
    float fp;
    wchar_t s[81];
    wchar_t c;
 
    if( (stream = fopen( "./fwscanf.out", "wb+" )) == NULL )
    {
        printf( "The file fwscanf.out was not opened\n" );
    }
    else
    {
    
        l = fwrite(L"a-string 65000 3.14159x",24 * sizeof(wchar_t), 1, stream);
    
        /* Set pointer to beginning of file:*/
        if ( fseek( stream, 0L, SEEK_SET ) )
        {
            #if __STDC_VERSION__ >= 199901L
            int rc = wprintf( L"fseek failed\n" );
            assert(rc == EOK);
            #endif
        }
        
        /* Read data back from file:*/
        (void)fwscanf_s( stream, L"%ls", s, 81 );
        (void)fwscanf_s( stream, L"%ld", &l );
        
        (void)fwscanf_s( stream, L"%f", &fp );
        (void)fwscanf_s( stream, L"%lc", &c, 1 );
        
        assert( my_wcscmp(s, L"a-string") == 0);
        assert(l == 65000);
        assertFloatEqu(fp, 3.14159F);
        assert(c == 'x');

        fclose( stream );
        
    }
}
#endif

int indirect_fscanf(FILE* file, const char* format, ...)
{
    va_list args;
    int ret = 0;
    
    va_start( args, format );
    ret = vfscanf_s(file, format, args ) ;
    va_end(args);
    return ret;
    
}

void test_vfscanf(void)
{

    char filename[256];
    char dest[DEST_BUFFER_SIZE] = {0};
    char dest2[DEST_BUFFER_SIZE] = {0};
    int fileId = 0;
    FILE* pf;
    char  ch;
    float fv = 0;
    int a, b ,c,d = 0, iv=0, i =0;

    (void)sprintf_s(filename, 256, FSCANF_FILES_PATH("f%d.txt"),fileId );

    while( (pf =  fopen(filename,"r")) != NULL){
        switch(fileId){
            case 0:
                (void)indirect_fscanf(pf, "%d:%d:%d", &a, &b, &c);
                assert(a == 2006 && b == 3 && c ==18);
                break;

            case 1:
                (void)indirect_fscanf(pf, "%2s%3s", dest, DEST_BUFFER_SIZE,dest2, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "12") == 0);
                assert(strcmp(dest2, "345") == 0);
                break;

            case 2:
                (void)indirect_fscanf(pf, "%*s%s", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "world") == 0);
                break;
            case 3:
                (void)indirect_fscanf(pf, "%127[^:]:%127[^ ]", dest, DEST_BUFFER_SIZE, dest2, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "wpc") == 0);
                assert(strcmp(dest2, "123456") == 0);
                break;
            case 4:
                (void)indirect_fscanf(pf, "%4x", &iv);
                assert(iv == 1);
                break;
            case 5:
                (void)indirect_fscanf(pf, "%x", &iv);
                assert(iv == 26);
                break;
            case 6:
                (void)indirect_fscanf(pf, "%4s", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "1234") == 0);
                break;
            case 7:
                (void)indirect_fscanf(pf, "%4s", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "a") == 0);
                break;
            case 8:
                (void)indirect_fscanf(pf, "%[1-9a-z]", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456abcdedf") == 0);
                break;
            case 9:
                (void)indirect_fscanf(pf, "%[1-9A-Z]",dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456") == 0);
                break;
            case 10:
                (void)indirect_fscanf(pf, "%[^A-Z]", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456abcdedf") == 0);
                break;
            case 11:
                (void)indirect_fscanf(pf, "%*[^/]/%[^@]", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "12DDWDFF") == 0);
                break;
            case 12:
                (void)indirect_fscanf(pf, "%*s%s",dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "world") == 0);
                break;
            case 13:
                (void)indirect_fscanf(pf,"%*s%d",&d);            /*Can Parse Correctly*/
                assert(d == 2);
                break;
            case 14:
                (void)indirect_fscanf(pf,"parent%d",&d);            /* result 25 returned*/
                assert(d == 25);
                break;
            case 15:
                (void)indirect_fscanf(pf,"%*[a-z]%1d",&d);    /*result 2 returned*/
                assert(d == 2);
                break;
            case 16:
                (void)indirect_fscanf(pf,"%*[^/]/%d",&d);        /*result 35 returned*/
                assert(d == 35);
                break;
            case 17:
                (void)indirect_fscanf(pf, "%*[^/]/%[^@]", dest,DEST_BUFFER_SIZE); 
                assert(strcmp(dest, "12DDWDFF") == 0);
                break;
            case 18:
                (void)indirect_fscanf(pf,"%s", dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456") == 0);
                break;
            case 19:
                (void)indirect_fscanf(pf,"%4s",dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "1234") == 0);
                break;
            case 20:
                (void)indirect_fscanf(pf,"%[^ ]",dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456") == 0);
                break;
            case 21:
                (void)indirect_fscanf(pf, "%[1-9a-z]",dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456abcdedf") == 0);
                break;
            case 22:
                (void)indirect_fscanf(pf,"%[^A-Z]",dest, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "123456abcdedf") == 0);
                break;
            case 23:
                (void)indirect_fscanf(pf, "%80s", dest, DEST_BUFFER_SIZE ); 
                assert(strcmp(dest, "15") == 0);
                break;
            case 24:
                (void)indirect_fscanf(pf,  "%c", &ch, sizeof(char) ); 
                assert(ch == '1');
                break;
            case 25:
                (void)indirect_fscanf(pf,  "%d", &i );  
                assert(i == 15);
                break;
            case 26:
                (void)indirect_fscanf(pf,  "%f", &fv ); 
                assertFloatEqu(fv, 15.0f);
                break;
            case 27:
                (void)indirect_fscanf(pf,  "%[0-9,:]-%[0-9,:]", dest,DEST_BUFFER_SIZE, dest2, DEST_BUFFER_SIZE);
                assert(strcmp(dest, "2006:03:18") == 0);
                assert(strcmp(dest2, "2006:04:18") == 0);
                break;
            case 28:
                break;

        }
        fclose(pf);

        fileId ++;
        (void)sprintf_s(filename, 256, FSCANF_FILES_PATH("f%d.txt"),fileId );
    }

    printf("vfscanf test %d files\n", fileId);
    
}

#ifndef SECUREC_VXWORKS_PLATFORM
int indirect_fwscanf(FILE* f, const wchar_t* format, ...)
{
    va_list args;
    int ret = 0;
    
    va_start( args, format );
    ret = vfwscanf_s(f, format, args ) ;
    va_end(args);
    return ret;
    
}
#endif
#ifndef SECUREC_VXWORKS_PLATFORM
void test_vfwscanf(void)
{
    FILE *stream;
    long l;
    float fp;
    wchar_t s[81];
    wchar_t c;
    #if __STDC_VERSION__ >= 199901L
    int rc;
    #endif

    if( (stream = fopen( "./vfwscanf.out", "wb+" )) == NULL )
    {
        #if __STDC_VERSION__ >= 199901L
        rc = wprintf( L"The file vfwscanf.out was not opened\n" );
        assert(rc == EOK);
        #endif
    }
    else
    {

        l = fwrite(L"a-string 65000 3.14159x", 24 * sizeof(wchar_t), 1, stream);
    
        /* Set pointer to beginning of file:*/
        if ( fseek( stream, 0L, SEEK_SET ) )
        {
            #if __STDC_VERSION__ >= 199901L
            rc = wprintf( L"fseek failed\n" );
            assert(rc == EOK);
            #endif
        }
        
        /* Read data back from file:*/
        (void)indirect_fwscanf(stream,L"%ls %ld %f%lc", s, 81,  &l, &fp,  &c, 1 );    

        assert( my_wcscmp(s, L"a-string") == 0);
        assert(l == 65000);
        assertFloatEqu(fp, 3.14159F);
        assert(c == 'x');
        
        fclose( stream );
        
    }
}
#endif

void testfscanf_multiline(void)
{
    int ulNum = 0;
    long aullreg[3] = {0};
    int i = 0;
    FILE *file = NULL;

    file = fopen(FSCANF_FILES_PATH("dosfmtasciifile.txt"), "r");
    if(NULL == file)
    {
        printf("File %s open fail!\n", FSCANF_FILES_PATH("dosfmtasciifile.txt"));
        return;
    }
 
    printf("------expected result:\nulNum = 0,0,0\nulNum = 1,1,0\nulNum = 2,0,0\nulNum = 3,1,0\nulNum = 4,0,0\nulNum = 5,1,0\nulNum = 6,0,0\n");
    printf("------actual result:\n");
    while (0 == feof(file))
    {
        (void)fscanf_s(file, "%x,", &ulNum);
        printf("ulNum = %x", ulNum);

        for(i = 0; i < 2; i++)
        {
            (void)fscanf_s(file, "%lx,", &aullreg[i]);
        }
        
        for( i = 0; i < 2; i++)
        {
            printf(",%lx", aullreg[i]);
        }
        printf("\n");
    }
    fclose(file);
    return;
}

void testfscanf_xmlspy(void)
{
    int ret=0;
    char cName[33]={0};
    FILE *file = NULL;

    printf("%s\n","------expected result:");
    file = fopen(FSCANF_FILES_PATH("fscanftest_xmlspy.xml"), "rF");
    if(NULL == file)
    {
        printf("File %s open fail!\n", FSCANF_FILES_PATH("fscanftest_xmlspy.xml"));
        return;
    }
    else
    {
        while (!feof(file))
        {
            ret=0;
            ret = fscanf(file, "\r\n%*[^<]");
            memset(cName,0,sizeof(cName));
            ret = fscanf(file, "<%32s", &cName[0]); 
            ret = fscanf(file, "%*[^>]"); 
            printf("info=%s\n,ret=%d\n",cName, ret);
            if(fgetc(file)==EOF)
            {
                printf("read fxml end\n");
            }
        }
    }
    fclose(file);
    
    file=NULL;
    printf("%s","------actual result:\n");
    file = fopen(FSCANF_FILES_PATH("fscanftest_xmlspy.xml"), "rF");
    if(NULL == file)
    {
        printf("File %s open fail!\n", FSCANF_FILES_PATH("fscanftest_xmlspy.xml"));
        return;
    }
    else
    {
        while (!feof(file))
        {
            ret=0;
            ret = fscanf_s(file, "\r\n%*[^<]");
            memset(cName,0,sizeof(cName));
            ret = fscanf_s(file, "<%32s", &cName[0],33); 
            ret = fscanf_s(file, "%*[^>]"); 
            printf("info=%s\n,ret=%d\n",cName, ret);
            if(fgetc(file)==EOF)
            {
                printf("read fxml end\n");
            }
        }
    }
    fclose(file);
}

void testfscanf_read1K(void)
{
    char buf[1025+1] = {0};
    int ret = 0;
    FILE *file = NULL;
    int len = 0;
    
    file = fopen(FSCANF_FILES_PATH("fscanf1k.txt"), "r");
    if(NULL == file)
    {
        printf("File %s open fail!\n", FSCANF_FILES_PATH("fscanf1k.txt"));
        return;
    }

    ret = fscanf_s(file, "%1025s", buf,sizeof(buf));
    len = strlen(buf);
    printf("fscanf_s  1K ret %d,buf len is %d\n", ret,len);
    assert(ret == 1);
   
    fclose(file);
    return;
}

void testsscanf_branches(void)
{
#ifndef SECUREC_VXWORKS_PLATFORM
    int ret =0;
    wchar_t wDest[DEST_BUFFER_SIZE] = {0};
#endif
     
#ifndef SECUREC_VXWORKS_PLATFORM
     ret = sscanf_s("abc","%ls",wDest,DEST_BUFFER_SIZE);
     assert(ret == 1);
#endif
    return;
}


void testfwscanf_read1K(void)
{
#ifndef SECUREC_VXWORKS_PLATFORM
    unsigned short wValue = 0x1234;
    char buf[1024+2] = {0};
    int ret = 0;
    FILE *file = NULL;
    int len = 0;
    char filename[256]={0};
    
    if (*(char*)&wValue == 0x12)
    {
        /* Big-Endian */
        if(sizeof(wchar_t) == 2)
        {
            strcpy(filename,FSCANF_FILES_PATH("fwscanf1kBigEndian2"));
        }
        else
        {
            strcpy(filename,FSCANF_FILES_PATH("fwscanf1kBigEndian4"));
        }
    }
    else
    {
        if(sizeof(wchar_t) == 2)
        {
            strcpy(filename,FSCANF_FILES_PATH("fwscanf1kLittleEndian2"));
        }
        else
        {
            strcpy(filename,FSCANF_FILES_PATH("fwscanf1kLittleEndian4"));
        }
    }
    
    file = fopen(filename, "rb");
    if(NULL == file)
    {
        printf("File %s open fail!\n",filename);
        return;
    }

    ret = fwscanf_s(file, L"%1025hs", buf,1026);
    len = strlen(buf);
    printf("fwscanf_s  1K ret %d,buf len is %d\n", ret,len);
    assert(ret == 1);
    assert(buf[0] == 'x');
    assert(buf[1024] == 'x');
    fclose(file);
#endif
    return;
}

void testswscanf_branches(void)
{
#ifndef SECUREC_VXWORKS_PLATFORM
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
    
    
    #if (defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__UNIX)))
   {
        long l1 = 0;
        wchar_t wDest[32] = {0};
        char dest[32] = {0};
        INT64T d1;
        int d2;
        short d3;


        *wDest=L'b';
        swscanf_s(L"a",L"%l{a]",wDest,2);
        assert(*wDest == L'b');

        swscanf_s(L"abcd",L"%4hs",dest,5);
        assert(0 == strcmp(dest,"abcd"));

        swscanf_s(L"123",L"%jd",&l1);
        printf("%ld\n",l1);

        swscanf_s(L"123",L"%td",&l1);
        printf("%ld\n",l1);

        swscanf_s(L"123",L"%zd",&l1);
        printf("%ld\n",l1);

        swscanf_s(L"123",L"%qd",&l1);
        printf("%ld\n",l1);


        swscanf_s(L"18446744073709551620",L"%lld",&d1);
        assert(d1 ==  9223372036854775807ULL);

        swscanf_s(L"9223372036854775808",L"%lld",&d1);
        assert(d1 ==  9223372036854775807ULL);

        swscanf_s(L"-18446744073709551620",L"%lld",&d1); /*> MAX_64BITS_VALUE_DIV_TEN*/
        assert(d1 ==  (-9223372036854775807LL - 1));

        swscanf_s(L"-9223372036854775809",L"%lld",&d1);/* if (num64 > MIN_64BITS_NEG_VALUE) */
        assert(d1 ==  (-9223372036854775807LL - 1));


        swscanf_s(L"10000000000000000",L"%llx",&d1);/*if((num64 >> 60) > 0)*/
        assert(d1 ==  (18446744073709551615ULL));

        swscanf_s(L"10000000000000000000000",L"%llo",&d1);/*if (_T('8') > ch) if((num64 >> 61) > 0)*/
        printf("%lld\n",d1);
        assert(d1 ==  (-1));

        swscanf_s(L"18446744073709551616",L"%lld",&d1);/*  if (num64as < (UINT64T)(ch - _T('0'))) */
        assert(d1 ==  9223372036854775807ULL);


        swscanf_s(L"-10000000000000000",L"%llx",&d1);/* if (num64 > MIN_64BITS_VALUE) */
        printf("%lld\n",d1);
        assert(d1 ==  (-1));


        swscanf_s(L"10000000000000000",L"%x",&d2); 
        printf("%d\n",d2);
        assert(d1 ==  (-1));

        swscanf_s(L"10000000000000000000000",L"%o",&d2);
        printf("%d\n",d2);
        assert(d1 ==  (-1));


        if(sizeof(long) == 4)
        { 
                swscanf_s(L"4294967300",L"%d",&d2); 
                printf("%d\n",d2);
                assert(d2 == 2147483647);

                swscanf_s(L"-4294967300",L"%d",&d2);
                printf("%d\n",d2);
                assert(d2 == (-2147483647 -1));


                swscanf_s(L"4294967296",L"%d",&d2); 
                printf("%d\n",d2);
                assert(d2 == 2147483647);

                swscanf_s(L"2147483649",L"%d",&d2); /* > MIN_32BITS_NEG_VALUE*/
                printf("%d\n",d2);
                assert(d2 == 2147483647);

                swscanf_s(L"-2147483649",L"%d",&d2);
                printf("%d\n",d2);
                assert(d2 == (-2147483647 -1));

                swscanf_s(L"100000004",L"%x",&d2);/* > MAX_32BITS_VALUE_DIV_TEN*/
                printf("%d\n",d2);
                assert(d2 == (-1));

                swscanf_s(L"-100000004",L"%x",&d2);
                printf("%d\n",d2);
                assert(d2 == (-1));

                d3=0;
                swscanf_s(L"4294967300",L"%hd",&d3);
                printf("%hd\n",d3);

                d3=0;
                swscanf_s(L"-4294967300",L"%hd",&d3);
                printf("%hd\n",d3);

                d3=0;
                swscanf_s(L"2147483649",L"%hd",&d3);/*> MIN_32BITS_NEG_VALUE*/
                printf("%hd\n",d3);
                assert(d3 == (-1));

                d3=0;
                swscanf_s(L"-2147483649",L"%hd",&d3);
                printf("%hd\n",d3);
                assert(d3 == (0));

                d3=0;
                swscanf_s(L"2147483649",L"%hx",&d3);/*> MIN_32BITS_NEG_VALUE*/
                printf("%hd\n",d3);
                assert(d3 == (-1));

                d3=0;
                swscanf_s(L"-2147483649",L"%hx",&d3);
                printf("%hd\n",d3);
                assert(d3 == (-1));

                swscanf_s(L"4294967300",L"%ld",&l1);
                printf("%ld\n",l1);

                swscanf_s(L"-4294967300",L"%ld",&l1);
                printf("%ld\n",l1);

        }
        else if(sizeof(long) == 8)
        {
                swscanf_s(L"18446744073709551620",L"%d",&d2); 
                printf("%d\n",d2);
                assert(d2 == (-1));

                swscanf_s(L"-18446744073709551620",L"%d",&d2);
                printf("%d\n",d2);
                assert(d2 == (0));


                swscanf_s(L"18446744073709551616",L"%d",&d2); /* if (number == MUL10(decimalEdge))*/
                printf("%d\n",d2);
                assert(d2 == (-1));

                swscanf_s(L"10000000000000004",L"%x",&d2);/* > MAX_32BITS_VALUE_DIV_TEN*/
                printf("%d\n",d2);
                assert(d2 == (-1));

                swscanf_s(L"-10000000000000004",L"%x",&d2);
                printf("%d\n",d2);
                assert(d2 == (-1));

                d3=0;
                swscanf_s(L"18446744073709551620",L"%hd",&d3);
                printf("%hd\n",d3);
                assert(d3 == (-1));

                d3=0;
                swscanf_s(L"-18446744073709551620",L"%hd",&d3);
                printf("%hd\n",d3);
                assert(d3 == (0));


                d3=0;
                swscanf_s(L"18446744073709551620",L"%hx",&d3);
                printf("%hx\n",d3);
                assert(d3 == (-1));

                d3=0;
                swscanf_s(L"-18446744073709551620",L"%hx",&d3);
                printf("%hx\n",d3);
                assert(d3 == (-1));

        }
    }
#endif
#endif
    return;
}
