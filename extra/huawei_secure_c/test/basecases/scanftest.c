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


void test_scanf(void)
{
    int ret = 0,  conv= 0,iv = 0;
    float fv = 0;
    char dest[DEST_BUFFER_SIZE] = {0};

    printf("do you want to test scanf? (y/n)");
    ret = getchar();
    ret = tolower(ret);

    while (ret == 'y'){
        
        printf("please input integer float string\n");
        
        conv = scanf_s("%d%f%100s", &iv, &fv, dest, DEST_BUFFER_SIZE);
        printf("convert %d items, you input value are %d  %f %.100s \n", conv, iv, fv, dest);
    
        
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
    int ret = 0, conv = 0,iv = 0;
    float fv = 0;
    char dest[DEST_BUFFER_SIZE] = {0};

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



#define TEST_STR "11111111112222222222333333333344444444445555555555666666666677777777778888888888\
99999999990000000000.000000000011111111112222222222333333333344444444445555555555666666666677777777\
778888888888999999999900000000001111111111222222222233333333334444444444555555555566666666667777777\
7778888888888999999999900000000001111111111222222222233333333334444444444555555555566666666667777777\
7778888888888999999999900000000001111111111222222222233333333334444444444555555555566666666667777777\
777888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666777777\
7777888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666777777\
77778888888888999999999900000000001111111111222222222233333333334444444444555555555566666666667777777\
777888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666777777777788888888889999999999"
#define TEST_STR2 "1111111111.0000000000111111111122222222223333333333444444444455555555556666666666\
7777777777888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666\
7777777777888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666\
7777777777888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666\
7777777777888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666\
7777777777888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666\
7777777777888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666\
7777777777888888888899999999990000000000111111111122222222223333333333444444444455555555556666666666\
77777777778888888888999999999922222222223333333333444444444455555555556666666666777777777788888888889999999999"

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

void scanf_gbk_01()
{
    char buf[] ="21341234 123 4123412 -1";
    int *point=0;
    int conv = sscanf_s(buf,"%p",&point);

    assert(conv == 1);
    assert(point == (int *)0x21341234);

}

void scanf_gbk_02()
{
    char buf[] ="21341234 123 4123412 -1";
    int *point=0;

    int conv = sscanf_s(buf,"%Fp",&point);
    assert(conv == 1);
    assert(point ==(int *) 0x21341234);

}



void scanf_gbk_04()
{
    wchar_t buf[128]={0};

    int conv = sscanf_s("hello, world",
            "%S",
            buf,sizeof(buf));

    assert(conv == 1);
    assert(0 == wcscmp(buf, L"hello,"));
}
/**/


void scanf_gbk(void)
{
    char* oriLocale = NULL;
    char* newLocale = NULL;
    char oldLocal[100] = {0};
    const char as[] = "蝴蝶测试工具，好不好用呢？谁用谁知道啊！";
    const wchar_t *ws = L"蝴蝶测试工具，好不好用呢？谁用谁知道啊！";
    wchar_t wBuf[48];
    char atmp[88]={0};
    int ret = 0;

    scanf_gbk_01();
    scanf_gbk_02();
    scanf_gbk_04();

    ret = MB_CUR_MAX;
    oriLocale = setlocale(LC_ALL, NULL);
    #ifdef __GNUC__ 
    assert(sizeof(as) == 61);
    #endif
    
    oriLocale = setlocale(LC_ALL, NULL);
    if (oriLocale!=NULL)
    {
        strcpy_s(oldLocal,100,oriLocale);
        oriLocale = oldLocal;
    }
    newLocale = setlocale(LC_ALL, LC_NAME_zh_CN_DEFAULT);
    if ( NULL == newLocale ) 
    { 
        printf("setlocale() with %s failed!!\n", LC_NAME_zh_CN_DEFAULT); 
    }
    else 
    { 
        printf("setlocale() with %s succeed.\n", LC_NAME_zh_CN_DEFAULT); 
        ret = MB_CUR_MAX;
        ret = wctomb(atmp, ws[0] );
        ret = sscanf_s( as, "%S", wBuf , sizeof(wBuf) / sizeof(wchar_t) );
        assert(ret == 1);
        assert(0 == my_wcscmp(wBuf, ws));

        ret = sscanf_s( as, "蝴蝶%s", atmp , sizeof(atmp));
        assert(ret == 1);
        assert(0 == strcmp(atmp, "测试工具，好不好用呢？谁用谁知道啊！"));

        ret = sscanf_s( as, "葫蝶%s", atmp , sizeof(atmp));
        assert(ret == 0);

        ret = sscanf_s( as, "蝴蝶测试工具%s", atmp , sizeof(atmp));
        assert(ret == 1);
        assert(0 == strcmp(atmp, "，好不好用呢？谁用谁知道啊！"));
    }



    (void)setlocale(LC_ALL, oriLocale);    /*restore original locale*/
    ret = MB_CUR_MAX;

    ret = sscanf_s( as, "%s", atmp , sizeof(atmp));
    assert(ret == 1);
    assert(0 == strcmp(atmp, as));


}
static int vfscf(FILE *pf, const char *fmt, ...)
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
#endif
    //char inputStr[] = "123 567.4 asdfqwer";
char * oriLocale;

    char src[SRC_BUFFER_SIZE] = "abcd";
    //char str[512] = {0};

    int iv = 0xFF,     ret ;
    float fv = 0;
    int conv = 0;
    //unsigned short wv = iv;
    //char* pTest = dest;
    unsigned int  ui = 0;
    int a, b ,c,d = 0;
    char  tokenstring[] = "15 12 14...";
    //char  s[81] = {0};
    char  ch;
    int   i;
    //float fp = 0.0f;
    double dblVal;
    char sztime1[32] = {0};
    char sztime2[32] = {0};
    //int j = 0;
    int inumber = 9000;
    int iRet = 0;
    FILE *ffp;
    MY_INT64 val64;
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
    
    char* newLocale = NULL;
    char oldLocal[100] = {0};

    conv = sscanf_s("3.456789","%lg",&dblVal);
    assert(conv == 1);
    assertFloatEqu((float)dblVal, 3.456789f);

    conv = sscanf_s("3.456789","%Lg",&dblVal);
    assert(conv == 1);
    assertFloatEqu((float)dblVal, 3.456789f);

/*    conv = sscanf_s("3.456789","%llg",&dblVal);
    assert(conv == 1);
    assertFloatEqu(dblVal, 3.456789f);
*/

    conv = sscanf_s("34.12454","%f",&fv);
    assertFloatEqu(fv, 34.12454f);

    oriLocale = setlocale(LC_ALL, NULL);
    if (oriLocale!=NULL)
    {
        strcpy_s(oldLocal,100,oriLocale);
        oriLocale = oldLocal;
    }
    newLocale = setlocale(LC_ALL, LC_NAME_zh_CN_DEFAULT);
    if ( NULL == setlocale(LC_ALL, LC_NAME_zh_CN_DEFAULT) ) 
    { 
        printf("call setlocale with %s failed!!\n", LC_NAME_zh_CN_DEFAULT); 
    }
    else {
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

    (void)setlocale(LC_ALL, oriLocale);    /*restore original locale*/

    conv = sscanf_s("9223372036854775807", "%lld", &val64);
    /*assert(sizeof(MY_INT64) == 8);*/
    assert(conv == 1);
    /*printf("%I64u/n", *(INT64T*)&val64);*/

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
    assert(d == -2147483647L -1);

    (void)sscanf_s("2147483648", "%u",&ui);
    assert(ui == 2147483648);

    ret = sscanf_s("10 0x1b aaaaaaaa bbbbbbbb","%d %x %5[a-z] %*s %f",&d,&a,dest, DEST_BUFFER_SIZE,dest, DEST_BUFFER_SIZE);
    assert(ret == 3);
    assert(d ==10);
    assert(a ==27);
    assert(strcmp(dest, "aaaaa") == 0);

    (void)sscanf_s("-2147483648", "%d",&d);
    assert(d == -2147483647L - 1);

    (void)sscanf_s("3147483647", "%d",&d);
    assert(d == -1147483649);


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
    (void)sscanf_s( "","%{a] %d", dest, DEST_BUFFER_SIZE,&d);  
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
/*
    memset(wDest,0xA,sizeof(wDest));
    (void)sscanf_s("\n", "%ls %d", wDest, DEST_BUFFER_SIZE,&d);  
    assert(my_wcscmp(wDest, L"") == 0);
    assert(d == 10);
*/
#endif

   
    conv = sscanf_s("3.456789","%lg",&dblVal);
    assert(conv == 1);

    if (sizeof(void*) == sizeof(INT64T)) 
    {
        INT64T d1,d2;
        (void)sscanf_s("123,123","%Id,%Iu",&d1,&d2);
        assert(d1 == 123);
        assert(d2 == 123);

    }
    else
    {
        INT32T d1,d2;
        (void)sscanf_s("123,123","%Id,%Iu",&d1,&d2);
        assert(d1 == 123);
        assert(d2 == 123);
 

    }


         
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
    //wchar_t wDest[DEST_BUFFER_SIZE] = {0};
    //char inputStr[] = "123 567.4 asdfqwer";
    //wchar_t wStr[] = L"123 5689.4 asdfqwer";

    char src[SRC_BUFFER_SIZE] = "abcd";
    //char str[512] = {0};

    int iv = 0xFF,     ret ;
    float fv = 0;
    int conv = 0;
    //unsigned short wv = iv;
    //char* pTest = dest;
    unsigned int  ui = 0;
    int a, b ,c,d = 0;
    char  tokenstring[] = "15 12 14...";
    //char  s[81] = {0};
    char  ch;
    int   i;
    //float fp = 0.0f;


    //int j = 0;
    
    (void)strcpy_s(src, DEST_BUFFER_SIZE, "123 567.4 asdfqwer");
    conv = indirect_sscanf(src, "%d%f%s", &iv, &fv, dest,DEST_BUFFER_SIZE);
    assert(conv == 3);
    assert( strcmp(dest, "asdfqwer") == 0);
    assert( iv == 123 );
    assertFloatEqu(fv, 567.4f);


    ret = sprintf_s(dest, DEST_BUFFER_SIZE, "asdasd%s", NULL);
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

    (void)indirect_sscanf("2147483648", "%d",&d);
    assert(d == -2147483647L - 1);

    (void)indirect_sscanf("2147483648", "%u",&ui);
    assert(ui == 2147483648);

    (void)indirect_sscanf("10 0x1b aaaaaaaa bbbbbbbb","%d %x %5[a-z] %*s %f",&d,&a,dest, DEST_BUFFER_SIZE,dest, DEST_BUFFER_SIZE);
    assert(d ==10);
    assert(a ==27);
    assert(strcmp(dest, "aaaaa") == 0);

    (void)indirect_sscanf("-2147483648", "%d",&d);
    assert(d == -2147483647L -1);

    (void)indirect_sscanf("3147483647", "%d",&d);
    assert(d == -1147483649);

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
        assert(p == (char*)1);
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
    
   
    fclose(file);
    return;
}

void testsscanf_branches(void)
{
#ifndef SECUREC_VXWORKS_PLATFORM
    int ret = 0;
    wchar_t wDest[DEST_BUFFER_SIZE] = {0};
#endif
     
#ifndef SECUREC_VXWORKS_PLATFORM
     ret = sscanf_s("abc","%ls",wDest,DEST_BUFFER_SIZE);
     assert(ret == 1);
#endif
    return;
}
#endif

