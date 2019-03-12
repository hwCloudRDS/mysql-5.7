
#include "securec.h"
#include "base_funcs.h"
#include "testutil.h"

#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#if !(defined(SECUREC_VXWORKS_PLATFORM))
#include <wchar.h>
#endif
#include <stdlib.h>
#include <string.h>

#define DEST_BUFFER_SIZE  20
#define SRC_BUFFER_SIZE  200


#ifndef INT_MIN
    #define INT_MIN     (-2147483648) /* minimum (signed) int value */
#endif

#define BUFFER_SIZE 3
#define BIG_BUFFER_SIZE 256
#define MATH_PI 3.1415926

#if (defined(_WIN32) || defined(_WIN64) || defined(COMPATIBLE_LINUX_FORMAT))
extern int wprintf (const wchar_t* format, ...);
#endif

void assertMeetExpectedStr(const char* formattedStr, const char* expected, unsigned int funcRet, int lineId )
{
    int destLen = 0;
    char* errorInfo = NULL;
    int rc;
    if ( funcRet != slen(expected) ||  0 != strcmp(formattedStr, expected) ) { /*lint !e668*/
        destLen = slen(formattedStr) + slen(expected) + 30;
        errorInfo = (char*)malloc(destLen);
        
        if (errorInfo){
            rc = sprintf_s(errorInfo,destLen, "Out: %s; expected: %s; at: %d", formattedStr, expected, lineId -1 );
            printf("%s\r\n", errorInfo);
            printf("err line=%d\n",lineId);
            assert(0);
            free(errorInfo); /*lint !e527*/
        }
    }

}
#ifndef SECUREC_VXWORKS_PLATFORM
void assertMeetExpectedWstr(const wchar_t* formattedStr, const wchar_t* expected, unsigned int funcRet, int lineId )
{
    int destLen = 0;
    wchar_t* errorInfo = NULL; 
    int rc;
    if ( funcRet != wslen(expected) ||  0 != my_wcscmp(formattedStr, expected) ) {
        destLen = wslen(formattedStr) + wslen(expected) + 30;
        errorInfo = (wchar_t*)malloc(destLen * sizeof(wchar_t));
        
        if (errorInfo){
            rc = swprintf_s(errorInfo,destLen, L"Out: %s; expected: %s; at: %d", formattedStr, expected, lineId -1 );
            fputws ( errorInfo, stdout );
/*
            rc = wprintf(L"%s\r\n", errorInfo);
            assert(rc == EOK);
*/
            printf("err line=%d\n",lineId);
            assert(0);
            free(errorInfo); /*lint !e527*/
        }
    }

}
#endif

void test_sprintf_s_basic(void)
{
    char bigBuf[BIG_BUFFER_SIZE];
    int iv = 0;
    char d[2048] = {0};
    char *s = "asda";
    double ddd = 1234.5678;
     /*int aaa = -12345678;*/
     char buf[128] = {0};
     size_t sizeVal = 123456;

    int ret = 0, result;
#if (defined(_MSC_VER) && (_MSC_VER == 1200))
    INT64T temp64 = 0;
#endif

    result = sprintf_s(d, 2048, "%s...%10s...%-10s...%10.5s...%-10.5s===\r\n", s, s, s, s, s); 
    printf("length is %d, content is \r\n%s\r\n", result, d);
    

    result = sprintf_s(d, 2048, "%0.*f===\r\n", 2, ddd); 
    printf("length is %d, content is \r\n%s\r\n", result, d);

    result = sprintf_s(d, 2048, "%0.*f===\r\n", -1, ddd);
    printf("length is %d, content is \r\n%s\r\n", result, d);

    memset(d, 0, 2048);
    ret = sprintf_s(d, 2048, "%f\n", 1.7e+308);
    assert(ret == 317);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "abc %n", &iv);
    assert(ret == -1);
    assert( 0 == strcmp(bigBuf, "") );

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%.8g", 3.141592654);
    assertMeetExpectedStr(bigBuf, "3.1415927", ret, __LINE__);

    memset(buf, 0, sizeof(buf));
    ret = sprintf_s(buf,128, "%.8g", 3.141592654);
    assertMeetExpectedStr(buf, "3.1415927", ret, __LINE__);
    

    memset(buf, 0, sizeof(buf));
    ret = sprintf_s(buf,128, "%.8g", 3.1415926);
    assertMeetExpectedStr(buf, "3.1415926", ret, __LINE__);
    
    memset(buf, 0, sizeof(buf));
    ret = sprintf_s(buf,128, "%.8g", (double)90);
     assertMeetExpectedStr(buf, "90", ret, __LINE__);
     
    memset(buf, 0, sizeof(buf));
    ret = sprintf_s(buf,128, "%.8g", 90.1);
    assertMeetExpectedStr(buf, "90.1", ret, __LINE__);
    


    memset(buf, 0, sizeof(buf));
    ret = sprintf_s(buf, sizeof(buf), "%g\n", 3.14);
    assertMeetExpectedStr(buf, "3.14\n", ret, __LINE__);

    memset(buf, 0, sizeof(buf));
    ret = sprintf_s(buf, sizeof(buf), "%g\n", 3.14e+5);
    assertMeetExpectedStr(buf, "314000\n", ret, __LINE__);

    memset(buf, 0, sizeof(buf));
    ret = sprintf_s(buf, sizeof(buf), "%g\n", 3.14e-5);
#if !(defined(_MSC_VER))
    assertMeetExpectedStr(buf, "3.14e-05\n", ret, __LINE__);
#else
    assertMeetExpectedStr(buf, "3.14e-005\n", ret, __LINE__);
#endif

    memset(buf, 0, sizeof(buf));
    ret = sprintf_s(buf, sizeof(buf), "%g\n", 3.14e+100);
    assertMeetExpectedStr(buf, "3.14e+100\n", ret, __LINE__);

    memset(buf, 0, sizeof(buf));
    ret = sprintf_s(buf, sizeof(buf), "%g\n", 3.0);
    assertMeetExpectedStr(buf, "3\n", ret, __LINE__);

    memset(buf, 0, sizeof(buf));
    ret = sprintf_s(buf,128, "%.8g", 1.23e+1);
    assertMeetExpectedStr(buf, "12.3", ret, __LINE__);
    
    memset(buf, 0, sizeof(buf));
    ret = sprintf_s(buf,128, "%.8g", 1.23e+100);
    assertMeetExpectedStr(buf, "1.23e+100", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%s", "abc123");
    assertMeetExpectedStr(bigBuf, "abc123", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "header: %s", "abc123");
    assertMeetExpectedStr(bigBuf, "header: abc123", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "header: %.2s", "abc123");
    assertMeetExpectedStr(bigBuf, "header: ab", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%d", INT_MAX);
    assertMeetExpectedStr(bigBuf, "2147483647", ret, __LINE__);
    
#if (defined(_MSC_VER) && (_MSC_VER == 1200))
    //vc6 not support "%lld"
    ;    
#else
    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%lld", 120259084288LL);
    assertMeetExpectedStr(bigBuf, "120259084288", ret, __LINE__);
#endif

    

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%zd", 2147483647);
    assertMeetExpectedStr(bigBuf, "2147483647", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%zi", 2147483647);
    assertMeetExpectedStr(bigBuf, "2147483647", ret, __LINE__);

    /*ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%zd", -2147483648);
    assertMeetExpectedStr(bigBuf, "-2147483648", ret, __LINE__);*//*already tested in comptest*/
    
    /*ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%zi", -2147483648);
    assertMeetExpectedStr(bigBuf, "-2147483648", ret, __LINE__);*//*already tested in comptest*/

    /*ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%zu", 4294967295);
    assertMeetExpectedStr(bigBuf, "4294967295", ret, __LINE__);*//*already tested in comptest*/

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%zx", 0xffffffff);
    assertMeetExpectedStr(bigBuf, "ffffffff", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%zo", 037777777777);
    assertMeetExpectedStr(bigBuf, "37777777777", ret, __LINE__);

#if (defined(_MSC_VER) && (_MSC_VER == 1200))
    //vc6 not support "%llu"
    ;
#else
    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%llu", 18446744073709551611ULL);
    assertMeetExpectedStr(bigBuf, "18446744073709551611", ret, __LINE__);
#endif

    

#ifdef _WIN64
    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%I64d", 120259084288UL);
    assertMeetExpectedStr(bigBuf, "120259084288", ret, __LINE__);
#endif
    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%i", INT_MAX);
    assertMeetExpectedStr(bigBuf, "2147483647", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%i", INT_MIN);
    assertMeetExpectedStr(bigBuf, "-2147483648", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%u", INT_MIN);
    assertMeetExpectedStr(bigBuf, "2147483648", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%u",  -1 / 2 -1);
    assertMeetExpectedStr(bigBuf, "4294967295", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%o",  0xFF);
    assertMeetExpectedStr(bigBuf, "377", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%x", INT_MAX);
    assertMeetExpectedStr(bigBuf, "7fffffff", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "0X%X", INT_MAX);
    assertMeetExpectedStr(bigBuf, "0X7FFFFFFF", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%e", MATH_PI);
#if !(defined(_MSC_VER))
    assertMeetExpectedStr(bigBuf, "3.141593e+00", ret, __LINE__);
#else
    assertMeetExpectedStr(bigBuf, "3.141593e+000", ret, __LINE__);
#endif
    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%E", MATH_PI);
#if !(defined(_MSC_VER))
    assertMeetExpectedStr(bigBuf, "3.141593E+00", ret, __LINE__);
#else
    assertMeetExpectedStr(bigBuf, "3.141593E+000", ret, __LINE__);
#endif
    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%g", MATH_PI);
    assertMeetExpectedStr(bigBuf, "3.14159", ret, __LINE__);

        ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%f", -MATH_PI);
        /* !! is different from above "3.14159" */
    assertMeetExpectedStr(bigBuf, "-3.141593", ret, __LINE__);

    /* !! bug */
    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%A", MATH_PI);
    /*FIXME assertMeetExpectedStr(bigBuf, "0X1.921FB5P+1", ret, __LINE__);*/



    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "abc %h", iv);
    assert(ret == -1);
    assert( 0 == strcmp(bigBuf, "") );

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "abc %k", iv);
    assert(ret == -1);
    assert( 0 == strcmp(bigBuf, "") );

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%p", (void*)0x1234ab);

#if defined(__SOLARIS) || defined(_AIX)
       assertMeetExpectedStr(bigBuf, "1234ab", ret, __LINE__);
#elif defined(__hpux)
    if (is64Bits()){
        assertMeetExpectedStr(bigBuf, "00000000001234ab", ret, __LINE__);
    }else if (is32Bits()){
        assertMeetExpectedStr(bigBuf, "001234ab", ret, __LINE__);
    }else{
        printf("unknown dest system pointer size!!");
    }
#elif defined(_MSC_VER)   
    if (is64Bits()){
        assertMeetExpectedStr(bigBuf, "00000000001234AB", ret, __LINE__);
    }else if (is32Bits()){
        assertMeetExpectedStr(bigBuf, "001234AB", ret, __LINE__);
    }else{
        printf("unknown dest system pointer size!!");
    }
#else    
        assertMeetExpectedStr(bigBuf, "0x1234ab", ret, __LINE__);
#endif

    if (is64Bits()){ /*2014 7 31 add test cases*/
        /*test 64bits pointer*/
#if (defined(_MSC_VER) && (_MSC_VER == 1200))
        temp64 = 0x0012345678ab;
        ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%p", (void*)temp64); /*lint !e511*/    
#else
        ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%p", (void*)0x0012345678abULL); /*lint !e511*/        
#endif
        /*assert(ret == 12);*/
#if defined(__SOLARIS) || defined(_AIX)
        assertMeetExpectedStr(bigBuf, "12345678ab", ret, __LINE__);
#elif defined(__hpux)
        assertMeetExpectedStr(bigBuf, "00000012345678ab", ret, __LINE__);
#elif defined(_MSC_VER)
        assertMeetExpectedStr(bigBuf, "00000012345678AB", ret, __LINE__);
#else
        assertMeetExpectedStr(bigBuf, "0x12345678ab", ret, __LINE__);
#endif

#if (defined(_MSC_VER) && (_MSC_VER == 1200))
        temp64 = 0x012345678abcd;
        ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%p", (void*)temp64); /*lint !e511*/    
#else
        ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%p", (void*)0x012345678abcdULL); /*lint !e511*/        
#endif

       /* assert(ret == 14);*/
#if defined(__SOLARIS) || defined(_AIX)
        assertMeetExpectedStr(bigBuf, "12345678abcd", ret, __LINE__);
#elif defined(__hpux)
        assertMeetExpectedStr(bigBuf, "000012345678abcd", ret, __LINE__);
#elif defined(_MSC_VER)
        assertMeetExpectedStr(bigBuf, "000012345678ABCD", ret, __LINE__);
#else
        assertMeetExpectedStr(bigBuf, "0x12345678abcd", ret, __LINE__);
#endif
    }

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%p", (void*)0x12EF789);
#if defined(__SOLARIS) || defined(_AIX)
    assertMeetExpectedStr(bigBuf, "12ef789", ret, __LINE__);
#elif defined(__hpux)
    if (is64Bits()){
        assertMeetExpectedStr(bigBuf, "00000000012ef789", ret, __LINE__);
    }else if(is32Bits()){
        assertMeetExpectedStr(bigBuf, "012ef789", ret, __LINE__);
    }else{
        printf("unknown dest system pointer size!!");
    }    
#elif defined(_MSC_VER)
    if (is64Bits()){
        assertMeetExpectedStr(bigBuf, "00000000012EF789", ret, __LINE__);
    }else if(is32Bits()){
        assertMeetExpectedStr(bigBuf, "012EF789", ret, __LINE__);
    }else{
        printf("unknown dest system pointer size!!");
    }
#else
        assertMeetExpectedStr(bigBuf, "0x12ef789", ret, __LINE__);

#endif
    
    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%zd", sizeVal);
    assertMeetExpectedStr(bigBuf, "123456", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%Id", sizeVal);
    assertMeetExpectedStr(bigBuf, "123456", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%c%c", 'a', 'b');
    assertMeetExpectedStr(bigBuf, "ab", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%s %s", "security", "design");
    assertMeetExpectedStr(bigBuf, "security design", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%8d%8d", 123, 4567);
    assertMeetExpectedStr(bigBuf, "     123    4567", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%05d", 123);
    assertMeetExpectedStr(bigBuf, "00123", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%-8d%8d", 123, 4567);
    assertMeetExpectedStr(bigBuf, "123         4567", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%8x", 4567);
    assertMeetExpectedStr(bigBuf, "    11d7", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%-8X", 4568);
    assertMeetExpectedStr(bigBuf, "11D8    ", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%08X", 4567);
    assertMeetExpectedStr(bigBuf, "000011D7", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%04X", (short)-1);
    assertMeetExpectedStr(bigBuf, "FFFFFFFF", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%04X", (unsigned short)-1);
    assertMeetExpectedStr(bigBuf, "FFFF", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%10.3f", MATH_PI);
    assertMeetExpectedStr(bigBuf, "     3.142", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%-10.3f", MATH_PI);
    assertMeetExpectedStr(bigBuf, "3.142     ", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%.3f", MATH_PI);
    assertMeetExpectedStr(bigBuf, "3.142", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "asdasd%s", (char *)NULL);
    assertMeetExpectedStr(bigBuf, "asdasd(null)", ret, __LINE__);

    /*2014 10 31 add */
    ddd = atof("1.7976931348623158e+308");
    ret = sprintf_s(d, 2048, "%f %d %d", ddd, 12345678, 765);

     s = (char*)malloc(2048);
    if (NULL == s) {
        return;
    }
    result = sprintf(s, "%f %d %d", ddd, 12345678, 765);
    assertMeetExpectedStr(d, s, ret, __LINE__);

    ret = sprintf_s(d, 2048, "%f %d %d", ddd / 0.001, 12345678, 765);
    result = sprintf(s, "%f %d %d", ddd / 0.001, 12345678, 765);
    assertMeetExpectedStr(d, s, ret, __LINE__);


    memset_s(&ddd, sizeof(double), 0xFF, sizeof(double));
    ret = sprintf_s(d, 2048, "%f %d %d", ddd, 12345678, 765);
    result = sprintf(s, "%f %d %d", ddd, 12345678, 765);
    assertMeetExpectedStr(d, s, ret, __LINE__);

    ddd = 12345678998.321456878;
    ret = sprintf_s(d, 2048, "%s abcd %f %d %d", "lsd", ddd, 12345678, 765);
    result = sprintf(s, "%s abcd %f %d %d", "lsd", ddd, 12345678, 765);
    assertMeetExpectedStr(d, s, ret, __LINE__);

    free(s);
}

void test_sprintf_s_combination(void)
{
    char bigBuf[BIG_BUFFER_SIZE];
    char a1[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G'};
    char a2[] = {'H', 'I', 'J', 'K', 'L', 'M', 'N'};
    int ret = 0;

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%d %.3f %s", 456, MATH_PI, "abcdef321");
    assertMeetExpectedStr(bigBuf, "456 3.142 abcdef321", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%.3f", MATH_PI);
    assertMeetExpectedStr(bigBuf, "3.142", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%.7s%.7s", a1, a2);
    assertMeetExpectedStr(bigBuf, "ABCDEFGHIJKLMN", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE,"%.6s%.5s", a1, a2);
    assertMeetExpectedStr(bigBuf, "ABCDEFHIJKL", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%.*s%.*s", 7, a1, 7, a2);
    assertMeetExpectedStr(bigBuf, "ABCDEFGHIJKLMN", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%-*d", 4, 'A'); 
    assertMeetExpectedStr(bigBuf, "65  ", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE,"%#0*X", 8, 128);
    assertMeetExpectedStr(bigBuf, "0X000080", ret, __LINE__);

    ret = sprintf_s(bigBuf, BIG_BUFFER_SIZE, "%*.*f", 10, 2, 3.1415926);
    assertMeetExpectedStr(bigBuf, "      3.14", ret, __LINE__);
}

int indirect_sprintf(char *string, size_t sizeInBytes, const char *format, ...)
{
    va_list args;
    int ret = 0;
    
    va_start( args, format );
    ret = vsprintf_s(string, sizeInBytes, format, args );
    va_end(args);
    return ret;
    
}
void test_vsprintf_s(void)
{
    char bigBuf[BIG_BUFFER_SIZE];
    char a1[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G'};
    char a2[] = {'H', 'I', 'J', 'K', 'L', 'M', 'N'};
    int ret = 0;

    ret = indirect_sprintf(bigBuf, BIG_BUFFER_SIZE, "%d %.3f %s", 456, MATH_PI, "abcdef321");
    assertMeetExpectedStr(bigBuf, "456 3.142 abcdef321", ret, __LINE__);

    ret = indirect_sprintf(bigBuf, BIG_BUFFER_SIZE, "%.3f", MATH_PI);
    assertMeetExpectedStr(bigBuf, "3.142", ret, __LINE__);

    ret = indirect_sprintf(bigBuf, BIG_BUFFER_SIZE, "%.7s%.7s", a1, a2);
    assertMeetExpectedStr(bigBuf, "ABCDEFGHIJKLMN", ret, __LINE__);

    ret = indirect_sprintf(bigBuf, BIG_BUFFER_SIZE,"%.6s%.5s", a1, a2);
    assertMeetExpectedStr(bigBuf, "ABCDEFHIJKL", ret, __LINE__);

    ret = indirect_sprintf(bigBuf, BIG_BUFFER_SIZE, "%.*s%.*s", 7, a1, 7, a2);
    assertMeetExpectedStr(bigBuf, "ABCDEFGHIJKLMN", ret, __LINE__);

    ret = indirect_sprintf(bigBuf, BIG_BUFFER_SIZE, "%-*d", 4, 'A'); 
    assertMeetExpectedStr(bigBuf, "65  ", ret, __LINE__);

    ret = indirect_sprintf(bigBuf, BIG_BUFFER_SIZE,"%#0*X", 8, 128);
    assertMeetExpectedStr(bigBuf, "0X000080", ret, __LINE__);

    ret = indirect_sprintf(bigBuf, BIG_BUFFER_SIZE, "%*.*f", 10, 2, 3.1415926);
    assertMeetExpectedStr(bigBuf, "      3.14", ret, __LINE__);
}

void test_sprintf_s_boundaryCondition(void)
{
    char buf[BUFFER_SIZE];
    int ret = 0;

    ret = sprintf_s(buf, BUFFER_SIZE, "%s", "abc");
    assert(ret == -1);

    ret = sprintf_s(buf, BUFFER_SIZE, "%d", 123);
    assert(ret == -1);

    ret = sprintf_s(buf, BUFFER_SIZE, "%d", -12);
    assert(ret == -1);

    ret = sprintf_s(buf, BUFFER_SIZE, "%d", -123);
    assert(ret == -1);

    ret = sprintf_s(buf, BUFFER_SIZE, "%u", 123);
    assert(ret == -1);

}

#ifndef SECUREC_VXWORKS_PLATFORM
void test_swprintf_s_combination(void)
{
    wchar_t bigBuf[BIG_BUFFER_SIZE];
    wchar_t a1[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G'};
    wchar_t a2[] = {'H', 'I', 'J', 'K', 'L', 'M', 'N'};
    int ret = 0;
    char ca1[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G'};
    char ca2[] = {'H', 'I', 'J', 'K', 'L', 'M', 'N'};

    wchar_t wc = 'A';
    char ac = 'c';

    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"asdasd%s", NULL);
    assertMeetExpectedWstr(bigBuf, L"asdasd(null)", ret, __LINE__);


    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%d", 456);
    assertMeetExpectedWstr(bigBuf, L"456", ret, __LINE__);

#if defined(COMPATIBLE_LINUX_FORMAT)
    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%d %.3f %s", 456, MATH_PI, "abcdef321");
#else /* windows system */
    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%d %.3f %s", 456, MATH_PI, L"abcdef321");
#endif
    assertMeetExpectedWstr(bigBuf, L"456 3.142 abcdef321", ret, __LINE__);

    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%.3f", MATH_PI);
    assertMeetExpectedWstr(bigBuf, L"3.142", ret, __LINE__);

#if defined(COMPATIBLE_LINUX_FORMAT)
    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%.7s%.7s", ca1, ca2);
#else /* windows system */
    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%.7s%.7s", a1, a2);
#endif
    assertMeetExpectedWstr(bigBuf, L"ABCDEFGHIJKLMN", ret, __LINE__);


#if defined(COMPATIBLE_LINUX_FORMAT)
    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%.6s%.5s", ca1, ca2);
#else /* windows system */
    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%.6s%.5s", a1, a2);
#endif
    assertMeetExpectedWstr(bigBuf, L"ABCDEFHIJKL", ret, __LINE__);

#if defined(COMPATIBLE_LINUX_FORMAT)
    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%.*s%.*s", 7, ca1, 7, ca2);
#else /* windows system */
    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%.*s%.*s", 7, a1, 7, a2);
#endif
    
    assertMeetExpectedWstr(bigBuf, L"ABCDEFGHIJKLMN", ret, __LINE__);

    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%-*d", 4, 'A'); 
    assertMeetExpectedWstr(bigBuf, L"65  ", ret, __LINE__);

    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE,L"%#0*X", 8, 128);
    assertMeetExpectedWstr(bigBuf, L"0X000080", ret, __LINE__);

    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%*.*f", 10, 2, 3.1415926);
    assertMeetExpectedWstr(bigBuf, L"      3.14", ret, __LINE__);

#if defined(COMPATIBLE_LINUX_FORMAT)
    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%ls", L"hello Hw");
    assertMeetExpectedWstr(bigBuf, L"hello Hw", ret, __LINE__);

    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%ls __ %ls", L"hello Hw", L"Security Design");
    assertMeetExpectedWstr(bigBuf, L"hello Hw __ Security Design", ret, __LINE__);
#endif

    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%c", ac);
    assertMeetExpectedWstr(bigBuf, L"c", ret, __LINE__);

    ret = swprintf_s(bigBuf, BIG_BUFFER_SIZE, L"%lc", wc);
    assertMeetExpectedWstr(bigBuf, L"A", ret, __LINE__);

}
#endif
#ifndef SECUREC_VXWORKS_PLATFORM
int indirect_swprintf(wchar_t *string, size_t sizeInWords, const wchar_t* format, ...)
{
    va_list args;
    int ret = 0;
    
    va_start( args, format );
    ret = vswprintf_s(string, sizeInWords, format, args ) ;
    va_end(args);
    return ret;
    
}

void test_vswprintf_s(void)
{
    wchar_t bigBuf[BIG_BUFFER_SIZE];
    wchar_t a1[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G'};
    wchar_t a2[] = {'H', 'I', 'J', 'K', 'L', 'M', 'N'};
    char ca1[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G'};
    char ca2[] = {'H', 'I', 'J', 'K', 'L', 'M', 'N'};
    /*int iv = 0;*/
    wchar_t bigBufSys[100]={214,208,206,196}; /* 格式化"中文"的目标值*/
    int ret = 0;

    ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE, L"%d", 456);
    assertMeetExpectedWstr(bigBuf, L"456", ret, __LINE__);

#if defined(COMPATIBLE_LINUX_FORMAT)
    ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE, L"%d %.3f %s", 456, MATH_PI, "abcdef321");
#else /* windows system */
    ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE, L"%d %.3f %s", 456, MATH_PI, L"abcdef321");
#endif
    assertMeetExpectedWstr(bigBuf, L"456 3.142 abcdef321", ret, __LINE__);

    ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE, L"%.3f", MATH_PI);
    assertMeetExpectedWstr(bigBuf, L"3.142", ret, __LINE__);

#if defined(COMPATIBLE_LINUX_FORMAT)
    ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE, L"%.7s%.7s", ca1, ca2);
#else /* windows system */
    ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE, L"%.7s%.7s", a1, a2);
#endif

    assertMeetExpectedWstr(bigBuf, L"ABCDEFGHIJKLMN", ret, __LINE__);

#if defined(COMPATIBLE_LINUX_FORMAT)
    ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE, L"%.6s%.5s", ca1, ca2);
#else /* windows system */
    ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE, L"%.6s%.5s", a1, a2);
#endif
    assertMeetExpectedWstr(bigBuf, L"ABCDEFHIJKL", ret, __LINE__);

#if defined(COMPATIBLE_LINUX_FORMAT)
    ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE, L"%.*s%.*s", 7, ca1, 7, ca2);
#else /* windows system */
    ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE, L"%.*s%.*s", 7, a1, 7, a2);
#endif
    assertMeetExpectedWstr(bigBuf, L"ABCDEFGHIJKLMN", ret, __LINE__);

    ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE, L"%-*d", 4, 'A'); 
    assertMeetExpectedWstr(bigBuf, L"65  ", ret, __LINE__);

    ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE,L"%#0*X", 8, 128);
    assertMeetExpectedWstr(bigBuf, L"0X000080", ret, __LINE__);

    ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE, L"%*.*f", 10, 2, 3.1415926);
    assertMeetExpectedWstr(bigBuf, L"      3.14", ret, __LINE__);

    /*格式化中文*/
    #if (defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
        ret = indirect_swprintf(bigBuf, BIG_BUFFER_SIZE, L"%S", "中文");
        assertMeetExpectedWstr(bigBuf, bigBufSys, ret, __LINE__);
    #endif

}
#endif


void test_snprintf_s(void)
{
    char buf[BUFFER_SIZE];
    char bigBuf[BIG_BUFFER_SIZE];
    int ret = 0;

    ret = snprintf_s(buf, BUFFER_SIZE, 2, "%s", "abc");
    assert(ret == -1);
    assert(0 == strcmp(buf, "ab") );

#if (defined(_MSC_VER) && (_MSC_VER >= 1400)) || (defined(__GNUC__) && (__GNUC__ > 3))
    ret = COMP_SNPRINTF(buf, BUFFER_SIZE, 2, "%s", "abc");
    assert(ret == 2);
    assert(0 == strcmp(buf, "ab") );

    ret = COMP_SNPRINTF(bigBuf, BIG_BUFFER_SIZE, 20, "%s %d", "abc", 345);
    assert(ret == 7);
    assert(0 == strcmp(bigBuf, "abc 345") );
#endif

    ret = snprintf_s(bigBuf, BIG_BUFFER_SIZE, 2, "%d", 10000);
    assert(ret == -1);
    assert(0 == strcmp(bigBuf, "10") );

    ret = snprintf_s(bigBuf, BIG_BUFFER_SIZE, 3, "%s", "abc");
    assertMeetExpectedStr(bigBuf, "abc", ret, __LINE__);

    ret = snprintf_s(bigBuf, BIG_BUFFER_SIZE, 5, "%s", "abc");
    assertMeetExpectedStr(bigBuf, "abc", ret, __LINE__);

    ret = snprintf_s(bigBuf, 10, 20, "%s", "abc");
    assertMeetExpectedStr(bigBuf, "abc", ret, __LINE__);


    ret = snprintf_s(bigBuf, BIG_BUFFER_SIZE, sizeof(bigBuf) - 1, "%s", "abc");
    assertMeetExpectedStr(bigBuf, "abc", ret, __LINE__);

    ret = snprintf_s(bigBuf, 4, 3, "%s", "abc");
    assertMeetExpectedStr(bigBuf, "abc", ret, __LINE__);

    ret = snprintf_s(buf, 3, 3, "%s", "abc");
    assert(ret == -1);
    assert(0 == strcmp(buf, "") );
}

int indirect_snprintf(char *string, size_t sizeInBytes, size_t count, const char *format, ...)
{
    va_list args;
    int ret = 0;
    
    va_start( args, format );
    ret = vsnprintf_s(string, sizeInBytes, count, format, args ) ;
    va_end(args);
    return ret;
    
}

void test_vsnprintf_s(void)
{
    char buf[BUFFER_SIZE];
    char bigBuf[BIG_BUFFER_SIZE];
    int ret = 0;

    ret = indirect_snprintf(buf, BUFFER_SIZE, 2, "%s", "abc");
    assert(ret == -1);
    assert(0 == strcmp(buf, "ab") );

    ret = indirect_snprintf(bigBuf, BIG_BUFFER_SIZE, 3, "%s", "abc");
    assertMeetExpectedStr(bigBuf, "abc", ret, __LINE__);

    ret = indirect_snprintf(bigBuf, BIG_BUFFER_SIZE, 5, "%s", "abc");
    assertMeetExpectedStr(bigBuf, "abc", ret, __LINE__);

    ret = indirect_snprintf(bigBuf, 10, 20, "%s", "abc");
    assertMeetExpectedStr(bigBuf, "abc", ret, __LINE__);


    ret = indirect_snprintf(bigBuf, BIG_BUFFER_SIZE, sizeof(bigBuf) - 1, "%s", "abc");
    assertMeetExpectedStr(bigBuf, "abc", ret, __LINE__);

    ret = indirect_snprintf(bigBuf, 4, 3, "%s", "abc");
    assertMeetExpectedStr(bigBuf, "abc", ret, __LINE__);

    ret = indirect_snprintf(buf, 3, 3, "%s", "abc");
    assert(ret == -1);
    assert(0 == strcmp(buf, "") );
        
#ifdef COMPATIBLE_WIN_FORMAT
    ret = indirect_snprintf(buf, 3, -1, "%s", "abc");
    assert(ret == -1);
    assert(0 == strcmp(buf, "ab") );
#endif
}

static char branchesTestBuf[5121+256];
void test_sprintf_s_branches(void)
{
#ifndef VXWORKS_CAVIUM_5434
    int ret = 0;
    int i=1;
    /*long l=2;*//*unused variable*/
#if (defined(_MSC_VER) && (_MSC_VER == 1200))
    INT64T li = 3;
#else
    long long  li=3;
#endif

#if defined(COMPATIBLE_LINUX_FORMAT)
    ptrdiff_t ptrdiff=4;
    size_t size = 5;
#else
    int ptrdiff=4;
    int size = 5;
#endif
   
#if defined(COMPATIBLE_LINUX_FORMAT)
    long double ld=123.123;
#endif
    double d=123.123;


#if defined(COMPATIBLE_LINUX_FORMAT)
    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%qd,%Ld,%td,%zd,%.3Lf",li,li,ptrdiff,size,ld,d);
    assertMeetExpectedStr(branchesTestBuf, "3,3,4,5,123.123", ret, __LINE__);

    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%A,%a",d,d);
    assert(ret == -1);
    //assertMeetExpectedStr(branchesTestBuf, "0X1.EC7DF3B645A1DP+6,0x1.ec7df3b645a1dp+6", ret, __LINE__);

    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%.5121Lf",ld);
    assert(ret != -1);

   ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%#####################1Lf,%*.*f,%*.1f,%1.*f",ld,i,i,d,i,d,i,d);
   assertMeetExpectedStr(branchesTestBuf, "123.123000,123.1,123.1,123.1", ret, __LINE__);

    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%hhd,%hhu,%+ d,% d",128,128,128,128);
    assertMeetExpectedStr(branchesTestBuf, "-128,128,+128, 128", ret, __LINE__);

    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%#####################1Lf,%*.*Lf,%*.1Lf,%1.*Lf",ld,i,i,ld,i,ld,i,ld);
    assertMeetExpectedStr(branchesTestBuf, "123.123000,123.1,123.1,123.1", ret, __LINE__);
 

#else
    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%qd,%Ld,%td,%zd,%.3Lf",li,li,ptrdiff,size,(long double)d);
    assertMeetExpectedStr(branchesTestBuf, "3,3,4,5,123.123", ret, __LINE__);
    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%A,%a",d,d);
    assert(ret == -1);

    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%.5121Lf",(long double)d);
    assert(ret != -1);

    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%#####################1Lf,%*.*f,%*.1f,%1.*f",(long double)d,i,i,d,i,d,i,d);
    assertMeetExpectedStr(branchesTestBuf, "123.123000,123.1,123.1,123.1", ret, __LINE__);

    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%hhd,%hhu,%+ d,% d",128,128,128,128);
    assertMeetExpectedStr(branchesTestBuf, "-128,128,+128, 128", ret, __LINE__);
#endif
 
    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%2147483648d",128);
    assert(ret == -1);
    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%.2147483648d",128);
    assert(ret == -1);

    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%.2147483647f",1.0);
    assert(branchesTestBuf[0] == '\0');

    ret = sprintf_s(branchesTestBuf, sizeof(branchesTestBuf), "%.2147483647Lf",(long double)1.0);
    assert(branchesTestBuf[0] == '\0');
#endif
}


#ifndef SECUREC_VXWORKS_PLATFORM
static wchar_t branchesTestBufw[5121+256];
void test_swprintf_s_branches(void)
{
    int ret = 0;
    int i=1;
    long l=2;
#if (defined(_MSC_VER) && (_MSC_VER == 1200))
    INT64T li = 3;
#else
    long long  li=3;
#endif
#if defined(COMPATIBLE_LINUX_FORMAT)
    ptrdiff_t ptrdiff=4;
    size_t size = 5;
        char *ptr = NULL;
#else
    int ptrdiff=4;
    int size = 5;
#endif


    long double ld=123.123;
    double d=123.123;


#if defined(COMPATIBLE_LINUX_FORMAT)
   ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%qd,%Ld,%td,%zd,%.3Lf",li,li,ptrdiff,size,ld);
    assertMeetExpectedWstr(branchesTestBufw, L"3,3,4,5,123.123", ret, __LINE__);

    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%A,%a",d,d);
    assert(ret == -1);
    //assertMeetExpectedStr(branchesTestBuf, "0X1.EC7DF3B645A1DP+6,0x1.ec7df3b645a1dp+6", ret, __LINE__);

    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%E",d);
    assert(ret != -1);

    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%.5121Lf",ld);
    assert(ret != -1);

   ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%#####################1Lf,%*.*f,%*.1f,%1.*f",ld,i,i,d,i,d,i,d);
    assertMeetExpectedWstr(branchesTestBufw, L"123.123000,123.1,123.1,123.1", ret, __LINE__);

    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%hhd,%hhu,%+ d,% d",128,128,128,128);
    assertMeetExpectedWstr(branchesTestBufw, L"-128,128,+128, 128", ret, __LINE__);

    ret = swprintf_s(branchesTestBufw,sizeof(branchesTestBufw)/sizeof(wchar_t), L"%#Lf,%*.*Lf,%*.1Lf,%1.*Lf",ld,i,i,ld,i,ld,i,ld);
    assertMeetExpectedWstr(branchesTestBufw, L"123.123000,123.1,123.1,123.1", ret, __LINE__);


#if defined(COMPATIBLE_LINUX_FORMAT) && (!defined(__UNIX)) 
    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t),L"%p",NULL);
        assertMeetExpectedWstr(branchesTestBufw, L"(nil)", ret, __LINE__);
#endif

   ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t),L"%jd,%ju,%zu,%zd",li,li,size,size);
   assertMeetExpectedWstr(branchesTestBufw, L"3,3,5,5", ret, __LINE__);

   ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t),L"%ls",NULL);
   assertMeetExpectedWstr(branchesTestBufw, L"(null)", ret, __LINE__);


#else
    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%qd,%Ld,%td,%zd,%.3Lf",li,li,ptrdiff,size,d);
    assertMeetExpectedWstr(branchesTestBufw, L"3,3,4,5,123.123", ret, __LINE__);

    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%A,%a",d,d);
    assert(ret == -1);

    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%E",d);
    assert(ret != -1);;

    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%.5121Lf",d);
    assert(ret != -1);

    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%#####################1Lf,%*.*f,%*.1f,%1.*f",d,i,i,d,i,d,i,d);
    assertMeetExpectedWstr(branchesTestBufw, L"123.123000,123.1,123.1,123.1", ret, __LINE__);

    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%hhd,%hhu,%+ d,% d",128,128,128,128);
    assertMeetExpectedWstr(branchesTestBufw, L"-128,128,+128, 128", ret, __LINE__);
#endif

    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%2147483648d",128);
    assert(ret == -1);
    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%.2147483648d",128);
    assert(ret == -1);

    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%.2147483647f",1.0);
    assert(branchesTestBufw[0] == L'\0');
    ret = swprintf_s(branchesTestBufw, sizeof(branchesTestBufw)/sizeof(wchar_t), L"%.2147483647Lf",1.0);
    assert(branchesTestBufw[0] == L'\0');
}
#endif
