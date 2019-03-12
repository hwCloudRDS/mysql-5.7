

/******************************************************************************

Copyright (C), 2001-2012, Huawei Tech. Co., Ltd.

******************************************************************************
File Name     :
Version       :
Author        :
Created       : 2010/9/1
Last Modified :
Description   :
Function List :

History       :
1.Date        : 2010/9/1
Author      :
Modification: Created file

******************************************************************************/

#include "pub_funcs.h"
#include "securec.h"
/*#include "securecutil.h"*/
#include "base_funcs.h"
#if !(defined(SECUREC_VXWORKS_PLATFORM))
#include "comp_funcs.h"
#endif
/*#include "testutil.h"*/
#include <assert.h>
#include <string.h>
#include <locale.h>
#include "testutil.h"
#include <time.h>
extern void test_sscanf_compare(void);

#ifdef _DEBUG
#define NULL_OR_SOME_ERROR_HANDLER printf("NOT OK")
#define COMP_MEMCPY(dest, destSize, src, cnt) (memcpy_s(dest, destSize, src, cnt) == EOK ? dest : NULL_OR_SOME_ERROR_HANDLER)
#define COMP_STRCPY(p, dSize, s) (strcpy_s(p, dSize, s) == EOK ? p : NULL)
#else /*for release*/
#define COMP_MEMCPY(dest, destSize, src, cnt) (memcpy_s(dest, destSize, src, cnt) , dest)
#define COMP_STRCPY(p, dSize, s) (strcpy_s(p, dSize, s), p)
#endif


#define  MAX_SPRBUF_LEN  1024


void compatiblityTest(void)
{
    FILE *fStd = NULL;
    FILE *fSec = NULL;

    fStd = fopen( "sys_sscanf_output.txt", "w" ); 
    fSec = fopen( "sec_sscanf_output.txt", "w" );
    if((NULL != fStd) && (NULL != fSec))
    {

#if (defined(COMPATIBLE_TESTCASE_LINUX_MANUAL))   
         
        test_sscanf_format_d_add(fStd, fSec); 
        test_sscanf_format_o_add(fStd, fSec);   
        test_sscanf_format_u_add(fStd, fSec); 
        test_sscanf_format_x_add(fStd, fSec); 
        test_sscanf_format_X_add(fStd, fSec);  
        test_sscanf_format_i_add(fStd, fSec);
        /*test_sscanf_format_a_add(fStd, fSec);*/
        test_sscanf_format_c_add(fStd, fSec);  
        test_sscanf_format_s_add(fStd, fSec);  
        test_sscanf_format_e_add(fStd, fSec);
        test_sscanf_format_E_add(fStd, fSec);
        test_sscanf_format_f_add(fStd, fSec);
        test_sscanf_format_g_add(fStd, fSec);
        test_sscanf_format_p_add( fStd, fSec);
        test_sscanf_format_regular_add( fStd, fSec);
        test_sscanf_format_percent_add( fStd, fSec);
        /*test_sscanf_format_n_add(fStd, fSec);  */
        
         
#endif                                                     
        test_sscanf_format_o(fStd, fSec);
        test_sscanf_format_u(fStd, fSec);
        test_sscanf_format_x(fStd, fSec);
        test_sscanf_format_c(fStd, fSec);
        test_sscanf_format_C(fStd, fSec);

        test_sscanf_format_e(fStd, fSec);
        test_sscanf_format_g(fStd, fSec);
        test_sscanf_format_f(fStd, fSec);
#if !(defined(_WIN32) || defined(_WIN64))
        test_sscanf_format_a(fStd, fSec);
#endif
        test_sscanf_format_d(fStd, fSec);
        test_sscanf_format_i(fStd, fSec);
        test_sscanf_format_s(fStd, fSec);
#if !(defined(SECUREC_VXWORKS_PLATFORM))
        test_swscanf_format_s(fStd, fSec);
#endif

#if 0
//test_sscanf_format_n(fStd, fSec);
#endif
        test_sscanf_format_p(fStd, fSec);
        test_sscanf_format_percent(fStd, fSec);
        test_sscanf_format_regular(fStd, fSec);

#if (defined(COMPATIBLE_TESTCASE_COMBIN))
       test_sscanf_format_combin(fStd, fSec);
#endif
        

        fclose(fStd); 
        fStd=NULL;
        fclose(fSec); 
        fSec=NULL;
    }
    else
    {
        printf("fopen error");
    }

    /***printf**********/
    fStd = fopen( "sys_sprintf_output.txt", "w" ); 
    fSec = fopen( "sec_sprintf_output.txt", "w" ); 
    if((NULL != fStd) && (NULL != fSec))
    {
        /*not win ,not vxworks*/
        #if ( !(defined(SECUREC_VXWORKS_PLATFORM)) && !(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER)) ) 
            test_vswprintf_format_s(fStd,fSec);
        #endif

        test_printf_format_o(fStd, fSec);  
        test_printf_format_o_2(fStd, fSec);
        test_printf_format_o_3(fStd, fSec);
        test_printf_format_u(fStd, fSec);
        test_printf_format_u_2(fStd, fSec);
        test_printf_format_u_3(fStd, fSec);
        test_printf_format_x(fStd, fSec); 
        test_printf_format_x_2(fStd, fSec); 
        test_printf_format_x_3(fStd, fSec); 

        //add linux test case
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/
        test_printf_format_X(fStd, fSec);
        test_printf_format_X_2(fStd, fSec);
        test_printf_format_X_3(fStd, fSec);
#endif

        test_printf_format_c(fStd, fSec); 
        test_printf_format_c_2(fStd, fSec); 
        test_printf_format_char_Xing(fStd, fSec); 
        test_printf_format_C(fStd, fSec); 

        test_printf_format_e(fStd, fSec);
        test_printf_format_e_2(fStd, fSec);
        test_printf_format_g(fStd, fSec);
        test_printf_format_g_2(fStd, fSec);
        test_printf_format_f(fStd, fSec);
        test_printf_format_f_2(fStd, fSec);
        test_printf_format_float_Xing(fStd, fSec);

        /*add linux test case*/
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/
        test_printf_format_E(fStd, fSec);
        test_printf_format_E_2(fStd, fSec);
        test_printf_format_F(fStd, fSec);
        
        /* linux 32  sprintf(stdbuf, "%LF", 3.1415926e+00) ,segment error*/
#if !(defined(COMPATIBLE_LINUX_FORMAT))
        test_printf_format_F_2(fStd, fSec);
#endif

        test_printf_format_G(fStd, fSec);
        test_printf_format_G_2(fStd, fSec);
#endif

#if !(defined(_WIN32) || defined(_WIN64))
        test_printf_format_a(fStd, fSec);
#endif

        test_printf_format_d(fStd, fSec);
        test_sprintf_format_i(fStd, fSec);
        test_sprintf_format_i_2(fStd, fSec);
        test_sprintf_format_s(fStd, fSec);
        test_sprintf_format_s_2(fStd, fSec);
        test_sprintf_format_s_3(fStd, fSec);
        test_sprintf_format_s_NULL(fStd, fSec);

#if !(defined(SECUREC_VXWORKS_PLATFORM))
        test_swprintf_format_s(fStd, fSec);
#endif
        //test_printf_format_n(fStd, fSec);
        test_printf_format_p(fStd, fSec);
        test_printf_format_p_2(fStd, fSec);
        test_printf_format_percent(fStd, fSec);
        //test_printf_format_regular(fStd, fSec);
#if !(defined(SECUREC_VXWORKS_PLATFORM))
        test_swprintf_format_p(fStd, fSec);
#endif
        fclose(fStd); 
        fStd=NULL;
        fclose(fSec); 
        fSec=NULL;
    }
    else
    {
        printf("Comparative case:fopen error");
    }
}

#define pr_debug(fmt,arg)  printf(fmt, ##arg)

extern int testFuncsPerformance(int argc, char* argv[]); /* this function implement in t.c */

#if !defined(va_copy) && !defined(__va_copy)
static void  vcheck_va_copy(va_list list)
{
    if(sizeof(va_list) != sizeof(list))
    {
        printf("va_copy or __va_copy  not defined .the scanf, fscanf, sscanf function may not work properly\n");
    }
    else
    {
        printf("sizeof va_list = %d\n",sizeof(va_list));
    }

    return;
}

static void check_va_copy(char *fmt,...)
{
    va_list arglist;

    va_start(arglist,fmt);
    vcheck_va_copy(arglist);
    va_end(arglist);

    return;
}
#endif

int main(int argc, char* argv[])
{
    int testPerformance = 1;
    int testStrcat = 1;
    int testStrcpy = 1;
    int testStrtok= 1;
    int testMemcpy = 1;
    int testMemmove = 1;
    int testMemset = 1;
    int testScanf = 1;
    int testGets = 1;
    int testSprintf = 1;
    int testdopra = 1;

    char strVersion[34] = {0};
    unsigned int i;
    unsigned short usw = 0;
    unsigned short wValue = 0x1234;
    unsigned char myVal[] = {0x12, 0x34, 0x56, 0x78, 0x91, 0x32, 0x54, 0x76  };  
    

    /*show Secure C Version*/
    getHwSecureCVersion(strVersion, 34, &usw);

    printf("Lib Version: %s, major ver = %d, minor ver = %d\n", strVersion, (usw & 0xFF00) >> 8, usw & 0x00FF);
#ifdef SECUREC_ON_64BITS
    printf("Secure C on 64Bits\n");
#else
    printf("Secure C on 32Bits\n");
#endif

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

    printf("sizeof(long int) == %d\n", (int)sizeof (long int));
#if !defined(va_copy) && !defined(__va_copy)
    check_va_copy("notuse");
#endif

    /*wcsncatPerformanceTest();*/
    assert( sizeof(UINT8T) == 1);
    assert( sizeof(int) == 4);
    assert( sizeof(INT64T) == 8);
    assert( sizeof(UINT64T) == 8);

    /*read switch.ini start*/
    initSwitch();
    if (0 == readSwitch())
    {
        testPerformance = getSwitch("withPerformanceTest",1);
        testStrcat = getSwitch("testStrcat",1);
        testStrcpy = getSwitch("testStrcpy",1);
        testStrtok = getSwitch("testStrtok",1);
        testMemcpy= getSwitch("testMemcpy",1);
        testMemmove = getSwitch("testMemmove",1);
        testMemset = getSwitch("testMemset",1);
        testScanf = getSwitch("testScanf",1);
        testGets = getSwitch("testGets",1);
        testSprintf= getSwitch("testSprintf",1);
    }/*read switch.ini end*/  

    if (testSprintf) 
    {
        printf("\n------start test sprintf------\n");
        test_sprintf_s_basic();
        test_sprintf_s_combination();
        test_sprintf_s_boundaryCondition();
#ifndef SECUREC_VXWORKS_PLATFORM
        test_swprintf_s_combination();
        test_swprintf_s_branches();
        /*test printf wide string and char*/
        test_sprintf_s_wString();
        test_swprintf_s_wString();
        test_sprintf_s_wchar();
        test_swprintf_s_wchar();
#endif
        test_vsprintf_s();
#ifndef SECUREC_VXWORKS_PLATFORM
        test_vswprintf_s();
#endif
#if ( !(defined(SECUREC_VXWORKS_PLATFORM)) && !(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER)) ) 
        test_vswprintf_s_utf8();  
#endif
        test_snprintf_s();
        test_vsnprintf_s();
        test_sprintf_s_branches();
        printf("------end test sprintf  OK!------\n");
    }

    if (testStrcat)
    {
        printf("\n------start test strcat------\n");
        test_strcat_s();
        test_strncat_s();
#if defined(WITH_PERFORMANCE_ADDONS)
        test_strcat_sp();
        test_strncat_sp();
#endif
#ifndef SECUREC_VXWORKS_PLATFORM
        test_wcscat_s();
        test_wcsncat_s();
#endif
        printf("------end test strcat  OK!------\n");
    }

    if (testStrcpy) 
    {
        printf("\n------start test strcpy------\n");
        testOverlap();
#if defined(WITH_PERFORMANCE_ADDONS)
        testOverlapp();
#endif
        TestStrcpy_s();
        TestStrncpy_s();
#if defined(WITH_PERFORMANCE_ADDONS)
        TestStrcpy_sp();
        TestStrncpy_sp();
#endif      

#ifndef SECUREC_VXWORKS_PLATFORM
        TestWcscpy_s();
        TestWcsncpy_s();
#endif
        printf("------end test strcpy  OK!------\n");
    }

    /*strtok*/
    if (testStrtok) 
    {
        printf("\n------start test strtok------\n");
        /*TestStrtok_s();*/
        test_strtok();
#ifndef SECUREC_VXWORKS_PLATFORM
        test_wcstok();
#endif
        printf("------end test strtok  OK!------\n");
    }

    /*for memcpy*/
    if (testMemcpy) 
    {
        printf("\n------start test memcpy------\n");
        TestMemcpy_s();
#if defined(WITH_PERFORMANCE_ADDONS)
        TestMemcpy_sp();
#endif
#ifndef SECUREC_VXWORKS_PLATFORM
        Test_wmemcpy_s();
#endif
        printf("------end test memcpy  OK!------\n");
    }

    /*for memset*/
    if (testMemset) 
    {
        printf("\n------start test memset------\n");
        test_memset_s();
#if defined(WITH_PERFORMANCE_ADDONS)
        test_memset_sp();
#endif
        printf("------end test memset  OK!------\n");
    }

    /*for memmove*/
    if (testMemmove) 
    {
        printf("\n------start test memmove------\n");
        memmove_s_test();
#ifndef SECUREC_VXWORKS_PLATFORM
        wmemmove_s_test();
#endif
        printf("------end test memmove  OK!------\n");
    }

    if (testScanf) 
    {
        printf("\n------start test sscanf------\n");

        /*    the following test cases use console which can't automaticly run*/
        /*        test_scanf();*/
        /*        test_vscanf();*/
        /*        test_wscanf();*/
        /*        test_vwscanf();*/

        scanf_gbk();    /*LSD 2014.3.17 add*/
        test_sscanf();
        test_vsscanf();

#if !defined(ONLY_TEST_ANSI_VER_LIB) && !defined(SECUREC_VXWORKS_PLATFORM)
        testSwscanf();
        test_vswscanf();
        test_fwscanf();
        test_vfwscanf();
        testfwscanf_read1K();
        testswscanf_branches();
        test_wscanf_3();
#endif
        testfscanf();
        test_vfscanf();
        printf("------end test sscanf  OK!------\n");

        printf("\n------start test fscanf_s Multi line ------\n");
        testfscanf_multiline();
        printf("------end test fscanf_s Multi line   ------\n\n");

        
        testfscanf_read1K();
        testsscanf_branches();

#ifndef _MSC_VER
        printf("\n------start test fscanf_s xmlspy line ------\n");
        testfscanf_xmlspy();
        printf("------end test fscanf_s xmlspy line   ------\n\n");
#endif

    #ifndef SECUREC_VXWORKS_PLATFORM
        /*test scanf wide string and char*/
        test_sscanf_s_wChar();
        test_swscanf_s_wChar();
        test_sscanf_s_wString();
        test_swscanf_s_wString();
    #endif

    }

    if (testGets) 
    {
        /*the following "gets_s" test cases use console which can't automaticly run*/
        printf("\n------start test gets------\n");
        test_gets_s();
        printf("------end test gets  OK!------\n\n");
    }

    /* test Comparative case */
    compatiblityTest();
    if(testdopra)
    {
        printf("dopra sample test begain\n");
        dopratest_main();
        printf("dopra sample test end\n");
    }

    if (testPerformance) 
    {

#if 0
        printf("\n------Now porformance test------\n");
        sprintfPerformanceTest();

        strcpyChunkPerformanceTest();
#ifndef SECUREC_VXWORKS_PLATFORM
        wcscpyChunkPerformanceTest();
#endif
        strcatChunkPerformanceTest();
#ifndef SECUREC_VXWORKS_PLATFORM
        wcscatChunkPerformanceTest();
#endif

        /* memcpyPerformanceTest();*/
        strcpyPerformanceTest();
#ifndef SECUREC_VXWORKS_PLATFORM
        wcscpyPerformanceTest();
#endif
        strncpyPerformanceTest();
#ifndef SECUREC_VXWORKS_PLATFORM
        wcsncpyPerformanceTest();
#endif

        strcatPerformanceTest();
#ifndef SECUREC_VXWORKS_PLATFORM
        wcscatPerformanceTest();
#endif
        strncatPerformanceTest();
#ifndef SECUREC_VXWORKS_PLATFORM
        wcsncatPerformanceTest();
#endif

#endif
    }

    printf("\n\n--------------------\nall tests finished!\n");
    return 0;
}

