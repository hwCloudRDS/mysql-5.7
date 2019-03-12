/*
base_funcs.h
*/

#ifndef __UNITTEST_H__B918_45ed_AECF_676FAD108434
#define __UNITTEST_H__B918_45ed_AECF_676FAD108434

#if !(defined(__hpux) || defined(SECUREC_VXWORKS_PLATFORM))
typedef unsigned int uint32_t;
typedef int int32_t;
#endif
//lint -esym(526, test*)
//lint -esym(526, Test*)
//lint -esym(526, mem*)
//lint -esym(526, wmem*)
//lint -esym(526, scanf*)
//lint -esym(526, strcpy*)
//lint -esym(526, str*)
//lint -esym(526, wcs*)
//lint -esym(526, sprintfPerformanceTest*)
//void testSECPerformance();
void test_strcat_s(void);
void test_strncat_s(void);

void test_strcat_sp(void);
void test_strncat_sp(void);
void testOverlapp(void);
void TestStrcpy_sp(void);
void TestStrncpy_s(void);
void TestMemcpy_sp(void);
void test_memset_sp(void);
void testfscanf_multiline(void);
void testfscanf_xmlspy(void);
void TestStrncpy_sp(void);
#ifndef SECUREC_VXWORKS_PLATFORM
void test_wcscat_s(void);
void test_wcsncat_s(void);
#endif
void testfscanf_read1K(void);
void testsscanf_branches(void);

void testOverlap(void);
void TestStrcpy_s(void);
void TestStrncpy_s();
         
void TestWcscpy_s(void);
void TestWcsncpy_s(void);
         
/*for strcat */
void TestStrcat_s();
void TestStrncat_s();
       
/*strtok*/
void TestStrtok_s();
void test_strtok(void);
void test_wcstok(void);
         
/*for memcpy*/
void TestMemcpy_s(void);
void Test_wmemcpy_s(void);

/*for memmove*/
void memmove_s_test(void);
void wmemmove_s_test(void);

/*for memset*/
void test_memset_s(void);

/*for sprintf*/
void test_snprintf_s(void);
void test_sprintf_s_boundaryCondition(void);
void test_sprintf_s_combination(void);
void test_sprintf_s_basic(void);
void test_vsprintf_s(void);
void test_vswprintf_s(void);
void test_swprintf_s_branches(void);
void test_sprintf_s_branches(void);

void test_swprintf_s_combination(void);
void test_vsnprintf_s(void);

/*for sscanf*/
void scanf_gbk(void);
void test_scanf(void);
void test_wscanf(void);
void test_vscanf(void);
void test_vwscanf(void);

void test_sscanf(void);
void testSwscanf(void);

void testfscanf(void);
void test_fwscanf(void);
void test_vfscanf(void);
void test_vfwscanf(void);

void test_vsscanf(void);
void test_vswscanf(void);
void testfwscanf_read1K(void);
void testswscanf_branches(void);

/*for gets_s*/
void test_gets_s(void);

/*for performance test*/
void TestMemcpyPerformance(void);
 
#define RUN_TIME         9

/*double strcpyTest(int is_secure, int loopCnt);*/
void strcpyPerformanceTest(void);
void wcscpyPerformanceTest(void);
void strncpyPerformanceTest(void);
void wcsncpyPerformanceTest(void);

void strcatPerformanceTest(void);
void wcscatPerformanceTest(void);
void strncatPerformanceTest(void);
void wcsncatPerformanceTest(void);

void memcpyPerformanceTest(void);

void strcpyChunkPerformanceTest(void);
void wcscpyChunkPerformanceTest(void);
void strcatChunkPerformanceTest(void);
void wcscatChunkPerformanceTest(void);

void strcpy_sChunkPerformanceTest(void);


void sprintfPerformanceTest(void);
void ThreeMemcpyPerformanceTest(void);
void ThreeMemsetPerformanceTest(void);
void analyseBestMaxCopyLen(void);

void test_sscanf_d(void);
void test_sscanf_i(void);

void test_sscanf_compare(void);
void test_scanf_compare(void);
void test_fscanf_compare(void);
void test_fwscanf_compare(void);
void test_wscanf_format_s(void);

#endif
