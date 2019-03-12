
#include "securec.h"
#include "base_funcs.h"
#include "dopra_comptest.h"
#include <string.h>
#ifdef COMPATIBLE_LINUX_FORMAT
#include <stdint.h>
#include <stddef.h>
#endif
#include <stdio.h>
#include <stdlib.h>


int byte_order()
 {
    unsigned short wValue = 0x1234;
    unsigned char myVal[] = {0x12, 0x34, 0x56, 0x78, 0x91, 0x32, 0x54, 0x76  };
    unsigned int i = 0;
#if !(defined(__hpux))
    i = *(int*)(myVal +1);

   if (*(char*)&wValue == 0x12) 
    {
        return 1;
    }
   else
    {
        return 0;
    }
#endif    
    return 0;
}

#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
/**
 *@test    Itest_VOS_sscanf_01
 *- @tspec    VOS_sscanf
 *- @ttitle    д���ַ�64λ���ͣ�"%lld"
 *- @tbrief    
 *        -# ���洫��"9223372036854775807 123"
 *- @texpect    д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_01()
{    
    VOS_CHAR   sBuf[64] = "9223372036854775807 123";  
    VOS_INT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_INT64 iExpValue = 0x7fffffffffffffffULL;
    
    Tl_VOS_sscanf_INT64(sBuf,"%lld",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_02
 *- @tspec    VOS_sscanf
 *- @ttitle    д���ַ�64λ���ͣ�"%lld"
 *- @tbrief    
 *        -# ���洫��"0"
 *- @texpect    д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_02()
{    
    VOS_CHAR   sBuf[64] = "0";  
    VOS_INT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_INT64 iExpValue = 0;
    
    Tl_VOS_sscanf_INT64(sBuf,"%lld",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_03
 *- @tspec    VOS_sscanf
 *- @ttitle    д���ַ�64λ���ͣ�"%lld"
 *- @tbrief    
 *        -# ���洫��"1"
 *- @texpect    д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_03()
{    
    VOS_CHAR   sBuf[64] = "1";  
    VOS_INT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_INT64 iExpValue = 1;
    
    Tl_VOS_sscanf_INT64(sBuf,"%lld",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_04
 *- @tspec    VOS_sscanf
 *- @ttitle    д���ַ�64λ���ͣ�"%lld"
 *- @tbrief    
 *        -# ���洫��"-1"
 *- @texpect    д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_04()
{    
    VOS_CHAR   sBuf[64] = "-1";  
    VOS_INT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_INT64 iExpValue = -1;
    
    Tl_VOS_sscanf_INT64(sBuf,"%lld",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_05
 *- @tspec    VOS_sscanf
 *- @ttitle    д���ַ�64λ���ͣ�"%lld"
 *- @tbrief    
 *        -# ���洫��"4294967294"
 *- @texpect    д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_05()
{    
    VOS_CHAR   sBuf[64] = "4294967294";  
    VOS_INT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_INT64 iExpValue = 0xFFFFFFFE;
    
    Tl_VOS_sscanf_INT64(sBuf,"%lld",iValue,(VOS_INT32)uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_06
 *- @tspec    VOS_sscanf
 *- @ttitle    д���ַ�64λ���ͣ�"%lld"
 *- @tbrief    
 *        -# ���洫��"-4294967294"
 *- @texpect    д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_06()
{    
    VOS_CHAR   sBuf[64] = "-4294967294";  
    VOS_INT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_INT64 iExpValue = 0xFFFFFFFF00000002LL;
    
    Tl_VOS_sscanf_INT64(sBuf,"%lld",iValue,uiRet,iExpValue);
    
}


/**
 *@test    Itest_VOS_sscanf_07
 *- @tspec    VOS_sscanf
 *- @ttitle    д���ַ�64λ���ͣ�"%llu"
 *- @tbrief    
 *        -# ���洫��"0"
 *- @texpect    д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_07()
{    
    VOS_CHAR   sBuf[64] = "0";  
    VOS_UINT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_UINT64 iExpValue = 0;
    
    Tl_VOS_sscanf_UINT64(sBuf,"%llu",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_08
 *- @tspec    VOS_sscanf
 *- @ttitle    д���ַ�64λ���ͣ�"%llu"
 *- @tbrief    
 *        -# ���洫��"9223372036854775807"
 *- @texpect    д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_08()
{    
    VOS_CHAR   sBuf[64] = "18446744073709551615";  
    VOS_UINT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_UINT64 iExpValue = 0xffffffffffffffffULL;
    
    Tl_VOS_sscanf_UINT64(sBuf,"%llu",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_08
 *- @tspec    VOS_sscanf
 *- @ttitle    д���ַ�64λ���ͣ�"%llu"
 *- @tbrief    
 *        -# ���洫��"-1"
 *- @texpect    д�벻�ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_09()
{    
    VOS_CHAR   sBuf[64] = "-1";  
    VOS_UINT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_UINT64 iExpValue = (VOS_UINT64)(-1);
    
    Tl_VOS_sscanf_UINT64(sBuf,"%llu",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sprintf_01
 *- @tspec    VOS_sprintf
 *- @ttitle    ��ȡ64λ���ͣ�"%llu"
 *- @tbrief    
 *        -# ���洫��"1"
 *- @texpect   ��ȡ�ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sprintf_01()
{    
    VOS_CHAR   sReadBuf[64] = {0};  
    VOS_UINT64  sWriteBuf = 1;  
    VOS_INT32 uiExpRet = 18;/*sjl modify sprintf return int value, not uint32 value*/
    VOS_CHAR iExpValue[64] = "vos_sprintf test 1";
    
    Tl_VOS_sprintf_UINT64(sReadBuf,"vos_sprintf test %llu",sWriteBuf,uiExpRet,iExpValue,VOS_OK);/*sjl test bug*/

    
}

/**
 *@test    Itest_VOS_sprintf_02
 *- @tspec    VOS_sprintf
 *- @ttitle    ��ȡ64λ���ͣ�"%llu"
 *- @tbrief    
 *        -# ���洫��"0xffffffffffffffff"
 *- @texpect   ��ȡ�ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sprintf_02()
{    
    VOS_CHAR   sReadBuf[64];  
    VOS_UINT64  sWriteBuf = 0xffffffffffffffffULL;  
    VOS_INT32 uiExpRet = 37;
    VOS_CHAR iExpValue[64] = "vos_sprintf test 18446744073709551615";
    
    Tl_VOS_sprintf_UINT64(sReadBuf,"vos_sprintf test %llu",sWriteBuf,uiExpRet,iExpValue,VOS_OK);

    
}

/**
 *@test    Itest_VOS_sprintf_03
 *- @tspec    VOS_sprintf
 *- @ttitle    ��ȡ64λ���ͣ�"%llu"
 *- @tbrief    
 *        -# ���洫��"1"
 *- @texpect   ��ȡ�ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sprintf_03()
{    
    VOS_CHAR   sReadBuf[64];  
    VOS_UINT64  sWriteBuf = (VOS_UINT64)(-1);  
    VOS_INT32 uiExpRet = 19;
    VOS_CHAR iExpValue[64] = "vos_sprintf test -1";
    
    Tl_VOS_sprintf_UINT64(sReadBuf,"vos_sprintf test %llu",sWriteBuf,uiExpRet,iExpValue,(VOS_UINT32)VOS_ERROR);

    
}

/**
 *@test    Itest_VOS_sprintf_04
 *- @tspec    VOS_sprintf
 *- @ttitle    ��ȡ64λ���ͣ�"%lld"
 *- @tbrief    
 *        -# ���洫��"1"
 *- @texpect   ��ȡ�ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sprintf_04()
{    
    VOS_CHAR   sReadBuf[64];  
    VOS_UINT64  sWriteBuf = (VOS_UINT64)(-1);  
    VOS_INT32 uiExpRet = 19;
    VOS_CHAR iExpValue[64] = "vos_sprintf test -1";
    
    Tl_VOS_sprintf_INT64(sReadBuf,"vos_sprintf test %lld",(VOS_INT64)sWriteBuf,uiExpRet,iExpValue,VOS_OK);
  
}

/**
 *@test    Itest_VOS_sprintf_05
 *- @tspec    VOS_sprintf
 *- @ttitle    ��ȡ64λ���ͣ�"%lld"
 *- @tbrief    
 *        -# ���洫��"1"
 *- @texpect   ��ȡ�ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sprintf_05()
{    
    VOS_CHAR   sReadBuf[64];  
    VOS_UINT64  sWriteBuf = 0x7fffffffffffffffULL;  
    VOS_INT32 uiExpRet = 36;
    VOS_CHAR iExpValue[64] = "vos_sprintf test 9223372036854775807";
    
    Tl_VOS_sprintf_INT64(sReadBuf,"vos_sprintf test %lld",(VOS_INT64)sWriteBuf,uiExpRet,iExpValue,VOS_OK); 
}
#endif
/**
 *@test    Itest_VOS_sprintf_06
 *- @tspec    VOS_sprintf
 *- @ttitle    ��ȡ64λ���ͣ�"%lld"
 *- @tbrief    
 *        -# ���洫��"1"
 *- @texpect   ��ȡ�ɹ�
 *- @tprior
 *- @tremark �������ڴ�˻������У������
 */

#ifndef _MSC_VER
 VOS_VOID Itest_VOS_sprintf_06()
{  
    VOS_CHAR   sReadBuf[64];  
    VOS_UINT64  sWriteBuf = 0x7fffffffffffffffULL;  
    
#if (VOS_WORDSIZE == 64)
    VOS_INT32 uiExpRet = 36;
    
    VOS_CHAR iExpValue[64] = "vos_sprintf test 9223372036854775807"; 
    
    Tl_VOS_sprintf_INT64(sReadBuf,"vos_sprintf test %zd",(VOS_INT64)sWriteBuf,uiExpRet,iExpValue,VOS_OK);
#else
    
    /* �ڴ�˻�������,��ȡ 7fffffff */
#if (byte_order)
    VOS_INT32 uiExpRet = 27;
    VOS_CHAR iExpValue[64] = "vos_sprintf test 2147483647";  /* �������ڴ�˻������У���ȡǰ���֣����Ǻ󲿷� */

    Tl_VOS_sprintf_INT64(sReadBuf,"vos_sprintf test %zd",(VOS_INT64)sWriteBuf,uiExpRet,iExpValue,VOS_OK);
#else
    VOS_INT uiExpRet = 19;
    VOS_CHAR iExpValue[64] = "vos_sprintf test -1";  

    Tl_VOS_sprintf_INT64(sReadBuf,"vos_sprintf test %zd",(VOS_INT64)sWriteBuf,uiExpRet,iExpValue,VOS_OK);
#endif
#endif 
}
#endif
/**
 *@test    Itest_VOS_nvsprintf_01
 *- @tspec    VOS_nvsprintf
 *- @ttitle    ��acString������д�뵽acBuff
 *- @tbrief    
 *        -# �����Ժ������ؿ������ֽڳ��ȣ�Ҫ��������󳤶ȴ����ַ����ĳ���
 *- @texpect   д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_01()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "Itest_VOS_nvsprintf_01";
    VOS_UINT32 uiMaxStrLen = 64;
    VOS_INT32 ulStrLen;
    
    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, acString);

    CU_ASSERT_EQUAL(ulStrLen, VOS_StrLen(acString));
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
 *@test    Itest_VOS_nvsprintf_02
 *- @tspec    VOS_nvsprintf
 *- @ttitle    ��acString������д�뵽acBuff
 *- @tbrief    
 *        -# �����Ժ������ؿ������ֽڳ��ȣ�Ҫ��������󳤶�С���ַ����ĳ���
 *           
 *- @texpect   д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_02()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "Itest_VOS_nvsprintf_02";
    VOS_UINT32 uiMaxStrLen = 23;
    VOS_INT32 ulStrLen = 0;
    
    ulStrLen = Tl_VOS_nvsprintf(acBuff,uiMaxStrLen,acString);/*uiMaxStrLen must smaller than 64 and bigger than 21*/
    
    /*uiMaxStrLen�ĳ��Ȱ���'\0'*/
    CU_ASSERT_EQUAL(ulStrLen + 1, uiMaxStrLen);
    VOS_MemCmp(acBuff, acString, (VOS_SIZE_T)ulStrLen);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
 *@test    Itest_VOS_nvsprintf_03
 *- @tspec    VOS_nvsprintf
 *- @ttitle    ��acString������д�뵽acBuff
 *- @tbrief    
 *        -# �����쳣���(acBuffΪ�ա�uiMaxStrLenΪ0��acStringΪ�ա�argΪ��)
 *          
 *- @texpect   д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_03()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "Itest_VOS_nvsprintf_03";
    VOS_UINT32 uiMaxStrLen = 19;
    VOS_INT32 ulStrLen;

    ulStrLen = Tl_VOS_nvsprintf(VOS_NULL_PTR, uiMaxStrLen, acString);
    CU_ASSERT_EQUAL(ulStrLen, (VOS_UINT32)-1);

    ulStrLen = Tl_VOS_nvsprintf(acBuff, 0, acString);
    CU_ASSERT_EQUAL(ulStrLen, (VOS_UINT32)-1);

    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, VOS_NULL_PTR);
    CU_ASSERT_EQUAL(ulStrLen, (VOS_UINT32)-1);
    
/* ���Ա�����SEκ��:
    weizhe:
    va_list�����Ͼ���ָ��ջ�ϵ�һ��ָ�룬��ͬ��ƽ̨��ʵ�ֵĶ������в��á�
    �е���char* ���� void*,��arm�ϵ�gcc4.1֮���ϸ���arm��eabi���壬��һ���ṹ���ṹ���滹�Ǹ�ָ�룩��
    �Ҿ��� (NULL == arguments) ����ж�û�б�Ҫ������ɾ����
    ��Ϊva_list��һ��ָ��ջ�ĵ�ַ��ֻ��ͨ��va_start va_end va_arg�⼸����������������������ǿ�ָ�롣
    ���һ��Ҫд����жϣ��������������ģ�
    (NULL == *(void**)&arguments)
    �����һ��ǽ���ɾ����
�������Ϸ�������������ע��;
    ulStrLen = VOS_nvsprintf(acBuff, uiMaxStrLen, acString, NULL);
    CU_ASSERT_EQUAL(ulStrLen, -1); */ 
    
}

/**
 *@test    Itest_VOS_nvsprintf_04
 *- @tspec    VOS_nvsprintf
 *- @ttitle    ��acString������д�뵽acBuff
 *- @tbrief    
 *        -# �����Ժ������ؿ������ֽڳ��ȣ�acStringΪ'\0'
 *           
 *- @texpect   д��ʧ��
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_04()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "\0";
    VOS_UINT32 uiMaxStrLen = 19;
    VOS_INT32 ulStrLen;
    
    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, acString);

    CU_ASSERT_EQUAL(ulStrLen, 0);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
 *@test    Itest_VOS_nvsprintf_05
 *- @tspec    VOS_nvsprintf
 *- @ttitle    ������д�뵽acBuff
 *- @tbrief    
 *        -# ���洫��"5"��������д��acBuff��Ȼ����acString��Ƚ�
 *           
 *- @texpect   д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_05()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "nvprintf test 5";
    VOS_UINT32 uiMaxStrLen = 16;
    VOS_INT32 ulStrLen;
    VOS_INT32 lNum = 5;
    
    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, "nvprintf test %ld", lNum);

    CU_ASSERT_EQUAL(ulStrLen + 1, uiMaxStrLen);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
 *@test    Itest_VOS_nvsprintf_06
 *- @tspec    VOS_nvsprintf
 *- @ttitle    ������д�뵽acBuff
 *- @tbrief    
 *        -# ���洫��"-1"��������д��acBuff��Ȼ����acString��Ƚ�
 *           
 *- @texpect   д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_06()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "nvprintf test -1";
    VOS_UINT32 uiMaxStrLen = 17;
    VOS_INT32 ulStrLen;
    VOS_INT32 lNum = -1;
    
    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, "nvprintf test %d", lNum);

    CU_ASSERT_EQUAL(ulStrLen + 1, uiMaxStrLen);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
 *@test    Itest_VOS_nvsprintf_07
 *- @tspec    VOS_nvsprintf
 *- @ttitle    ��ȡ64λ�޷������ͣ�"%llu"
 *- @tbrief    
 *        -# ���洫��"0xffffffffffffffffULL"��������д��acBuff��Ȼ����acString��Ƚ�
 *           
 *- @texpect   д��ɹ�
 *- @tprior
 *- @tremark
 */
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_nvsprintf_07()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "nvprintf test 18446744073709551615";
    VOS_UINT32 uiMaxStrLen = 35;
    VOS_INT32 ulStrLen;
    VOS_UINT64 ullNum = 0xffffffffffffffffULL;

    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, "nvprintf test %llu", ullNum);

    CU_ASSERT_EQUAL(ulStrLen + 1, uiMaxStrLen);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
 *@test    Itest_VOS_nvsprintf_08
 *- @tspec    VOS_nvsprintf
 *- @ttitle    ��ȡ64λ���ͣ�"%lld"
 *- @tbrief    
 *        -# ���洫��"0x7fffffffffffffffULL"��������д��acBuff��Ȼ����acString��Ƚ�
 *           
 *- @texpect   д��ɹ�
 *- @tprior
 *- @tremark
 */

 VOS_VOID Itest_VOS_nvsprintf_08()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "nvprintf test 9223372036854775807";
    VOS_UINT32 uiMaxStrLen = 34;
    VOS_INT32 ulStrLen;
    VOS_INT64 ullNum = 0x7fffffffffffffffULL;

    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, "nvprintf test %lld", ullNum);

    CU_ASSERT_EQUAL(ulStrLen + 1, uiMaxStrLen);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}
#endif
/**
 *@test    Itest_VOS_nvsprintf_09
 *- @tspec    VOS_nvsprintf
 *- @ttitle    ����������
 *- @tbrief    
 *        -# ���洫��"1","2","3","4"��������д��acBuff��Ȼ����acString��Ƚ�
 *           
 *- @texpect   д��ɹ�
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_09()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "nvprintf test 1 2 3 4";
    VOS_UINT32 uiMaxStrLen = 22;
    VOS_INT32 ulStrLen;
    VOS_INT32 lNum1 = 1;
    VOS_INT32 lNum2 = 2;
    VOS_INT32 lNum3 = 3;
    VOS_INT32 lNum4 = 4;

    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, 
        "nvprintf test %d %d %d %d", lNum1, lNum2, lNum3, lNum4);

    CU_ASSERT_EQUAL(ulStrLen + 1, uiMaxStrLen);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
*@test Itest_VOS_sprintf_FUNC_001
*- @tspec
*- @ttitle VOS_sprintfʹ�á�z���ֱ���cdiouxX���
*- @tprecon DOPRAĬ�����ã�32λϵͳ
*- @tbrief 1.VOS_sprintfʹ�á�z���ֱ���c��d��i��o��u��x��X���
           2.�жϷ���λ��
           3.�жϴ�ӡ��ֵ��ʵ��ֵ
*- @texpect 1.�������λ����ȷ
            2.��ӡ��ֵ��ʵ��ֵһ��
*- @tprior 1
*- @tauto True
*- @tremark
*/
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
#ifndef SECUREC_ON_64BITS
VOS_VOID Itest_VOS_sprintf_FUNC_001()
{
    VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T iNum   = 2147483647;  /* 32λ �з����� ���ֵ */
    VOS_UINT32 uiNum = 4294967295UL;  /* 32λ �޷����� ���ֵ */  
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* �ýӿڷֱ����ʽ�����ַ���"%zc"��"%zd"��"%zi"��"%zo"��"%zu"��"%zx"��"%zX"��� */
    uiRet = VOS_sprintf(scBuffer, "%zc", cBuffer);
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBuffer, "z");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zi", iNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zo", uiNum);
    CU_ASSERT_EQUAL(uiRet, 11);
    uiRet = VOS_StrCmp(scBuffer, "37777777777");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zu", uiNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "4294967295");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zx", uiNum);
    CU_ASSERT_EQUAL(uiRet, 8);
    uiRet = VOS_StrCmp(scBuffer, "ffffffff");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zX", uiNum);
    CU_ASSERT_EQUAL(uiRet, 8);
    uiRet = VOS_StrCmp(scBuffer, "FFFFFFFF");
    CU_ASSERT_EQUAL(uiRet, 0);    
}
/**
*@test Itest_VOS_nsprintf_FUNC_001
*- @tspec
*- @ttitle VOS_nsprintfʹ�á�z���ֱ���cdiouxX���
*- @tprecon DOPRAĬ�����ã�32λϵͳ
*- @tbrief 1.VOS_nsprintfʹ�á�z���ֱ���c��d��i��o��u��x��X���
           2.�жϷ���λ��
           3.�жϴ�ӡ��ֵ��ʵ��ֵ
*- @texpect 1.�������λ����ȷ
            2.��ӡ��ֵ��ʵ��ֵһ��
*- @tprior 1
*- @tauto True
*- @tremark
*/

VOS_VOID Itest_VOS_nsprintf_FUNC_001()
{
    VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T iNum   = 2147483647;  /* 32λ �з����� ���ֵ */
    VOS_UINT32 uiNum = 4294967295UL;  /* 32λ �޷����� ���ֵ */  
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* �ýӿڷֱ����ʽ�����ַ���"%zc"��"%zd"��"%zi"��"%zo"��"%zu"��"%zx"��"%zX"��� */
    uiRet = VOS_nsprintf(scBuffer, 64, "%zc", cBuffer);
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBuffer, "z");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zi", iNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zo", uiNum);
    CU_ASSERT_EQUAL(uiRet, 11);
    uiRet = VOS_StrCmp(scBuffer, "37777777777");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zu", uiNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "4294967295");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zx", uiNum);
    CU_ASSERT_EQUAL(uiRet, 8);
    uiRet = VOS_StrCmp(scBuffer, "ffffffff");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zX", uiNum);
    CU_ASSERT_EQUAL(uiRet, 8);
    uiRet = VOS_StrCmp(scBuffer, "FFFFFFFF");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/**
*@test Itest_VOS_sscanf_FUNC_001
*- @tspec
*- @ttitle VOS_sscanfʹ�á�z���ֱ���cdiouxX���
*- @tprecon DOPRAĬ�����ã�32λϵͳ
*- @tbrief 1.VOS_sscanfʹ�á�z���ֱ���c��d��i��o��u��x��X���
           2.�ж����뷵��λ��
           3.�ж�������ֵ��ʵ��ֵ�Ƿ�һ��
*- @texpect 1.���뷵��λ����ȷ
            2.��ӡ��ֵ��ʵ��ֵһ��
*- @tprior 1
*- @tauto True
*- @tremark
*/

VOS_VOID Itest_VOS_sscanf_FUNC_001()
{
    //VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T uiNumFirst   = 2147483647;  /* 32λ �з����� ���ֵ */
    VOS_SIZE_T iNumAdd = 0;
    VOS_UINT32 uiNum = 4294967295UL;  /* 32λ �޷����� ���ֵ */  
    VOS_UINT32 uiNumAdd;
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* �ýӿڷֱ����ʽ�����ַ���"%zc"��"%zd"��"%zi"��"%zo"��"%zu"��"%zx"��"%zX"��� */
    uiRet = VOS_sscanf("z", "%zc", scBuffer,sizeof(scBuffer));
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBuffer, "z");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sscanf("2147483647", "%zd", &iNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(iNumAdd, uiNumFirst);

    uiRet = VOS_sscanf("2147483647", "%zi", &iNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(iNumAdd, uiNumFirst);

    uiRet = VOS_sscanf("37777777777", "%zo", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);

    uiRet = VOS_sscanf("4294967295", "%zu", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);

    uiRet = VOS_sscanf("ffffffff", "%zx", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);

    uiRet = VOS_sscanf("FFFFFFFF", "%zX", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);
}

/**
*@test Itest_VOS__vsprintf_FUNC_001
*- @tspec
*- @ttitle VOS_vsprintf/ VOS_nvsprintf��'zd'���
*- @tprecon DOPRAĬ�����ã�32λϵͳ
*- @tbrief 1.VOS_vsprintf/ VOS_nvsprintf�ֱ���'zd'���
           2.�ж����뷵��λ��
           3.�ж�������ֵ��ʵ��ֵ�Ƿ�һ��
*- @texpect 1.��ȷ����λ��
            2.��ӡ��ֵ��ʵ��ֵһ��
*- @tprior 1
*- @tauto True
*- @tremark
*/

/* VOS_vsprintf/ VOS_nvsprintf�漰�ɱ�����б�ָ�룬�������������ڷ�װ���б�ָ�� */



VOS_VOID Itest_VOS__vsprintf_FUNC_001()
{   
 //   VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T iNum   = 2147483647;  /* 32λ �з����� ���ֵ */
   // VOS_UINT32 uiNum = 4294967295;  /* 32λ �޷����� ���ֵ */  
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* VOS_vsprintf/ VOS_nvsprintf�ֱ��ʽ�����ַ���"%zd"��� */
    uiRet = Test_VOS_vsprintf(scBuffer, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = Test_VOS_nvsprintf(scBuffer, 64, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);
   
}

/**
*@test Itest_VOS_sprintf_FUNC_002
*- @tspec
*- @ttitle VOS_sprintf��'Zd'��'dz'��'zz'���
*- @tprecon DOPRAĬ�����ã�32λϵͳ
*- @tbrief 1.VOS_sprintf��'Zd'��'dz'��'zz'���
           2.�ж����뷵��λ����Χ
           
*- @texpect 1.����λ����Χ��ȷ
            2.��������ִ�У����쳣
*- @tprior 1
*- @tauto False
*- @tremark
*/

VOS_VOID Itest_VOS_sprintf_FUNC_002()
{
//    VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T iNum   = 2147483647;  /* 32λ �з����� ���ֵ */
  //  VOS_UINT32 uiNum = 4294967295;  /* 32λ �޷����� ���ֵ */  
    VOS_INT32 iRet = 0;
    VOS_CHAR scBuffer[64] = {0};
  
    /* �ýӿڷֱ���Ƿ���ʽ�����ַ���"Zd"��"dz"��"zz"��� */
   
    iRet = VOS_sprintf(scBuffer, "%Zd", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_sprintf(scBuffer, "%dz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_sprintf(scBuffer, "%zz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer);
    
    //printf("\n%d-", VOS_nsprintf(scBuffer, 64, "%Zd", Num));
    /* printf("\n\r scBuffer is %p,\r the bit is %u\n", scBuffer,uiRet);
   
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);
    */
    /*
    uiRet = VOS_sprintf(scBuffer, "%dz", iNum);
    printf("\n\r scBuffer is %p,\r the bit is %u\n", scBuffer,uiRet);

    pcBuffer = VOS_MemSet(scBuffer,0,(sizeof(VOS_CHAR)*64));
    printf("\n\r scBuffer is %p\r \n", scBuffer);
    
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);
    */
/*
    uiRet = VOS_sprintf(scBuffer, "%zz", uiNum);
    printf("\n\rscBuffer is %p,\r the bit is %u\n", scBuffer,uiRet);
    
    CU_ASSERT_EQUAL(uiRet, 11);
    uiRet = VOS_StrCmp(scBuffer, "4294967295");
    CU_ASSERT_EQUAL(uiRet, 0);
    */

}

/**
*@test Itest_VOS_nsprintf_FUNC_002
*- @tspec
*- @ttitle VOS_nsprintf��'Zd'��'dz'��'zz'���
*- @tprecon DOPRAĬ�����ã�32λϵͳ
*- @tbrief 1.VOS_nsprintf��'Zd'��'dz'��'zz'���
           2.�ж����뷵��λ����Χ
           
*- @texpect 1.����λ����Χ��ȷ
            2.��������ִ�У����쳣
*- @tprior 1
*- @tauto False
*- @tremark
*/

VOS_VOID Itest_VOS_nsprintf_FUNC_002()
{
   // VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T iNum   = 2147483647;  /* 32λ �з����� ���ֵ */
 //   VOS_UINT32 uiNum = 4294967295;  /* 32λ �޷����� ���ֵ */  
    VOS_INT32 iRet = 0;
    VOS_CHAR scBuffer[64] = {0};
  
    /* �ýӿڷֱ���Ƿ���ʽ�����ַ���"Zd"��"dz"��"zz"��� */
   
    iRet = VOS_nsprintf(scBuffer, 64, "%Zd", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_nsprintf(scBuffer, 64, "%dz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_nsprintf(scBuffer, 64, "%zz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer);
}

/**
*@test Itest_VOS_sscanf_FUNC_002
*- @tspec
*- @ttitle VOS_sscanf��'Zd'��'dz'��'zz'���
*- @tprecon DOPRAĬ�����ã�32λϵͳ
*- @tbrief 1.VOS_sscanf��'Zd'��'dz'��'zz'���
           2.�ж����뷵��λ����Χ
           
*- @texpect 1.����λ����Χ��ȷ
            2.��������ִ�У����쳣
*- @tprior 1
*- @tauto False
*- @tremark
*/

VOS_VOID Itest_VOS_sscanf_FUNC_002()
{
    //VOS_INT32 iNumAdd   = 2147483647;  /* 32λ �з����� ���ֵ */
    VOS_SIZE_T iNumAdd = 4294967295UL;  /* 32λ �޷����� ���ֵ */  
    VOS_INT32 iRet = 0;
    //VOS_CHAR scBuffer[64] = {0};
  
    /* �ýӿڷֱ���Ƿ���ʽ�����ַ���"Zd"��"dz"��"zz"��� */
   
    
    iRet = VOS_sscanf("2147483647", "%Zd", &iNumAdd);    

    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n iNumAdd is %zd\n", iNumAdd); 

    iRet = VOS_sscanf("2147483647", "%dz", &iNumAdd);    

    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n iNumAdd is %zd\n", iNumAdd); 

    iRet = VOS_sscanf("2147483647", "%zz", &iNumAdd);    

    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n iNumAdd is %zd\n", iNumAdd); 

}
#endif

#ifdef SECUREC_ON_64BITS
/**
*@test Itest_VOS_sprintf_FUNC_003
*- @tspec
*- @ttitle VOS_sprintfʹ�á�z���ֱ���cdiouxX���
*- @tprecon DOPRAĬ�����ã�64λϵͳ
*- @tbrief 1.VOS_sprintfʹ�á�z���ֱ���c��d��i��o��u��x��X���
           2.�жϷ���λ��
           3.�жϴ�ӡ��ֵ��ʵ��ֵ
*- @texpect 1.�������λ����ȷ
            2.��ӡ��ֵ��ʵ��ֵһ��
*- @tprior 1
*- @tauto True
*- @tremark
*/

VOS_VOID Itest_VOS_sprintf_FUNC_003()
{
    VOS_CHAR cBuffer = 'z';
    VOS_INT64 iNum   = 9223372036854775807;  /* 64λ �з����� ���ֵ */
    VOS_SIZE_T uiNum = 18446744073709551615UL;  /* 64λ �޷����� ���ֵ */  
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* �ýӿڷֱ����ʽ�����ַ���"%zc"��"%zd"��"%zi"��"%zo"��"%zu"��"%zx"��"%zX"��� */
    uiRet = VOS_sprintf(scBuffer, "%zc", cBuffer);
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBuffer, "z");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 19);
    uiRet = VOS_StrCmp(scBuffer, "9223372036854775807");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zi", iNum);
    CU_ASSERT_EQUAL(uiRet, 19);
    uiRet = VOS_StrCmp(scBuffer, "9223372036854775807");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zo", uiNum);
    CU_ASSERT_EQUAL(uiRet, 22);
    uiRet = VOS_StrCmp(scBuffer, "1777777777777777777777");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zu", uiNum);
    CU_ASSERT_EQUAL(uiRet, 20);
    uiRet = VOS_StrCmp(scBuffer, "18446744073709551615");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zx", uiNum);
    CU_ASSERT_EQUAL(uiRet, 16);
    uiRet = VOS_StrCmp(scBuffer, "ffffffffffffffff");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zX", uiNum);
    CU_ASSERT_EQUAL(uiRet, 16);
    uiRet = VOS_StrCmp(scBuffer, "FFFFFFFFFFFFFFFF");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/**
*@test Itest_VOS_nsprintf_FUNC_003
*- @tspec
*- @ttitle VOS_nsprintfʹ�á�z���ֱ���cdiouxX���
*- @tprecon DOPRAĬ�����ã�64λϵͳ
*- @tbrief 1.VOS_nsprintfʹ�á�z���ֱ���c��d��i��o��u��x��X���
           2.�жϷ���λ��
           3.�жϴ�ӡ��ֵ��ʵ��ֵ
*- @texpect 1.�������λ����ȷ
            2.��ӡ��ֵ��ʵ��ֵһ��
*- @tprior 1
*- @tauto True
*- @tremark
*/

VOS_VOID Itest_VOS_nsprintf_FUNC_003()
{
    VOS_CHAR cBuffer = 'z';
    VOS_INT64 iNum   = 9223372036854775807;  /* 64λ �з����� ���ֵ */
    VOS_SIZE_T uiNum = 18446744073709551615UL;  /* 64λ �޷����� ���ֵ */  
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* �ýӿڷֱ����ʽ�����ַ���"%zc"��"%zd"��"%zi"��"%zo"��"%zu"��"%zx"��"%zX"��� */
    uiRet = VOS_nsprintf(scBuffer, 64, "%zc", cBuffer);
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBuffer, "z");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 19);
    uiRet = VOS_StrCmp(scBuffer, "9223372036854775807");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zi", iNum);
    CU_ASSERT_EQUAL(uiRet, 19);
    uiRet = VOS_StrCmp(scBuffer, "9223372036854775807");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zo", uiNum);
    CU_ASSERT_EQUAL(uiRet, 22);
    uiRet = VOS_StrCmp(scBuffer, "1777777777777777777777");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zu", uiNum);
    CU_ASSERT_EQUAL(uiRet, 20);
    uiRet = VOS_StrCmp(scBuffer, "18446744073709551615");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zx", uiNum);
    CU_ASSERT_EQUAL(uiRet, 16);
    uiRet = VOS_StrCmp(scBuffer, "ffffffffffffffff");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zX", uiNum);
    CU_ASSERT_EQUAL(uiRet, 16);
    uiRet = VOS_StrCmp(scBuffer, "FFFFFFFFFFFFFFFF");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/**
*@test Itest_VOS_sscanf_FUNC_003
*- @tspec
*- @ttitle VOS_sscanfʹ�á�z���ֱ���cdiouxX���
*- @tprecon DOPRAĬ�����ã�64λϵͳ
*- @tbrief 1.VOS_sscanfʹ�á�z���ֱ���c��d��i��o��u��x��X���
           2.�ж����뷵��λ��
           3.�ж�������ֵ��ʵ��ֵ�Ƿ�һ��
*- @texpect 1.���뷵��λ����ȷ
            2.��ӡ��ֵ��ʵ��ֵһ��
*- @tprior 1
*- @tauto True
*- @tremark
*/

VOS_VOID Itest_VOS_sscanf_FUNC_003()
{
   // VOS_CHAR cBuffer = 'z';
    VOS_INT64 iNum   = 9223372036854775807;  /* 64λ �з����� ���ֵ */
    VOS_INT64 iNumAdd;
    VOS_SIZE_T uiNum = 18446744073709551615UL;  /* 64λ �޷����� ���ֵ */  
    VOS_SIZE_T uiNumAdd;
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBufferAdd[64] = {0};

    /* �ýӿڷֱ����ʽ�����ַ���"%zc"��"%zd"��"%zi"��"%zo"��"%zu"��"%zx"��"%zX"��� */
    uiRet = VOS_sscanf("z", "%zc", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBufferAdd, "z");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sscanf("9223372036854775807", "%zd", &iNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(iNumAdd, iNum);

    uiRet = VOS_sscanf("9223372036854775807", "%zi", &iNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(iNumAdd, iNum);

    uiRet = VOS_sscanf("1777777777777777777777", "%zo", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);

    uiRet = VOS_sscanf("18446744073709551615", "%zu", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);

    uiRet = VOS_sscanf("ffffffffffffffff", "%zx", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);

    uiRet = VOS_sscanf("FFFFFFFFFFFFFFFF", "%zX", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);
}

/**
*@test Itest_VOS__vsprintf_FUNC_002
*- @tspec
*- @ttitle VOS_vsprintf/ VOS_nvsprintf��'zd'���
*- @tprecon DOPRAĬ�����ã�64λϵͳ
*- @tbrief 1.VOS_vsprintf/ VOS_nvsprintf�ֱ���'zd'���
           2.�ж����뷵��λ��
           3.�ж�������ֵ��ʵ��ֵ�Ƿ�һ��
*- @texpect 1.��ȷ����λ��
            2.��ӡ��ֵ��ʵ��ֵһ��
*- @tprior 1
*- @tauto True
*- @tremark
*/

VOS_VOID Itest_VOS__vsprintf_FUNC_002()
{
   // VOS_CHAR cBuffer = 'z';
    VOS_INT64 iNum   = 9223372036854775807;  /* 64λ �з����� ���ֵ */
    //VOS_UINT64 uiNum = 18446744073709551615;  /* 64λ �޷����� ���ֵ */  
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* VOS_vsprintf/ VOS_nvsprintf�ֱ��ʽ�����ַ���"%zd"��� */
    uiRet = Test_VOS_vsprintf(scBuffer, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 19);
    uiRet = VOS_StrCmp(scBuffer, "9223372036854775807");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = Test_VOS_nvsprintf(scBuffer, 64, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 19);
    uiRet = VOS_StrCmp(scBuffer, "9223372036854775807");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/**
*@test Itest_VOS_sprintf_FUNC_004
*- @tspec
*- @ttitle VOS_sprintf��'Zd'��'dz'��'zz'���
*- @tprecon DOPRAĬ�����ã�64λϵͳ
*- @tbrief 1.VOS_sprintf��'Zd'��'dz'��'zz'���
           2.�ж����뷵��λ����Χ
           
*- @texpect 1.����λ����Χ��ȷ
            2.��������ִ�У����쳣
*- @tprior 1
*- @tauto False
*- @tremark
*/

VOS_VOID Itest_VOS_sprintf_FUNC_004()
{
    //VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T iNum   = (VOS_SIZE_T)9223372036854775807;  /* 64λ �з����� ���ֵ */
    //VOS_UINT64 uiNum = 18446744073709551615;  /* 64λ �޷����� ���ֵ */  
    VOS_INT32 iRet = 0;
    VOS_CHAR scBuffer[64] = {0};
  
    /* �ýӿڷֱ���Ƿ���ʽ�����ַ���"Zd"��"dz"��"zz"��� */
   
    iRet = VOS_sprintf(scBuffer, "%Zd", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_sprintf(scBuffer, "%dz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_sprintf(scBuffer, "%zz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer);
}

/**
*@test Itest_VOS_nsprintf_FUNC_004
*- @tspec
*- @ttitle VOS_nsprintf��'Zd'��'dz'��'zz'���
*- @tprecon DOPRAĬ�����ã�64λϵͳ
*- @tbrief 1.VOS_nsprintf��'Zd'��'dz'��'zz'���
           2.�ж����뷵��λ����Χ
           
*- @texpect 1.����λ����Χ��ȷ
            2.��������ִ�У����쳣
*- @tprior 1
*- @tauto False
*- @tremark
*/

VOS_VOID Itest_VOS_nsprintf_FUNC_004()
{
    VOS_SIZE_T iNum   = (VOS_SIZE_T)9223372036854775807;  /* 64λ �з����� ���ֵ */
    //VOS_UINT64 uiNum = 18446744073709551615;  /* 64λ �޷����� ���ֵ */  
    VOS_INT32 iRet = 0;
    VOS_CHAR scBuffer[64] = {0};
  
    /* �ýӿڷֱ���Ƿ���ʽ�����ַ���"Zd"��"dz"��"zz"��� */
   
    iRet = VOS_nsprintf(scBuffer, 64, "%Zd", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_nsprintf(scBuffer, 64, "%dz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_nsprintf(scBuffer, 64, "%zz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer);
}

/**
*@test Itest_VOS_sscanf_FUNC_004
*- @tspec
*- @ttitle VOS_sscanf��'Zd'��'dz'��'zz'���
*- @tprecon DOPRAĬ�����ã�64λϵͳ
*- @tbrief 1.VOS_sscanf��'Zd'��'dz'��'zz'���
           2.�ж����뷵��λ����Χ
           
*- @texpect 1.����λ����Χ��ȷ
            2.��������ִ�У����쳣
*- @tprior 1
*- @tauto False
*- @tremark
*/

VOS_VOID Itest_VOS_sscanf_FUNC_004()
{
    VOS_SIZE_T iNumAdd = (VOS_SIZE_T)9223372036854775807;  /* 64λ �з����� ���ֵ */  
    VOS_INT32 iRet = 0;
      
    /* �ýӿڷֱ���Ƿ���ʽ�����ַ���"Zd"��"dz"��"zz"��� */    
    iRet = VOS_sscanf("9223372036854775807", "%Zd", &iNumAdd);    

    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n iNumAdd is %zu\n", iNumAdd); 

    iRet = VOS_sscanf("9223372036854775807", "%dz", &iNumAdd);    

    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n iNumAdd is %zu\n", iNumAdd); 

    iRet = VOS_sscanf("9223372036854775807", "%zz", &iNumAdd);    

    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n iNumAdd is %zu\n", iNumAdd); 
}
#endif
#endif
/**
*@test Itest_VOS_sscanf_FUNC_005
*- @tspec
*- @ttitle VOS_sscanf��"%i"���
*- @tprecon DOPRAĬ�����ã�32λϵͳ
*- @tbrief 1.VOS_sscanf��"%i"���
           2.�ж����뷵��ֵ��ȷ
           
*- @texpect 1.���뷵��ֵ��ȷ
     
*- @tprior 1
*- @tauto False
*- @tremark DTS2013040801523 
*/

VOS_VOID Itest_VOS_sscanf_FUNC_005()
{
    VOS_INT32  siNum1 = 0x12345678;
    VOS_INT32  siNum2 = 0;   
    VOS_CHAR   scTmpBuf[50] = {0};

    VOS_sprintf(scTmpBuf, "%i", siNum1);
    CU_ASSERT_EQUAL(VOS_sscanf(scTmpBuf, "%i", &siNum2), 1);
    CU_ASSERT_EQUAL(siNum1, siNum2);
    //printf("\n siNum1 is %d \n",siNum1);
    //printf("\n siNum2 is %d \n",siNum2);
}

/**
*@test Itest_VOS_sprintf_FUNC_006
*- @tspec
*- @ttitle VOS_sprintf������0x80000000������ȷ

*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sprintf������0x80000000����
           2.�ж����뷵��ֵ��ȷ
           
*- @texpect 1.���뷵��ֵ��ȷ
     
*- @tprior 1
*- @tauto False
*- @tremark DTS2013062508226 
*/

VOS_VOID Itest_VOS_sprintf_FUNC_006()
{
    unsigned long dwVal = 0x80000000;
    char acOutputString[64];
    memset(acOutputString, 0, sizeof(acOutputString));
     
    (void)VOS_sprintf(acOutputString, "%ld", (signed long)dwVal);
    //printf("ld fmt signed long=%s(%lu)\r\n", acOutputString, dwVal);
#ifdef SECUREC_ON_64BITS    
    #if (defined(COMPATIBLE_WIN_FORMAT))
	CU_ASSERT_EQUAL(0,strcmp(acOutputString, "-2147483648"));
    #else
    CU_ASSERT_EQUAL(0,strcmp(acOutputString, "2147483648"));
    #endif
#else
    CU_ASSERT_EQUAL(0,strcmp(acOutputString, "-2147483648"));
#endif

}


VOS_UINT32 test_CompareStringError(const char * pStringA, const char * pStringB)
{
    VOS_INT32 iRet;

    iRet = VOS_StrCmp(pStringA,pStringB);

    if (0 != iRet)
    {
        VOS_Printf("\nASSERT_ERROR! pStringA: %s ,  pStringB: %s \n", pStringA, pStringB);
        return VOS_ERROR;
    }

    return VOS_OK;
}

/**
*@test Itest_VOS_nsprintf_FUNC_005
*- @tspec
*- @ttitle VOS_nsprintf��"%ld"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nsprintf��"%ld"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_005()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    long int tempNum1 = 0;
    long int tempNum2 = 0;
    
    #ifndef SECUREC_ON_64BITS
    tempNum1 = 0x7fffffff; // 2147483647
    tempNum2 = 0x80000000; //-2147483648

    iRet = VOS_nsprintf(sBuff, 64, "%ld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "2147483647"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%ld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 11);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-2147483648"), VOS_OK);

    #else
    #if (defined(COMPATIBLE_WIN_FORMAT))
    VOS_INT64 tempNum11 = 0x7fffffffffffffff;        /*   9223372036854775807       19���ַ�*/
    VOS_INT64 tempNum22 = 0x8000000000000000;        /* -9223372036854775808     20���ַ�*/

    iRet = VOS_nsprintf(sBuff, 64, "%lld", tempNum11);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%lld", tempNum22);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #else
    tempNum1 = 0x7fffffffffffffff;        /*   9223372036854775807       19���ַ�*/
    tempNum2 = 0x8000000000000000;        /* -9223372036854775808     20���ַ�*/

    iRet = VOS_nsprintf(sBuff, 64, "%ld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%ld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #endif
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_006
*- @tspec
*- @ttitle VOS_nsprintf��"%lu"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nsprintf��"%lu"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_006()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    long unsigned int tempNum1 = 0;
    long unsigned int tempNum2 = 0;
    
    #ifndef SECUREC_ON_64BITS
    tempNum1 = 0xffffffff; // 429 496 729 5
    tempNum2 = 0; 


    iRet = VOS_nsprintf(sBuff, 64, "%lu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "4294967295"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20���ַ�
    tempNum2 = 0; //

    iRet = VOS_nsprintf(sBuff, 64, "%lu", tempNum1);
    #if (defined(COMPATIBLE_WIN_FORMAT))
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "4294967295"), VOS_OK);    
    #else
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);
    #endif

    iRet = VOS_nsprintf(sBuff, 64, "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_007
*- @tspec
*- @ttitle VOS_nsprintf��"%lld"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nsprintf��"%lld"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_nsprintf_FUNC_007()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    #ifndef SECUREC_ON_64BITS
    VOS_INT64  tempNum1 = 0x7fffffffffffffffLL;        /*    9223372036854775807       19���ַ�*/
    VOS_INT64  tempNum2 = (VOS_INT64)0x8000000000000000LL;       /* -9223372036854775808     20���ַ�*/


    iRet = VOS_nsprintf(sBuff, 64, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);

    #else
    VOS_INT64  tempNum1 = 0x7fffffffffffffff;        /*    9223372036854775807       19���ַ�*/
    VOS_INT64  tempNum2 = (VOS_INT64)0x8000000000000000;       /* -9223372036854775808     20���ַ�*/

    iRet = VOS_nsprintf(sBuff, 64, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_008
*- @tspec
*- @ttitle VOS_nsprintf��"%llu"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nsprintf��"%llu"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_008()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;

    #ifndef SECUREC_ON_64BITS
    unsigned   long  long  tempNum1 = 0xffffffffffffffffLL; //184 467 440 737 095 516 15     20���ַ�
    unsigned   long  long  tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20���ַ�
    VOS_UINT64 tempNum2 = 0; 
    
    iRet = VOS_nsprintf(sBuff, 64, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }
#endif 
/**
*@test Itest_VOS_nsprintf_FUNC_009
*- @tspec
*- @ttitle VOS_nsprintf��"%x"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nsprintf��"%x"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_009()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0;

    iRet = VOS_nsprintf(sBuff, 64, "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_010
*- @tspec
*- @ttitle VOS_nsprintf��"%#x"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nsprintf��"%#x"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_010()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0;

    iRet = VOS_nsprintf(sBuff, 64, "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_011
*- @tspec
*- @ttitle VOS_nsprintf��"%X"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nsprintf��"%X"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_011()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0;

    iRet = VOS_nsprintf(sBuff, 64, "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_012
*- @tspec
*- @ttitle VOS_nsprintf��"%#X"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nsprintf��"%#X"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_012()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_013
*- @tspec
*- @ttitle VOS_nsprintf��"%p"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nsprintf��"%p"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_013()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffff; // 268435455

    iRet = VOS_nsprintf(sBuff, 64, "%p", pTemp);
    
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif
    #else
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffffffffffff; //115292 150460 684697 5      19���ַ�

    iRet = VOS_nsprintf(sBuff, 64, "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif
    
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_014
*- @tspec
*- @ttitle VOS_nsprintf��"%lx"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nsprintf��"%lx"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_014()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    long unsigned int tempNum1 = 0;
    long unsigned int tempNum2 = 0;
    
    #ifndef SECUREC_ON_64BITS
    tempNum1 = 0xffffffff; // 268435455
    tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%lx", tempNum1);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
    #else
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
    #endif

    iRet = VOS_nsprintf(sBuff, 64, "%#lx", tempNum1);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
    #else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
    #endif

    iRet = VOS_nsprintf(sBuff, 64, "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_015
*- @tspec
*- @ttitle VOS_nsprintf��"%llx"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nsprintf��"%llx"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_nsprintf_FUNC_015()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
 
    #ifndef SECUREC_ON_64BITS
    unsigned long long tempNum1 = 0xffffffffffffffffLL; // 1152921504606846975
    unsigned long long tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif

 }
#endif 
/**
*@test Itest_VOS_sprintf_FUNC_005
*- @tspec
*- @ttitle VOS_sprintf��"%ld"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sprintf��"%ld"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_005()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    long int tempNum1 = 0;
    long int tempNum2 = 0;
    
    #ifndef SECUREC_ON_64BITS
    tempNum1 = 0x7fffffff;         /* 2147483647  10���ַ�*/
    tempNum2 = 0x80000000;        /*-2147483648 11���ַ�*/

    iRet = VOS_sprintf(sBuff,  "%ld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "2147483647"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%ld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 11);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-2147483648"), VOS_OK);

    #else
    #if (defined(COMPATIBLE_WIN_FORMAT))
    VOS_INT64 tempNum11 = 0x7fffffffffffffff;        /*   9223372036854775807       19���ַ�*/
    VOS_INT64 tempNum22 = 0x8000000000000000;        /* -9223372036854775808     20���ַ�*/

    iRet = VOS_sprintf(sBuff,  "%lld", tempNum11);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%lld", tempNum22);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #else
    tempNum1 = 0x7fffffffffffffff;        /*   9223372036854775807       19���ַ�*/
    tempNum2 = 0x8000000000000000;        /* -9223372036854775808     20���ַ�*/

    iRet = VOS_sprintf(sBuff,  "%ld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%ld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #endif
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_006
*- @tspec
*- @ttitle VOS_sprintf��"%lu"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sprintf��"%lu"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_006_1()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    long unsigned int tempNum1 = 0;
    long unsigned int tempNum2 = 0;
    
    #ifndef SECUREC_ON_64BITS
    tempNum1 = 0xffffffff; // 429 496 729 5
    tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%lu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "4294967295"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20���ַ�
    tempNum2 = 0; //

    iRet = VOS_sprintf(sBuff,  "%lu", tempNum1);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "4294967295"), VOS_OK);
    #else
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);
    #endif

    iRet = VOS_sprintf(sBuff,  "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_007
*- @tspec
*- @ttitle VOS_sprintf��"%lld"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sprintf��"%lld"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER)) 
 VOS_VOID Itest_VOS_sprintf_FUNC_007()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;

    #ifndef SECUREC_ON_64BITS
    VOS_INT64  tempNum1 = 0x7fffffffffffffffLL;        /*    9223372036854775807       19���ַ�*/
    VOS_INT64  tempNum2 = (VOS_INT64)0x8000000000000000LL;       /* -9223372036854775808     20���ַ�*/


    iRet = VOS_sprintf(sBuff, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_sprintf(sBuff, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);

    #else
    VOS_INT64  tempNum1 = 0x7fffffffffffffff;        /*    9223372036854775807       19���ַ�*/
    VOS_INT64  tempNum2 = (VOS_INT64)0x8000000000000000;       /* -9223372036854775808     20���ַ�*/

    iRet = VOS_sprintf(sBuff, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_sprintf(sBuff, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_008
*- @tspec
*- @ttitle VOS_sprintf��"%llu"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sprintf��"%llu"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_008()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
 
    #ifndef SECUREC_ON_64BITS
    VOS_UINT64  tempNum1 = 0xffffffffffffffffLL; //184 467 440 737 095 516 15     20���ַ�
    VOS_UINT64  tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = VOS_sprintf(sBuff, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20���ַ�
    VOS_UINT64 tempNum2 = 0; 
    
    iRet = VOS_sprintf(sBuff, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = VOS_sprintf(sBuff, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif

 }
#endif

/**
*@test Itest_VOS_sprintf_FUNC_009
*- @tspec
*- @ttitle VOS_sprintf��"%x"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sprintf��"%x"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_009()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0;

    iRet = VOS_sprintf(sBuff,  "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_010
*- @tspec
*- @ttitle VOS_sprintf��"%#x"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sprintf��"%#x"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_010()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0;

    iRet = VOS_sprintf(sBuff,  "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_011
*- @tspec
*- @ttitle VOS_sprintf��"%X"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sprintf��"%X"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_011()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0;

    iRet = VOS_sprintf(sBuff,  "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_012
*- @tspec
*- @ttitle VOS_sprintf��"%#X"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sprintf��"%#X"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_012()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_013
*- @tspec
*- @ttitle VOS_sprintf��"%p"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sprintf��"%p"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_013()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffff; // 268435455

    iRet = VOS_sprintf(sBuff,  "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif

    iRet = VOS_sprintf(sBuff,  "%#p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);
#elif defined(__hpux)
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#elif defined(_AIX) || defined(__SOLARIS)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif

#else
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffffffffffff; //115292 150460 684697 5      19���ַ�

    iRet = VOS_sprintf(sBuff,  "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif

    iRet = VOS_sprintf(sBuff,  "%#p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__hpux)
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#elif defined(_AIX) || defined(__SOLARIS)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif
#endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_014
*- @tspec
*- @ttitle VOS_sprintf��"%lx"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sprintf��"%lx"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_014()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    long unsigned int tempNum1 = 0;
    long unsigned int tempNum2 = 0;
    
    #ifndef SECUREC_ON_64BITS
    tempNum1 = 0xffffffff; // 268435455
   tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%lx", tempNum1);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
    #else
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
    #endif

    iRet = VOS_sprintf(sBuff,  "%#lx", tempNum1);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
    #else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
    #endif

    iRet = VOS_sprintf(sBuff,  "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_015
*- @tspec
*- @ttitle VOS_sprintf��"%llx"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sprintf��"%llx"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_015()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))  
    #ifndef SECUREC_ON_64BITS
    unsigned long long tempNum1 = 0xffffffffffffffffLL; // 1152921504606846975
    unsigned long long tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
#endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_003
*- @tspec
*- @ttitle VOS_vsprintf��"%ld"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_vsprintf��"%ld"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_003()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_INT32     tempNum1 = 0x7fffffff;         /* 2147483647  10���ַ�*/
    VOS_INT32     tempNum2 = (VOS_INT32)0x80000000;        /*-2147483648 11���ַ�*/

    iRet = Test_VOS_vsprintf(sBuff,  "%ld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "2147483647"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%ld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 11);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-2147483648"), VOS_OK);

    #else
    VOS_INT64  tempNum1 = 0x7fffffffffffffff;        /*   9223372036854775807       19���ַ�*/
    VOS_INT64  tempNum2 = 0x8000000000000000;        /* -9223372036854775808     20���ַ�*/
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = Test_VOS_vsprintf(sBuff,  "%lld", tempNum1);
#else
    iRet = Test_VOS_vsprintf(sBuff,  "%ld", tempNum1);
#endif
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = Test_VOS_vsprintf(sBuff,  "%lld", tempNum2);
#else
    iRet = Test_VOS_vsprintf(sBuff,  "%ld", tempNum2);
#endif
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_004
*- @tspec
*- @ttitle VOS_vsprintf��"%lu"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_vsprintf��"%lu"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_004()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 429 496 729 5
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%lu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "4294967295"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20���ַ�
    VOS_UINT64 tempNum2 = 0; //
    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_vsprintf(sBuff,  "%llu", tempNum1);
    #else
    iRet = Test_VOS_vsprintf(sBuff,  "%lu", tempNum1);
    #endif

    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_005
*- @tspec
*- @ttitle VOS_vsprintf��"%lld"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_vsprintf��"%lld"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_vsprintf_FUNC_005()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;

    #ifndef SECUREC_ON_64BITS

    VOS_INT64  tempNum1 = 0x7fffffffffffffffLL;        /*   9223372036854775807       19���ַ�*/
    VOS_INT64  tempNum2 = (VOS_INT64)0x8000000000000000LL;        /* -9223372036854775808     20���ַ�*/

    iRet = Test_VOS_vsprintf(sBuff, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);

    #else
    VOS_INT64  tempNum1 = 0x7fffffffffffffff;        /*   9223372036854775807       19���ַ�*/
    VOS_INT64  tempNum2 = 0x8000000000000000;        /* -9223372036854775808     20���ַ�*/

    iRet = Test_VOS_vsprintf(sBuff, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #endif
 }
#endif 
/**
*@test Itest_VOS_vsprintf_FUNC_006
*- @tspec
*- @ttitle VOS_vsprintf��"%llu"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_vsprintf��"%llu"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_006()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))  
#ifndef SECUREC_ON_64BITS
    unsigned   long  long  tempNum1 = 0xffffffffffffffffLL; //184 467 440 737 095 516 15     20���ַ�
    unsigned   long  long  tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20���ַ�
    VOS_UINT64 tempNum2 = 0; 
    
    iRet = Test_VOS_vsprintf(sBuff, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
#endif
 }


/**
*@test Itest_VOS_vsprintf_FUNC_007
*- @tspec
*- @ttitle VOS_vsprintf��"%x"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_vsprintf��"%x"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_007()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0;

    iRet = Test_VOS_vsprintf(sBuff,  "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_008
*- @tspec
*- @ttitle VOS_vsprintf��"%#x"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_vsprintf��"%#x"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_008()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0;

    iRet = Test_VOS_vsprintf(sBuff,  "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_009
*- @tspec
*- @ttitle VOS_vsprintf��"%X"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_vsprintf��"%X"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_009()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0;

    iRet = Test_VOS_vsprintf(sBuff,  "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_012
*- @tspec
*- @ttitle VOS_vsprintf��"%#X"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_vsprintf��"%#X"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_010()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_013
*- @tspec
*- @ttitle VOS_vsprintf��"%p"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_vsprintf��"%p"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_011()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffff; // 268435455

    iRet = Test_VOS_vsprintf(sBuff,  "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif
    iRet = Test_VOS_vsprintf(sBuff,  "%#p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);
#elif defined(__hpux)
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#elif defined(_AIX) || defined(__SOLARIS)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    printf("%s\n",sBuff);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif

#else
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffffffffffff; //115292 150460 684697 5      19���ַ�

    iRet = Test_VOS_vsprintf(sBuff,  "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif

    iRet = Test_VOS_vsprintf(sBuff,  "%#p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__hpux)
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#elif defined(_AIX) || defined(__SOLARIS)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif
#endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_012
*- @tspec
*- @ttitle VOS_vsprintf��"%lx"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_vsprintf��"%lx"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_012()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0; 
    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_vsprintf(sBuff,  "%llx", tempNum1);
    #else
    iRet = Test_VOS_vsprintf(sBuff,  "%lx", tempNum1);
    #endif
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_vsprintf(sBuff,  "%#llx", tempNum1);
    #else
    iRet = Test_VOS_vsprintf(sBuff,  "%#lx", tempNum1);
    #endif
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_013
*- @tspec
*- @ttitle VOS_vsprintf��"%llx"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_vsprintf��"%llx"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_vsprintf_FUNC_013()
{ 
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT64 tempNum1 = 0xffffffffffffffffLL; // 1152921504606846975
    VOS_UINT64 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_INT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_INT64 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
#endif

 }
#endif 
/**
*@test Itest_VOS_vsprintf_FUNC_014
*- @tspec
*- @ttitle VOS_vsprintf��"%d"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_vsprintf��"%d"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_014()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    VOS_INT32     tempNum1 = 0x7fffffff;         /* 2147483647  10���ַ�*/
    VOS_INT32     tempNum2 = (VOS_INT32)0x80000000;        /*-2147483648 11���ַ�*/

    iRet = Test_VOS_vsprintf(sBuff,  "%d", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "2147483647"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%d", tempNum2);
    CU_ASSERT_EQUAL(iRet, 11);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-2147483648"), VOS_OK);
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_003
*- @tspec
*- @ttitle VOS_nvsprintf��"%ld"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nvsprintf��"%ld"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_003()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_INT32     tempNum1 = 0x7fffffff;         /* 2147483647  10���ַ�*/
    VOS_INT32     tempNum2 = (VOS_INT32)0x80000000;        /*-2147483648 11���ַ�*/

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%ld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "2147483647"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%ld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 11);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-2147483648"), VOS_OK);

#else
    VOS_INT64  tempNum1 = 0x7fffffffffffffff;        /*   9223372036854775807       19���ַ�*/
    VOS_INT64  tempNum2 = 0x8000000000000000;        /* -9223372036854775808     20���ַ�*/
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lld", tempNum1);
#else
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%ld", tempNum1);
#endif
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lld", tempNum2);
#else
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%ld", tempNum2);
#endif
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_004
*- @tspec
*- @ttitle VOS_nvsprintf��"%lu"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nvsprintf��"%lu"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_004()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 429 496 729 5
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "4294967295"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20���ַ�
    VOS_UINT64 tempNum2 = 0; //
    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_nvsprintf(sBuff, 64, "%llu", tempNum1);
    #else
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lu", tempNum1);
    #endif
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_nvsprintf(sBuff, 64, "%llu", tempNum2);
    #else
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lu", tempNum2);
    #endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_005
*- @tspec
*- @ttitle VOS_nvsprintf��"%lld"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nvsprintf��"%lld"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_nvsprintf_FUNC_005()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_INT64  tempNum1 = 0x7fffffffffffffffLL;        /*   9223372036854775807       19���ַ�*/
    VOS_INT64  tempNum2 = (VOS_INT64)0x8000000000000000LL;        /* -9223372036854775808     20���ַ�*/

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);

#else
    VOS_INT64  tempNum1 = 0x7fffffffffffffff;        /*   9223372036854775807       19���ַ�*/
    VOS_INT64  tempNum2 = 0x8000000000000000;        /* -9223372036854775808     20���ַ�*/

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_006
*- @tspec
*- @ttitle VOS_nvsprintf��"%llu"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nvsprintf��"%llu"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_006()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT64  tempNum1 = 0xffffffffffffffffLL; //184 467 440 737 095 516 15     20���ַ�
    VOS_UINT64  tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20���ַ�
    VOS_UINT64 tempNum2 = 0; 
    
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }
#endif
/**
*@test Itest_VOS_nvsprintf_FUNC_007
*- @tspec
*- @ttitle VOS_nvsprintf��"%x"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nvsprintf��"%x"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_007()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0;

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_008
*- @tspec
*- @ttitle VOS_nvsprintf��"%#x"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nvsprintf��"%#x"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_008()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0;

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_009
*- @tspec
*- @ttitle VOS_nvsprintf��"%X"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nvsprintf��"%X"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_009()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0;

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_012
*- @tspec
*- @ttitle VOS_nvsprintf��"%#X"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nvsprintf��"%#X"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_010()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_UINT64 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_013
*- @tspec
*- @ttitle VOS_nvsprintf��"%p"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nvsprintf��"%p"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_011()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffff; // 268435455

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif
    
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);
#elif defined(__hpux)
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#elif defined(_AIX) || defined(__SOLARIS)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif

#else
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffffffffffff; //115292 150460 684697 5      19���ַ�

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__hpux)
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#elif defined(_AIX) || defined(__SOLARIS)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_012
*- @tspec
*- @ttitle VOS_nvsprintf��"%lx"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nvsprintf��"%lx"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_012()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_INT32 tempNum1 = (VOS_INT32)0xffffffff; // 268435455
    VOS_INT32 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_INT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_INT64 tempNum2 = 0; 
    #if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llx", tempNum1);
    #else
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lx", tempNum1);
    #endif
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_nvsprintf(sBuff, 64, "%#llx", tempNum1);
    #else
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#lx", tempNum1);
    #endif
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_nvsprintf(sBuff, 64, "%llx", tempNum2);
    #else
	iRet = Test_VOS_nvsprintf(sBuff, 64, "%lx", tempNum2);
    #endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_013
*- @tspec
*- @ttitle VOS_nvsprintf��"%llx"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nvsprintf��"%llx"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_nvsprintf_FUNC_013()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    unsigned long long tempNum1 = 0xffffffffffffffffLL; // 1152921504606846975
    unsigned long long tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_INT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19���ַ�
    VOS_INT64 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }
#endif
/**
*@test Itest_VOS_nvsprintf_FUNC_014
*- @tspec
*- @ttitle VOS_nvsprintf��"%d"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_nvsprintf��"%d"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_014()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;

    VOS_INT32     tempNum1 = 0x7fffffff;         /* 2147483647  10���ַ�*/
    VOS_INT32     tempNum2 = (VOS_INT32)0x80000000;        /*-2147483648 11���ַ�*/

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%d", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "2147483647"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%d", tempNum2);
    CU_ASSERT_EQUAL(iRet, 11);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-2147483648"), VOS_OK);
 }

/**
*@test Itest_VOS_sscanf_FUNC_006
*- @tspec
*- @ttitle VOS_sscanf��"%ld"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sscanf��"%ld"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_006()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf�Ĺ����Ǵ��ַ������������ */
    
#ifndef SECUREC_ON_64BITS
    VOS_INT32 tempNum = 0;

    iRet = VOS_sscanf("2147483647", "%ld", &tempNum);  /* 0x7fffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0x7fffffff);

    iRet = VOS_sscanf("-2147483648", "%ld", &tempNum); /* 0x80000000 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0x80000000);

#else
    VOS_INT64 tempNum = 0;
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = VOS_sscanf("9223372036854775807", "%lld", &tempNum);  /* 0x7fffffffffffffff */
#else
    iRet = VOS_sscanf("9223372036854775807", "%ld", &tempNum);  /* 0x7fffffffffffffff */
#endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0x7fffffffffffffff);
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = VOS_sscanf("-9223372036854775808", "%lld", &tempNum); /* 0x8000000000000000 */
#else
    iRet = VOS_sscanf("-9223372036854775808", "%ld", &tempNum); /* 0x8000000000000000 */
#endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0x8000000000000000);
#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_007
*- @tspec
*- @ttitle VOS_sscanf��"%lu"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sscanf��"%lu"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_007()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf�Ĺ����Ǵ��ַ������������ */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum = 0;

    iRet = VOS_sscanf("4294967295", "%lu", &tempNum);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%lu", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#else
    VOS_UINT64 tempNum = 0;
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = VOS_sscanf("18446744073709551615", "%llu", &tempNum);  /* 0xffffffffffffffff */
#else
    iRet = VOS_sscanf("18446744073709551615", "%lu", &tempNum);  /* 0xffffffffffffffff */
#endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffffffffffff);
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = VOS_sscanf("0", "%llu", &tempNum); /* 0 */
#else
    iRet = VOS_sscanf("0", "%lu", &tempNum); /* 0 */
#endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);
#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_008
*- @tspec
*- @ttitle VOS_sscanf��"%x"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sscanf��"%x"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_008()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf�Ĺ����Ǵ��ַ������������ */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum = 0;

    iRet = VOS_sscanf("ffffffff", "%x", &tempNum);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%x", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#else
    VOS_UINT64 tempNum = 0;

    iRet = VOS_sscanf("ffffffff", "%llx", &tempNum);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%llx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);
#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_009
*- @tspec
*- @ttitle VOS_sscanf��"%#x"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sscanf��"%#x"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_009()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf�Ĺ����Ǵ��ַ������������ */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum = 0;
    iRet = VOS_sscanf("0xffffffff", "%#x", &tempNum);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%#x", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#else
    VOS_UINT64 tempNum = 0;

    iRet = VOS_sscanf("0xffffffff", "%#llx", &tempNum);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);


    iRet = VOS_sscanf("0", "%#llx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#endif/* ������#�� */
 }


/**
*@test Itest_VOS_sscanf_FUNC_010
*- @tspec
*- @ttitle VOS_sscanf��"%X"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sscanf��"%X"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_010()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf�Ĺ����Ǵ��ַ������������ */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum = 0;

    iRet = VOS_sscanf("FFFFFFFF", "%X", &tempNum);  /* 0XFFFFFFFF */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%X", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#else
    VOS_UINT64 tempNum = 0;

    iRet = VOS_sscanf("FFFFFFFF", "%llX", &tempNum);  /* 0XFFFFFFFF */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%llx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);
#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_011
*- @tspec
*- @ttitle VOS_sscanf��"%#X"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sscanf��"%#X"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_011()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf�Ĺ����Ǵ��ַ������������ */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum = 0;
    
    iRet = sscanf("0XFFFFFFFF", "%#X", &tempNum);
    iRet = VOS_sscanf("0XFFFFFFFF", "%#X", &tempNum);  /* 0XFFFFFFFF */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%#X", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#else
    VOS_UINT64 tempNum = 0;

    iRet = VOS_sscanf("0XFFFFFFFF", "%#llX", &tempNum);  /* 0XFFFFFFFF */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%#llX", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_012
*- @tspec
*- @ttitle VOS_sscanf��"%p"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sscanf��"%x"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_012()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf�Ĺ����Ǵ��ַ������������ */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 * pTemp = VOS_NULL_PTR;

    iRet = VOS_sscanf("ffffffff", "%p", &pTemp);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(pTemp, (VOS_UINT32 *)0xffffffff);

    iRet = VOS_sscanf("0", "%x", &pTemp); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(pTemp, 0);

#else
    VOS_UINT64 * pTemp = VOS_NULL_PTR;

    iRet = VOS_sscanf("ffffffff", "%llx", &pTemp);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL((long)pTemp, (long)0xffffffff);

    iRet = VOS_sscanf("0", "%llx", &pTemp); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(pTemp, 0);
#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_013
*- @tspec
*- @ttitle VOS_sscanf��"%lx"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sscanf��"%#lx"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_013()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf�Ĺ����Ǵ��ַ������������ */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum = 0;

    iRet = VOS_sscanf("ffffffff", "%lx", &tempNum);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

#if 0
    tempNum = 0;
    iRet = VOS_sscanf("0xffffffff", "%#lx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);
#endif/* ������#�� */

#else
    VOS_UINT64 tempNum = 0;
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = VOS_sscanf("ffffffffffffffff", "%llx", &tempNum);  /* 0xffffffffffffffff */
#else
    iRet = VOS_sscanf("ffffffffffffffff", "%lx", &tempNum);  /* 0xffffffffffffffff */
#endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffffffffffff);

#if 0
    tempNum = 0;
    iRet = VOS_sscanf("0xffffffffffffffff", "%#lx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffffffffffff);
#endif/* ������#�� */
#endif
 }


/**
*@test Itest_VOS_sscanf_FUNC_014
*- @tspec
*- @ttitle VOS_sscanf��"%llx"���
*- @tprecon DOPRAĬ������
*- @tbrief 1.VOS_sscanf��"%#llx"���
                   2.�ж����뷵��ֵ��ȷ
*- @texpect 1.���뷵��ֵ��ȷ
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_014()
{  
#if !(defined(_MSC_VER) &&(1200 == _MSC_VER))
    VOS_INT32 iRet;

    /* VOS_sscanf�Ĺ����Ǵ��ַ������������ */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT64 tempNum = 0;

    iRet = VOS_sscanf("ffffffffffffffff", "%llx", &tempNum);  /* 0xffffffffffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL((tempNum== 0xffffffffffffffffLL), 1);
#if 0
    iRet = VOS_sscanf("0xffffffffffffffff", "%#llx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL((tempNum== 0xffffffffffffffffLL), 1);
#endif/* ������#�� */

#else
    VOS_UINT64 tempNum = 0;

    iRet = VOS_sscanf("ffffffffffffffff", "%llx", &tempNum);  /* 0xffffffffffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffffffffffff);
#if 0
    iRet = VOS_sscanf("0xffffffffffffffff", "%#llx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffffffffffff);
#endif/* ������#�� */
#endif
#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_015
*- @tspec
*- @ttitle VOS_sscanf��'%[]'���
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf ��'%[]'���
           2.ͨ��%[]��ʽ���ַ���
*- @texpect 
           1.����λ����ȷ
           2.��ʽ������ַ�����ȷ
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_015()
{
    VOS_CHAR scBufferAdd[10]="StringErr";
    VOS_CHAR scBufferAdd2[10]="StringErr"; 
    VOS_INT32 uiRet = 0;

    uiRet = VOS_sscanf("sscanf-noinit-alinit", "sscanf-%[a-z]-%s", scBufferAdd, sizeof(scBufferAdd),scBufferAdd2,sizeof(scBufferAdd2));
    CU_ASSERT_EQUAL(uiRet, 2);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    /*���%[]��ʽ���ַ����Ƿ����ĩβ���'\0'                     */
    /*�����'\0', ��Ӧ�����noinit����û�м�,�����noinitErr*/
    uiRet = VOS_StrCmp(scBufferAdd, "noinit");
    CU_ASSERT_EQUAL(uiRet, 0);

  /*  uiRet = VOS_StrCmp(scBufferAdd2, "alinit");
    CU_ASSERT_EQUAL(uiRet, 0);*//*secure funxtion return StringErr*/
}

/**
*@test Itest_VOS_sscanf_FUNC_016
*- @tspec
*- @ttitle VOS_sscanf��'%[^]'���
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf ��'%[^]'���
           2.ͨ��%[]��ʽ���ַ���
*- @texpect 
           1.����λ����ȷ
           2.��ʽ������ַ�����ȷ
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_016()
{
    VOS_CHAR scBufferAdd[]="HELLOworld"; 
    VOS_INT32 uiRet = 0;
    
    uiRet = VOS_sscanf("HELLOworld", "%[^a-z]", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    /*���%[]��ʽ���ַ����Ƿ����ĩβ���'\0' */
    uiRet = VOS_StrCmp(scBufferAdd, "HELLO");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sscanf("notepad=1.0.0.641", "%[^=]", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "notepad");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sscanf("123abcBCDEF", "%[^C-Z]", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "123abcB");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/**
*@test Itest_VOS_sscanf_FUNC_017
*- @tspec
*- @ttitle VOS_sscanf ��'%[]'���
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf ��'%[]'���
           2.ͨ��%[]��ʽ���ַ���
*- @texpect 
           1.����λ����ȷ
           2.��ʽ������ַ�����ȷ
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_017()
{
    VOS_CHAR scBufferAdd[64]; 
    VOS_CHAR scBufferAdd2[64]; 
    VOS_INT32 uiRet = 0;
    
    uiRet = VOS_sscanf("123456a=AAbcCCdedfBCDEF", "%[1-9a-z]=%s", scBufferAdd,sizeof(scBufferAdd), scBufferAdd2,sizeof(scBufferAdd2));
    CU_ASSERT_EQUAL(uiRet, 2);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "123456a");
    CU_ASSERT_EQUAL(uiRet, 0);

    /*uiRet = VOS_StrCmp(scBufferAdd2, "AAbcCCdedfBCDEF");
    CU_ASSERT_EQUAL(uiRet, 0);*//*securec function return ......123456a*/
}

/**
*@test Itest_VOS_sscanf_FUNC_018
*- @tspec
*- @ttitle VOS_sscanf * ��'%[^]'���
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf * ��'%[^]'���
           2.ͨ��%[]��ʽ���ַ���
*- @texpect 
           1.����λ����ȷ
           2.��ʽ������ַ�����ȷ
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_018()
{
    VOS_CHAR scBufferAdd[64]={0}; 
    VOS_INT32 uiRet = 0;
    
    uiRet = VOS_sscanf("notepad=1.2@#4", "%*[^=]=%s", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "1.2@#4");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/**
*@test Itest_VOS_sscanf_FUNC_019
*- @tspec
*- @ttitle VOS_sscanf  *���ĸ�ʽ���ַ����s c d i  o u x X
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf * ���ĸ�ʽ���ַ����
           2.ͨ��*��ʽ���ַ���
*- @texpect 
           1.����λ����ȷ
           2.��ʽ������ַ�����ȷ
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_019()
{
    VOS_CHAR scBufferAdd[]="HELLOworld"; 
    VOS_INT32 uiRet = 0;
    VOS_INT32 tempNum = 0;
    long int tempNum2 = 0;
    VOS_UINT32 utempNum = 0;
    VOS_CHAR scBuffer[10] = {0};

    /* '*'��%ld���*/
#ifndef SECUREC_ON_64BITS
    tempNum2 = 0;
    uiRet = VOS_sscanf("2147483647,2147483646", "%*ld,%ld", &tempNum2);
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum32 : %ld", tempNum32);
    CU_ASSERT_EQUAL(tempNum2, 0x7FFFFFFE);
    
#else
    tempNum2 = 0;
    uiRet = VOS_sscanf("9223372036854775807,9223372036854775806", "%*ld,%ld", &tempNum2);  /* 0x7fffffffffffffff */
    CU_ASSERT_EQUAL(uiRet, 1);
    printf("\r\n tempNum64 : %ld", tempNum2);
    CU_ASSERT_EQUAL(tempNum2, 0x7FFFFFFFFFFFFFFE);
#endif
    
    /* '*'��%s���*/
    uiRet = VOS_sscanf("hello WORLD", "%*s%*c%s", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "WORLD");
    CU_ASSERT_EQUAL(uiRet, 0);

    /* '*'��%i ���*/
    uiRet = VOS_sscanf("1234()2147483647", "%*i()%i", &tempNum);
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %i", tempNum);
    CU_ASSERT_EQUAL(tempNum, 2147483647);

    /* '*'��%o���*/
    uiRet = VOS_sscanf("1234~77777", "%*o~%o", &utempNum);
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %o", tempNum);
    CU_ASSERT_EQUAL(utempNum, 32767);
    
    /* '*'��%x���*/
    uiRet = VOS_sscanf("abcd^ffffffff", "%*x^%x", &utempNum);
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %x", tempNum);
    CU_ASSERT_EQUAL(utempNum, 4294967295UL);
    
    /* '*'��%X���*/
    uiRet = VOS_sscanf("ABCD@FFFFFFFF", "%*X@%X", &utempNum);
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %X", tempNum);
    CU_ASSERT_EQUAL(utempNum, 4294967295UL);
    
    /* '*'��%u���*/
    uiRet = VOS_sscanf("4294967293#4294967295", "%*u#%u", &utempNum);    
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %u", tempNum);
    CU_ASSERT_EQUAL(utempNum, 4294967295UL);

    /* '*'��%c���*/
    uiRet = VOS_sscanf("x$y", "%*c$%c", scBuffer,sizeof(scBuffer));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %s", scBuffer);
    uiRet = VOS_StrCmp(scBuffer, "y");
    CU_ASSERT_EQUAL(uiRet, 0);

}

/**
*@test Itest_VOS_sscanf_FUNC_020
*- @tspec
*- @ttitle VOS_sscanf  "%hd" "%hu" "%hi"���
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf��"%hd" "%hu" "%hi"���
           2.�ж����뷵��ֵ��ȷ
*- @texpect 
           1.����λ����ȷ
           2.��ʽ������ַ�����ȷ
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_020()
{
    VOS_INT32 uiRet = 0;
    VOS_INT16 tempNum = 0;

    /*%hd��ʽ���ַ���*/
    uiRet = VOS_sscanf("32767", "%hd", &tempNum);  /* 0x7fff*/
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %d", tempNum);
    CU_ASSERT_EQUAL(tempNum, 0x7fff);

    uiRet = VOS_sscanf("-32768", "%hd", &tempNum); /* 0x8000 */
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %d", tempNum);
    CU_ASSERT_EQUAL(tempNum, -32768);
    
    /*%hi��ʽ���ַ���*/
    uiRet = VOS_sscanf("32767", "%hi", &tempNum); 
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %d", tempNum);
    CU_ASSERT_EQUAL(tempNum, 32767);

}

/**
*@test Itest_VOS_sscanf_FUNC_021
*- @tspec
*- @ttitle VOS_sscanf  "%ho" "%hx" "%hX"���
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf��"%ho" "%hx" "%hX"���
           2.�ж����뷵��ֵ��ȷ
*- @texpect 
           1.����λ����ȷ
           2.��ʽ������ַ�����ȷ
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_021()
{
    VOS_INT32 uiRet = 0;
    VOS_UINT16 tempNum = 0;

    /*%ho��ʽ���ַ���*/
    uiRet = VOS_sscanf("77777", "%ho", &tempNum);  /* 0x7fff*/
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %d", tempNum);
    CU_ASSERT_EQUAL(tempNum, 32767);

    /*%hu��ʽ���ַ���*/
    uiRet = VOS_sscanf("65535", "%hu", &tempNum);  /* 0xffff*/
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum2 : %d", tempNum2);
    CU_ASSERT_EQUAL(tempNum, 0xffff);

    uiRet = VOS_sscanf("0", "%hu", &tempNum); /* 0*/
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum2 : %d", tempNum2);
    CU_ASSERT_EQUAL(tempNum, 0);
    
    /*%hx��ʽ���ַ���*/
    uiRet = VOS_sscanf("ffff", "%hx", &tempNum);  /* 0xffff*/
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum2 : %d", tempNum2);
    CU_ASSERT_EQUAL(tempNum, 65535);

    /*%hX��ʽ���ַ���*/
    uiRet = VOS_sscanf("FFFF", "%hX", &tempNum); 
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum2 : %d", tempNum2);
    CU_ASSERT_EQUAL(tempNum, 65535);

}

/**
*@test Itest_VOS_sscanf_FUNC_022
*- @tspec
*- @ttitle VOS_sscanf "n"��s, d,i,0,u,x,X���
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf��"n"��s, d,i,0,u,x,X���
           2.�ж����뷵��ֵ��ȷ
*- @texpect 
           1.����λ����ȷ
           2.��ʽ������ַ�����ȷ
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_022()
{
    VOS_CHAR scBufferAdd[10]="StringErr";
    VOS_INT32 uiRet = 0;
    VOS_INT32 tempNum1 = 0;
    VOS_INT32 tempNum2 = 0;
    VOS_UINT32 utempNum1 = 0;

    /*%ns��ʽ���ַ���*/
    VOS_MemSet(scBufferAdd,0,sizeof(scBufferAdd));
    uiRet = VOS_sscanf("abcdef", "%5s", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBufferAdd, "abcde");
    CU_ASSERT_EQUAL(uiRet, 0);
   
    /*%nd��ʽ���ַ���*/
    tempNum1 = 0;
    tempNum2 = 0;
    uiRet = sscanf("123456", "%3d%3d", &tempNum1, &tempNum2); 

    tempNum1 = 0;
    tempNum2 = 0;
    uiRet = VOS_sscanf("123456", "%3d%3d", &tempNum1, &tempNum2); 
    CU_ASSERT_EQUAL(uiRet, 2);
    CU_ASSERT_EQUAL(tempNum1, 123);
   /* CU_ASSERT_EQUAL(tempNum2, 456);*//*securec can not support %3d%3d*/

    /*%ni��ʽ���ַ���*/
    tempNum1 = 0;
    tempNum2 = 0;
    uiRet = VOS_sscanf("123456", "%3i%3d", &tempNum1, &tempNum2);
    CU_ASSERT_EQUAL(uiRet, 2);
    CU_ASSERT_EQUAL(tempNum1, 123);
    /*CU_ASSERT_EQUAL(tempNum2, 456);*//*securec can not support %3d%3d*/

    /*%no��ʽ���ַ���*/
    utempNum1 = 0;
    uiRet = VOS_sscanf("77777777", "%5o", &utempNum1);
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(utempNum1, 0x7FFF);
    
    /*%nx��ʽ���ַ���*/
    utempNum1 = 0;
    uiRet = VOS_sscanf("ffffffff", "%4x", &utempNum1);
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(utempNum1, 65535);
 
     /*%nX��ʽ���ַ���*/
    utempNum1 = 0;
    uiRet = VOS_sscanf("FFFFFFFF", "%4X", &utempNum1);
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(utempNum1, 65535);
 
     /*%nu��ʽ���ַ���*/
    utempNum1 = 0;
    uiRet = VOS_sscanf("4294967295", "%6u", &utempNum1);
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(utempNum1, 429496);
}

/**
*@test Itest_VOS_sscanf_FUNC_023
*- @tspec
*- @ttitle VOS_sscanf "n"��[]���
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf��"n"��[]���
           2.�ж����뷵��ֵ��ȷ
*- @texpect 
           1.����λ����ȷ
           2.��ʽ������ַ�����ȷ
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_023()
{
    VOS_CHAR scBufferAdd[10]="StringErr";
    VOS_INT32 uiRet = 0;

    /*%n[]��ʽ���ַ���*/
    uiRet = VOS_sscanf("abcdefBAS", "%3[a-z]", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "abc");
    CU_ASSERT_EQUAL(uiRet, 0);
    
     /*%n[^]��ʽ���ַ���*/
    uiRet = VOS_sscanf("ABCDEasad", "%4[^a-z]", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "ABCD");
    CU_ASSERT_EQUAL(uiRet, 0);

}


/**
*@test Itest_VOS_sscanf_FUNC_024
*- @tspec
*- @ttitle VOS_sscanf "%%"��ȡ%
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf��"%%"���
           2.�ж����뷵��ֵ��ȷ
*- @texpect 
           1.����λ����ȷ
           2.��ʽ������ַ�����ȷ
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_024()
{
    VOS_CHAR scBufferAdd[10];
    VOS_INT32 uiRet = 0;

    /*%n[]��ʽ���ַ���*/
    uiRet = VOS_sscanf("%%%123", "%%%%%%%s", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "123");
    CU_ASSERT_EQUAL(uiRet, 0);

}

/**
*@test Itest_VOS_sscanf_FUNC_025
*- @tspec
*- @ttitle VOS_sscanf ��ȡ�ո���ַ�
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf��"%[^\n]"���
           2.�ж����뷵��ֵ��ȷ
*- @texpect 
           1.����λ����ȷ
           2.��ʽ������ַ�����ȷ
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_025()
{
    VOS_CHAR scBufferAdd[64] = {0};
    VOS_INT32 uiRet = 0;

    /*%n[]��ʽ���ַ���*/
    uiRet = VOS_sscanf("Idkalwjdkl$   &^%^   *(*(?>?<?~~~", "%[^\n]*c", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "Idkalwjdkl$   &^%^   *(*(?>?<?~~~");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/* **************** the end *************** */
VOS_VOID dopra_comptest()
{
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
    Itest_VOS_sscanf_01();
    Itest_VOS_sscanf_02();
    Itest_VOS_sscanf_03();
    Itest_VOS_sscanf_04();
    Itest_VOS_sscanf_05();
    Itest_VOS_sscanf_06();

    Itest_VOS_sscanf_07();
    Itest_VOS_sscanf_08();
    Itest_VOS_sscanf_09();
    Itest_VOS_sprintf_01();
    Itest_VOS_sprintf_02();
    Itest_VOS_sprintf_03();
    Itest_VOS_sprintf_04();
    Itest_VOS_sprintf_05();
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    //Itest_VOS_sprintf_06();/*already test in comptest document*/
#endif
    Itest_VOS_nvsprintf_01();
    Itest_VOS_nvsprintf_02();/*bug,count smaller than source string*/
    Itest_VOS_nvsprintf_03();
    Itest_VOS_nvsprintf_04();
    Itest_VOS_nvsprintf_05();
    Itest_VOS_nvsprintf_06();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
    Itest_VOS_nvsprintf_07();
    Itest_VOS_nvsprintf_08();
#endif
    Itest_VOS_nvsprintf_09();
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
#ifndef SECUREC_ON_64BITS
    Itest_VOS_sprintf_FUNC_001();
    Itest_VOS_nsprintf_FUNC_001();
    Itest_VOS_sscanf_FUNC_001();
    Itest_VOS__vsprintf_FUNC_001();
#else
    Itest_VOS_sprintf_FUNC_003();
    Itest_VOS_nsprintf_FUNC_003();
    Itest_VOS_sscanf_FUNC_003();
    Itest_VOS__vsprintf_FUNC_002();
#endif
#endif
    Itest_VOS_sscanf_FUNC_005();
    Itest_VOS_sprintf_FUNC_006();
    Itest_VOS_nsprintf_FUNC_005();
    Itest_VOS_nsprintf_FUNC_006();
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    Itest_VOS_nsprintf_FUNC_007();
    Itest_VOS_nsprintf_FUNC_008();
#endif
    Itest_VOS_nsprintf_FUNC_009();
    Itest_VOS_nsprintf_FUNC_010();
    Itest_VOS_nsprintf_FUNC_011();
    Itest_VOS_nsprintf_FUNC_012();
    Itest_VOS_nsprintf_FUNC_013();/*bug,%#p need to test*/
    Itest_VOS_nsprintf_FUNC_014();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER)) 
    Itest_VOS_nsprintf_FUNC_015();
#endif
    Itest_VOS_sprintf_FUNC_005();
    Itest_VOS_sprintf_FUNC_006_1();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER)) 
    Itest_VOS_sprintf_FUNC_007();
    Itest_VOS_sprintf_FUNC_008();
#endif
    Itest_VOS_sprintf_FUNC_009();
    Itest_VOS_sprintf_FUNC_010();
    Itest_VOS_sprintf_FUNC_011();
    Itest_VOS_sprintf_FUNC_012();
    Itest_VOS_sprintf_FUNC_013();/*bug,%#p need to test*/
    Itest_VOS_sprintf_FUNC_014();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER)) 
    Itest_VOS_sprintf_FUNC_015();
#endif
    Itest_VOS_vsprintf_FUNC_003();
    Itest_VOS_vsprintf_FUNC_004();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER)) 
    Itest_VOS_vsprintf_FUNC_005();
    Itest_VOS_vsprintf_FUNC_006();
#endif
    Itest_VOS_vsprintf_FUNC_007();
    Itest_VOS_vsprintf_FUNC_008();
    Itest_VOS_vsprintf_FUNC_009();
    Itest_VOS_vsprintf_FUNC_010();
    Itest_VOS_vsprintf_FUNC_011();/*bug,%#p need to test*/
    Itest_VOS_vsprintf_FUNC_012();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
    Itest_VOS_vsprintf_FUNC_013();
#endif
    Itest_VOS_vsprintf_FUNC_014();
    Itest_VOS_nvsprintf_FUNC_003();
    Itest_VOS_nvsprintf_FUNC_004();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
    Itest_VOS_nvsprintf_FUNC_005();
    Itest_VOS_nvsprintf_FUNC_006();
#endif
    Itest_VOS_nvsprintf_FUNC_007();
    Itest_VOS_nvsprintf_FUNC_008();
    Itest_VOS_nvsprintf_FUNC_009();
    Itest_VOS_nvsprintf_FUNC_010();
    Itest_VOS_nvsprintf_FUNC_011();/*bug,%#p need to test*/
    Itest_VOS_nvsprintf_FUNC_012();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
    Itest_VOS_nvsprintf_FUNC_013();
#endif
    Itest_VOS_nvsprintf_FUNC_014();
    Itest_VOS_sscanf_FUNC_006();
    Itest_VOS_sscanf_FUNC_007();
    Itest_VOS_sscanf_FUNC_008();
    Itest_VOS_sscanf_FUNC_010();
    Itest_VOS_sscanf_FUNC_012();
    Itest_VOS_sscanf_FUNC_013();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
    Itest_VOS_sscanf_FUNC_014();
#endif
    Itest_VOS_sscanf_FUNC_015();
    Itest_VOS_sscanf_FUNC_016();
    Itest_VOS_sscanf_FUNC_017();
    Itest_VOS_sscanf_FUNC_018();
#if !(defined(SECUREC_ON_64BITS))
    Itest_VOS_sscanf_FUNC_019();/*not the same in linux64*/
#endif
    Itest_VOS_sscanf_FUNC_020();
    Itest_VOS_sscanf_FUNC_021();
    Itest_VOS_sscanf_FUNC_022();
    Itest_VOS_sscanf_FUNC_023();
    Itest_VOS_sscanf_FUNC_024();
    Itest_VOS_sscanf_FUNC_025();
}

VOS_VOID dopratest_main()
{
#if !(defined(SECUREC_VXWORKS_PLATFORM)||(defined(_MSC_VER)&&(1200 ==_MSC_VER)))
    char acString[64] = "Itest_VOS_nvsprintf_02";/*22 character*/
    char scString[10] = "IT_02";/*22 character*/
#endif
    int ret = 0;
    char sBuff[64]={0};
    void *pTemp = NULL;
    unsigned int tempNum = 0; 
    char scBuffer[100] = {0};
#ifdef SECUREC_ON_64BITS
#ifndef _MSC_VER
    long long int iNum = 0;
#else
    __int64 iNum = 0;
#endif
#else
    int iNum = 0;
#endif
    long int templd = 0;

#if !(defined(SECUREC_VXWORKS_PLATFORM)||(defined(_MSC_VER)&&(1200 ==_MSC_VER)))
    /*nvsprintf function test*/
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = VOS_vsnprintf(scBuffer,50,"abcd%s",acString);/*if vsnprintf the count bigger than or equal 26,it will OK*/
    printf("sys:%d,%s\n",ret,scBuffer);
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = VOS_vsnprintf_s(scBuffer,32,50,"abcd%s",acString,sizeof(acString));
    printf("sec:%d,%s\n",ret,scBuffer);

    memset(scBuffer,'a',sizeof(scBuffer));
    ret = VOS_vsnprintf(scBuffer,12,"abcd%s",acString);/*if vsnprintf the count bigger than or equal 26,it will OK*/
    printf("sys:%d,%s\n",ret,scBuffer);
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = VOS_vsnprintf_s(scBuffer,64,12,"abcd%s",acString,sizeof(acString));
    printf("sec:%d,%s\n",ret,scBuffer);

    /*count smaller than the source string length*/
    ret = VOS_vsnprintf(scBuffer,12,"abcd%s",scString);
    printf("sys:%d,%s\n",ret,scBuffer);
    ret = VOS_vsnprintf_s(scBuffer,64,12,"abcd%s",scString,sizeof(scString));
    printf("sec:%d,%s\n",ret,scBuffer);
#endif
    /*sprintf %#p test*/
#ifdef SECUREC_ON_64BITS
        ret = 0;pTemp = (void *)0xffffffffffffffff;
        memset(sBuff,'a',sizeof(sBuff));
        ret = sprintf(sBuff, "%#p", pTemp);
        printf("sys:%s\n",sBuff);
        memset(sBuff,'a',sizeof(sBuff));
        ret = 0;pTemp = (void *)0xffffffffffffffff;
        ret = sprintf_s(sBuff, 64, "%#p", pTemp);
        printf("sec:%s\n",sBuff);
#else
        ret = 0;pTemp = (void *)0xffffffff;
        memset(sBuff,'a',sizeof(sBuff));
        ret = sprintf(sBuff, "%#p", pTemp);
        printf("sys:%s\n",sBuff);
        memset(sBuff,'a',sizeof(sBuff));
        ret = 0;pTemp = (void *)0xffffffff;
        ret = sprintf_s(sBuff, 64, "%#p", pTemp);
        printf("sec:%s\n",sBuff);
#endif
    /*sscanf %#x test*/
    ret = 0; tempNum = 0;
    ret = sscanf("0xffffffff", "%#x", &tempNum); 
    printf("sys:%x\n",tempNum);
    ret = 0; tempNum = 0;
    ret = sscanf_s("0xffffffff", "%#x", &tempNum); 
    printf("sec:%x\n",tempNum);

    /*snprintf %#x test*/
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM))
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = snprintf(sBuff, 64, "%#x", tempNum);
    printf("sys:%d,%s\n",ret,sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = snprintf_s(sBuff, 64,64, "%#x", tempNum); 
    printf("sec:%d,%s\n",ret,sBuff);

    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = snprintf(sBuff, 64, "%#X", tempNum);
    printf("sys:%d,%s\n",ret,sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = snprintf_s(sBuff, 64,64, "%#X", tempNum); 
    printf("sec:%d,%s\n",ret,sBuff);
#endif
    
    /*sprintf %#x test*/
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = sprintf(sBuff, "%#x", tempNum);
    printf("sys:%d,%s\n",ret,sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = sprintf_s(sBuff, 64, "%#x", tempNum); 
    printf("sec:%d,%s\n",ret,sBuff);

    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = sprintf(sBuff, "%#X", tempNum);
    printf("sys:%d,%s\n",ret,sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = sprintf_s(sBuff, 64, "%#X", tempNum); 
    printf("sec:%d,%s\n",ret,sBuff);
    
    /*vsprintf %#x test*/
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    vos_vsprintf(sBuff, "%#x", tempNum);
    printf("sys:%s\n",sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    vos_vsprintf_s(sBuff, 64, "%#x", tempNum); 
    printf("sec:%s\n",sBuff);

    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    vos_vsprintf(sBuff, "%#X", tempNum);
    printf("sys:%s\n",sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    vos_vsprintf_s(sBuff, 64, "%#X", tempNum); 
    printf("sec:%s\n",sBuff);
 
#if !(defined(SECUREC_VXWORKS_PLATFORM)||(defined(_MSC_VER)&&(1200 ==_MSC_VER)))
    /*vsnprintf %#x test*/
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    VOS_vsnprintf(sBuff, 64,"%#x", tempNum);
    printf("sys:%s\n",sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    VOS_vsnprintf_s(sBuff, 64, 64,"%#x", tempNum); 
    printf("sec:%s\n",sBuff);

    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    VOS_vsnprintf(sBuff,  64,"%#X", tempNum);
    printf("sys:%s\n",sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    VOS_vsnprintf_s(sBuff, 64,64, "%#X", tempNum);
    printf("sec:%s\n",sBuff);
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    /*%Zd test*/
    ret = 0; tempNum = 0;
    ret = sscanf("123", "%Zd", &tempNum); 
    printf("sys:%zd\n",tempNum);
    ret = 0; tempNum = 0;
    ret = sscanf_s("0xffffffff", "%Zd", &tempNum); 
    printf("sec:%zd\n",tempNum);
#endif
#ifndef SECUREC_ON_64BITS
    ret = 0;templd = 0;
    ret = sscanf("2147483647,2147483646", "%*ld,%ld", &templd);
    printf("sys,tempNum32 : %ld\n", templd);
    ret = 0;templd = 0;
    ret = sscanf_s("2147483647,2147483646", "%*ld,%ld", &templd);
    printf("sec,tempNum32 : %ld\n", templd);
#else
    ret = 0;templd = 0;
    ret = sscanf("9223372036854775807,9223372036854775806", "%*ld,%ld", &templd);  /* 0x7fffffffffffffff */
    printf("sys,tempNum64 : %ld\n", templd);
    ret = 0;templd = 0;
    ret = sscanf_s("9223372036854775807,9223372036854775806", "%*ld,%ld", &templd);  /* 0x7fffffffffffffff */
    printf("sec,tempNum64 : %ld\n", templd);
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    iNum = 0;ret = 0;
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = sprintf(scBuffer, "%Zd", iNum);
    printf("sys: %s\n", scBuffer); 
    iNum = 0;ret = 0;
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = sprintf_s(scBuffer, 100,"%Zd", iNum);
    printf("sec: %s\n", scBuffer);
#endif
    iNum = 2147483647;ret = 0;
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = sprintf(scBuffer, "%dz", iNum);
    printf("sys: %s\n", scBuffer);
    iNum = 2147483647;ret = 0;
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = sprintf_s(scBuffer, 100,"%dz", iNum);
    printf("sec: %s\n", scBuffer); 
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    iNum = 2147483647;ret = 0;
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = sprintf(scBuffer, "%zz", iNum);
    printf("sys: %s\n", scBuffer);
    iNum = 2147483647;ret = 0;
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = sprintf_s(scBuffer,100, "%zz", iNum);
    printf("sec: %s\n", scBuffer);
#endif
    /*dopra sample test*/
    dopra_comptest();
}
#ifdef __cplusplus
 #if __cplusplus
}
 #endif
#endif 

