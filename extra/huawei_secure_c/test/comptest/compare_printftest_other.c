
#include "securec.h"
#include "testutil.h"
#include "comp_funcs.h"
#include <string.h>

extern void makeoutputdataprintf(FILE *fstd, 
                          FILE *fsec, 
                          char *formats, 
                          char *sample, 
                          char *sampletype,
                          int stdresult,
                          int secresult,
                          int isdifferent,
                          char *stdbuffer,
                          int stdlen,
                          char *secbuffer,
                          int seclen,
                          unsigned long line);
extern void outputdataprintf(FILE *fstd, 
                      FILE *fsec, 
                      char *formats, 
                      char *sample, 
                      char *sampletype,
                      int stdresult,
                      int secresult,
                      int isdifferent,
                      char *stdbuffer,
                      char *secbuffer,
                      unsigned long line);

void OutputTestResult(
                      char *fun,
                      FILE *fstd, 
                      FILE *fsec, 
                      char *formats, 
                      char *sample, 
                      char *sampletype,
                      int stdresult,
                      int secresult,
                      int isdifferent,
                      char *stdbuffer,
                      int stdlen,
                      char *secbuffer,
                      int seclen,
                      unsigned long line);

#define EPSINON 0.00001


#if defined(COMPATIBLE_LINUX_FORMAT)
#define IS_TEST_LINUX 1
#else
#undef IS_TEST_LINUX
#endif


//void test_printf_format_n(FILE* fStd,FILE* fSec)
//{
    /***************
    char *formats[] = 
    {
        "%hn",
        "%hhn",
        "%hhn",
        "%n",
        "%jn",
        "%ln",
        "%tn",
        "%zn",
        "%lln",
        "%qn",
        NULL
    };


    //注意：只有hn和hhn才是真正的边界值，其他只是用来测试是否支持该参数
    int edge[] = 
    {
        65535,
        255,
        65535,
        65535,//2147483647，太大无法测试
        65535,//2147483647，太大无法测试
        65535,//2147483647，太大无法测试
        65535,//2147483647，太大无法测试
        65535,//4294967295，太大无法测试
        65535,//太大无法测试
        65535,//太大无法测试
    };

    char *flag[] = 
    {
        "edge",
        "overflow",
        NULL
    };

    int value[] = 
    {
        0,
        1
    };

    int i; 
    int j; 
    int ret1 = 0;
    int ret2 = 0;
    int istd = 0;
    int isec = 0;

    char buf_in[65544];
    char buf_out_sys[65544];
    char buf_out_sec[65544];

#ifndef IS_TEST_LINUX
    _set_printf_count_output(1);
#endif

    fprintf(fStd, "-------------------------------n test begin--------------------------- \n");
    fprintf(fSec, "-------------------------------n test begin--------------------------- \n");

    i = j = 0;
    while(NULL != formats[i])
    {
        j=0;
        while(NULL != flag[j])
        {
            buf_out_sys[0] = '\0';
            buf_out_sec[0] = '\0';
            memset(buf_in, 'a', sizeof(buf_in));
            buf_in[edge[i] + value[j]] = '\0';
            strcat(buf_in, formats[i]);

            istd = 0;
            isec = 0;

            ret1 = sprintf(buf_out_sys, buf_in, &istd);
            ret2 = sprintf_s(buf_out_sec, sizeof(buf_out_sec), buf_in, &isec);

            fprintf(fStd,"Expression:sprintf-(%s) data length %d -%s ", formats[i], edge[i] + value[j], flag[j]);
            fprintf(fSec,"Expression:sprintf-(%s) data length %d -%s ", formats[i], edge[i] + value[j], flag[j]);

            if( ret1 == ret2 && istd == isec && strcmp(buf_out_sys, buf_out_sec)==0)
            {
                fprintf(fStd,"comparedResult:Equal\n");
                fprintf(fSec,"comparedResult:Equal\n");
            }
            else
            {
                fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
                fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
            }

            fprintf(fStd,"input strlen: %d\n", strlen(buf_in));
            fprintf(fStd,"return value: %d\n", ret1);
            fprintf(fStd,"output n value: %d\n",istd);
            fprintf(fStd,"output strlen len: %d\n",strlen(buf_out_sys));
            fprintf(fStd,"\n");


            fprintf(fSec,"input strlen: %d\n", strlen(buf_in));
            fprintf(fSec,"return value: %d\n", ret2);
            fprintf(fSec,"output n value: %d\n",isec);
            fprintf(fSec,"output strlen len: %d\n",strlen(buf_out_sec));
            fprintf(fSec,"\n");
            j++;
        }
        i++;
    }
    fprintf(fStd, "-------------------------------n test end--------------------------- \n");
    fprintf(fSec, "-------------------------------n test end--------------------------- \n");
*********/
//}

void test_printf_format_p(FILE* fStd,FILE* fSec)
{
    char *formats[] = 
    {
#ifdef SECUREC_ON_64BITS
        "%p","%#p","%5p","%19p","%22p","%022p",
#else
        "%p","%#p","%5p","%11p","%15p","%022p",
#endif
        NULL
    };

#ifdef SECUREC_ON_64BITS
    void* data[]= 
    {
        (void*)0x123,        
        (void*)0, 
        (void*)0xffffffffffffffff,
    };
    char *samples[][2] = 
    {
        {"0x123",                   "normal"},
        {"0",                     "edge"},
        {"0xffffffffffffffff",    "edge"},
        {NULL, NULL}
    };
#else
    void* data[]= 
    {
       (void*)0x123,        
       (void*)0,     
       (void*)0xffffffff,             
    };
    char *samples[][2] = 
    {
        {"0x123",                   "normal"},
        {"0",                     "edge"},
        {"0xffffffff",            "edge"},
        {NULL, NULL}
    };
#endif

#if !defined(__SOLARIS )
    char *formatEx1s[] = {
        "%p",
        NULL
    };
    char *sampleEx1 = NULL;
#endif

    int i; /*counter for different formats*/
    int k; /*counter for different data*/
    int ret1 = 0;
    int ret2 = 0;

    i=0;
    fprintf(fStd, "-------------------------------p test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------p test begin--------------------------- \n"); /*lint !e668*/

#if !defined(__SOLARIS )
    /* input argument is NUll */
    while(formatEx1s[i] != NULL)
    {
        char stdstr[64] = {0};
        char secstr[64] = {0};
        int isdiff = 0;
        memset(stdstr, 1, sizeof(stdstr));
        memset(secstr, 1, sizeof(secstr));
        /* print out standard c function result */
        ret1 = sprintf(stdstr, formatEx1s[i], sampleEx1);
        /* print out secure c function result */
        ret2 = sprintf_s(secstr, sizeof(secstr), formatEx1s[i], sampleEx1);
        /* compare the results */
        isdiff = (memcmp(stdstr, secstr, 32) || (ret1 != ret2));
        makeoutputdataprintf(fStd, fSec, formatEx1s[i], sampleEx1, "normal", ret1, ret2, isdiff, 
            stdstr, sizeof(stdstr), secstr, sizeof(secstr), __LINE__);
        i++;
    }
#endif

    i=0;
    while(NULL != formats[i])
    {
        char stdstr[64] = {0};
        char secstr[64] = {0};
        int diff;
        int smpmax;

        diff = 1;
        smpmax=sizeof(data)/sizeof(data[0]);
        k = 0;

        while(k < smpmax)
        {
            /*issame = 1;*/
            /* c standard function */
            memset(stdstr, 0, sizeof(stdstr));
            ret1 = sprintf(stdstr,formats[i],data[k]);
            /* c secure function */
            memset(secstr, 0, sizeof(secstr));
            ret2 = sprintf_s(secstr,64,formats[i],data[k]);

            fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], samples[k][1]);
            fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], samples[k][1]);

            /*compare the results*/
            if(ret1 != ret2)
                diff = 0;
            else if( strcmp(stdstr,secstr) != 0)
                diff = 0;
            else
                diff = 1;

#if TXT_DOCUMENT_PRINT
            if( 0 == diff)
            {
                fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
                fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
            }
            else
            {
                fprintf(fStd,"comparedResult:Equal\n");
                fprintf(fSec,"comparedResult:Equal\n");
            }

            /*print out standard c function result*/
            fprintf(fStd,"input value: %s\n", samples[k][0]);
            fprintf(fStd,"return value: %d\n", ret1);
            fprintf(fStd,"output value: %s\n",stdstr);
            fprintf(fStd,"\n");

            /*print out secure c function result*/
            fprintf(fSec,"input value: %s\n", samples[k][0]);
            fprintf(fSec,"return value: %d\n", ret2);
            fprintf(fSec,"output value: %s\n",secstr);
            fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
            if(!(diff))
            {
               SPRINTF(formats[i],samples[k][0],samples[k][1],ret1,ret2,stdstr,secstr,(long unsigned)__LINE__);
            }
#endif
            k++;
        }
#if OVERFLOW_MARK
#ifdef SECUREC_ON_64BITS
        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],-0xffffffffffffffff);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],-0xffffffffffffffff);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ",formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");


        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "-0xffffffffffffffff");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");


        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "-0xffffffffffffffff");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"-0xffffffffffffffff","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],0xfffffffffffffffff);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],0xfffffffffffffffff);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ",formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "0xfffffffffffffffff");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "0xfffffffffffffffff");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"0xfffffffffffffffff","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],-0xfffffffffffffffff);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],-0xfffffffffffffffff);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ",formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "-0xfffffffffffffffff");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "-0xfffffffffffffffff");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
           SPRINTF(formats[i],"-0xfffffffffffffffff","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],-0x10000000000000000);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],-0x10000000000000000);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ",formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ",formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "-0x10000000000000000");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");


        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "-0x10000000000000000");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"-0x10000000000000000","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],0x10000000000000000);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],0x10000000000000000);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "0x10000000000000000");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "0x10000000000000000");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"0x10000000000000000","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],0x10000000000000001);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],0x10000000000000001);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "0x10000000000000001");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "0x10000000000000001");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
           SPRINTF(formats[i],"0x10000000000000001","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],0x10000000000000010);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],0x10000000000000010);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "0x10000000000000010");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "0x10000000000000010");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"0x10000000000000010","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif
        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],-0x10000000000000001);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],-0x10000000000000001);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "-0x10000000000000001");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "-0x10000000000000001");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"-0x10000000000000001","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],-0x10000000000000010);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],-0x10000000000000010);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "-0x10000000000000010");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "-0x10000000000000010");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
           SPRINTF(formats[i],"-0x10000000000000010","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],0x1ffffffffffffffff);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],0x1ffffffffffffffff);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "0x1ffffffffffffffff");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "0x1ffffffffffffffff");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");    
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"0x1ffffffffffffffff","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],-0x1ffffffffffffffff);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],-0x1ffffffffffffffff);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "-0x1ffffffffffffffff");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "-0x1ffffffffffffffff");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"-0x1ffffffffffffffff","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif
#else

        /*1.-0xffffffff*/
        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],-0xffffffff);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],-0xffffffff);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "-0xffffffff");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "-0xffffffff");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"-0xffffffff","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /*2.-0xfffffffff*/
        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],-0xfffffffff);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],-0xfffffffff);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "-0xfffffffff");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");


        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "-0xfffffffff");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"-0xfffffffff","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /*3.0xfffffffff*/    
        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],0xfffffffff);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],0xfffffffff);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "0xfffffffff");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "0xfffffffff");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");  
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"0xfffffffff","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /*4.-0x100000000*/    
        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],-0x100000000);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],-0x100000000);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "-0x100000000");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "-0x100000000");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i], "-0x100000000","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /*5.0x100000000*/
        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],0x100000000);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],0x100000000);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "0x100000000");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "0x100000000");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"0x100000000","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /*6.0x100000001*/
        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],0x100000001);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],0x100000001);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ",formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "0x100000001");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "0x100000001");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"0x100000001","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /*7.0x100000010*/
        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],0x100000010);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],0x100000010);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ",formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "0x100000010");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "0x100000010");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"0x100000010","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /*8.-0x100000001*/
        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],-0x100000001);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],-0x100000001);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ",formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "-0x100000001");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "-0x100000001");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"-0x100000001","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /*9.-0x100000010*/    
        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],-0x100000010);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],-0x100000010);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ",formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "-0x100000010");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "-0x100000010");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"-0x100000010","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /*0x1ffffffff*/
        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],0x1ffffffff);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],0x1ffffffff);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ",formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "0x1ffffffff");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "0x1ffffffff");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");    
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"0x1ffffffff","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif

        /* c standard function */
        memset(stdstr, 0, sizeof(stdstr));
        ret1 = sprintf(stdstr,formats[i],-0x1ffffffff);
        /* c secure function */
        memset(secstr, 0, sizeof(secstr));
        ret2 = sprintf_s(secstr,64,formats[i],-0x1ffffffff);

        fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], "overflow(unsigned long long int)");
        fprintf(fSec,"Expression:sprintf-(%s)-%s ",formats[i], "overflow(unsigned long long int)");

        /*compare the results*/
        if(ret1 != ret2)
            diff = 0;
        else if( strcmp(stdstr,secstr) != 0)
            diff = 0;
        else
            diff = 1;

#if TXT_DOCUMENT_PRINT
        if( 0 == diff)
        {
            fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
            fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
        }
        else
        {
            fprintf(fStd,"comparedResult:Equal\n");
            fprintf(fSec,"comparedResult:Equal\n");
        }

        /*print out standard c function result*/
        fprintf(fStd,"input value: %s\n", "-0x1ffffffff");
        fprintf(fStd,"return value: %d\n", ret1);
        fprintf(fStd,"output value: %s\n",stdstr);
        fprintf(fStd,"\n");

        /*print out secure c function result*/
        fprintf(fSec,"input value: %s\n", "-0x1ffffffff");
        fprintf(fSec,"return value: %d\n", ret2);
        fprintf(fSec,"output value: %s\n",secstr);
        fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
        if(!(diff))
        {
            SPRINTF(formats[i],"-0x1ffffffff","overflow(unsigned long long int)",ret1,ret2,stdstr,secstr,__LINE__);
        }
#endif
#endif
#endif
        i++;
    }
    fprintf(fStd, "-------------------------------p test end--------------------------- \n");
    fprintf(fSec, "-------------------------------p test end--------------------------- \n");
}

void test_printf_format_p_2(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

    char *formats[] = {
        "%-10p",
        "% 10p",
        NULL
    };

    char *sample[] = 
    {
        "test1",
        NULL
    };

    char *flag[][2] = 
    {
        {"test1",       "normal"  },
    };

    int isdiff=0;
    int retc, rets;
    char stdbuf[256];
    char secbuf[256];
    int k=0;
    int m=0;

    fprintf(fstd, "-------------------------------p test 2 begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------p test 2 begin--------------------------- \n"); /*lint !e668*/

    k = 0;
    while(formats[k] != NULL)
    {
        m = 0;
        while(sample[m] != NULL)
        {
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, formats[k], sample[m]);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), formats[k], sample[m]);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, formats[k], flag[m][0], flag[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }

        k++;
    }

#endif

    fprintf(fstd, "-------------------------------p test 2 end--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------p test 2 end--------------------------- \n"); /*lint !e668*/

}

/* % */
void test_printf_format_percent(FILE* fStd,FILE* fSec)
{
    char *formats[] = 
    {
        "%%",
        /*"%'",*/
        /*"%\'",*/
#if UNSUPPORT_TEST
        "%0%",
        "%2%",
#endif
        NULL
    };
    char *samples[][2] = 
    {
        {"%%",      "normal"},
        {"%%%%",     "edge"}, 
#if OVERFLOW_MARK
        {"%",   "overflow"},
        {"2%",     "overflow"},
        {"b%",     "overflow"},
#endif
        {NULL, NULL}
    };

    int i = 0; /*counter for different formats*/
    int k; /*counter for different data*/
    int ret1 = 0;
    int ret2 = 0;

    fprintf(fStd, "-------------------------------percent test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------percent test begin--------------------------- \n"); /*lint !e668*/

    while(NULL != formats[i])
    {
        char stdstr[64] = {0};
        char secstr[64] = {0};
        int diff = 1;
        k = 0;
        while(NULL != samples[k][0])
        {

            /*print out standard c function result*/
            memset(stdstr, 0, sizeof(stdstr));
            ret1 = sprintf(stdstr,formats[i],samples[k][0]);

            /*print out secure c function result*/
            memset(secstr, 0, sizeof(secstr));
            ret2 = sprintf_s(secstr,64,formats[i],samples[k][0]);

            fprintf(fStd,"Expression:sprintf-(%s)-%s ", formats[i], samples[k][1]);
            fprintf(fSec,"Expression:sprintf-(%s)-%s ", formats[i], samples[k][1]);

            /*compare the results*/
            if(ret1 != ret2)
                diff = 0;
            else if( strcmp(stdstr,secstr) != 0)
                diff = 0;
            else
                diff = 1;

#if TXT_DOCUMENT_PRINT
            if( 0 == diff)
            {
                fprintf(fStd,"comparedResult:Different(%d)\n",__LINE__);
                fprintf(fSec,"comparedResult:Different(%d)\n",__LINE__);
            }
            else
            {
                fprintf(fStd,"comparedResult:Equal\n");
                fprintf(fSec,"comparedResult:Equal\n");
            }

            /*print out standard c function result*/
            fprintf(fStd,"input value: %s\n", samples[k][0]);
            fprintf(fStd,"return value: %d\n", ret1);
            fprintf(fStd,"output value: %s\n",stdstr);
            fprintf(fStd,"\n");

            /*print out secure c function result*/
            fprintf(fSec,"input value: %s\n", samples[k][0]);
            fprintf(fSec,"return value: %d\n", ret2);
            fprintf(fSec,"output value: %s\n",secstr);
            fprintf(fSec,"\n");
#endif
#if SCREEN_PRINT
            if(!(diff))
            {
                SPRINTF(formats[i],samples[k][0],samples[k][1],ret1,ret2,stdstr,secstr,(long unsigned)__LINE__);
            }
#endif
            k++;
        }
        i++;
    }
    fprintf(fStd, "-------------------------------percent test end--------------------------- \n");
    fprintf(fSec, "-------------------------------percent test end--------------------------- \n");
}
/* [] */
/*void test_printf_format_regular(FILE* fStd,FILE* fSec)
{

}
*/
#if !(defined(SECUREC_VXWORKS_PLATFORM))
void test_swprintf_format_p(FILE *fstd, FILE *fsec)
{
#if !defined(__SOLARIS )    
    wchar_t *formatEx1s[] = {
        L"%p",
        L"%.4p",
        NULL
    };
    wchar_t *sampleEx1 = NULL;

    int m = 0;
    int isdiff = 0;
    wchar_t stdbuf[32];
    wchar_t secbuf[32];
    char fmt[32];
    char smp[32];
    int i, len;
    int retc;
    int rets;

    fprintf(fstd, "-------------------------------swprintf p test start--------------------------- \n");
    fprintf(fsec, "-------------------------------swprintf p  test start--------------------------- \n");
    /* NULL */
    m = 0;
    while(formatEx1s[m] != NULL)
    {
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
#if (defined(_MSC_VER) && (_MSC_VER == 1200))
        /* print out standard c function result */
        retc = swprintf(stdbuf, formatEx1s[m], sampleEx1);
#else
        retc = swprintf(stdbuf, sizeof(stdbuf), formatEx1s[m], sampleEx1);
#endif

        /* print out secure c function result */
        rets = swprintf_s(secbuf, sizeof(secbuf), formatEx1s[m], sampleEx1);

        /* compare the results */
        isdiff = (memcmp(stdbuf, secbuf, 32) || (retc != rets));

        len = wcslen(stdbuf);
        for(i=0;i<len;++i)
        {
            *((char*)stdbuf + i) = (char)(stdbuf[i]) ;
        }
        *((char*)stdbuf + i) = (char)0;

        len = wcslen(secbuf);
        for(i=0;i<len;++i)
        {
            *((char*)secbuf + i) = (char)(secbuf[i]) ;
        }
        *((char*)secbuf + i) = (char)0;

        len = wcslen(formatEx1s[m]);
        for(i=0;i<len;++i)
        {
            *((char*)fmt + i) = (char)(formatEx1s[m][i]) ;
        }
        *((char*)fmt + i) = (char)0;

        if (sampleEx1 == NULL)
        {
            strcpy(smp,"NULL");
        }
        else
        {
            len = wcslen(sampleEx1);
            for(i=0;i<len;++i)
            {
                *((char*)smp + i) = (char)(sampleEx1[i]) ;
            }
            *((char*)smp + i) = (char)0;
        }

        OutputTestResult("swprintf_s",fstd, fsec, fmt, smp, "normal", retc, rets, isdiff, 
            (char*)stdbuf, sizeof(stdbuf), (char*)secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#endif    

    fprintf(fstd, "-------------------------------swprintf p test end--------------------------- \n");
    fprintf(fsec, "-------------------------------swprintf_s p  test end--------------------------- \n");
}
#endif
