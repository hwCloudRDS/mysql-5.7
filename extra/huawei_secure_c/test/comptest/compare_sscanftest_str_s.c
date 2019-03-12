
#include "securec.h"
#include "testutil.h"
#include "comp_funcs.h"
#include <string.h>
#if !(defined(SECUREC_VXWORKS_PLATFORM))
#include <wchar.h>
#endif

void makeoutputdata(FILE *fstd, 
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
    unsigned long line)
{
#if TXT_DOCUMENT_PRINT
    int j = 0;
    /* print out the compare result to stdard function result file */
    fprintf(fstd, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(isdifferent)
        fprintf(fstd, "comparedResult:Different\n");
    else
        fprintf(fstd, "comparedResult:Equal\n");
    fprintf(fstd, "input  value : %s\n", sample);
    fprintf(fstd, "return value : %-2d\n", stdresult);
    fprintf(fstd, "output buffer:");
    for(j = 0; j < stdlen; j++)
        fprintf(fstd, " %02x", stdbuffer[j]);
    fprintf(fstd, "\n\n");
    
    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(isdifferent)
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output buffer:");
    for(j = 0; j < seclen; j++)
        fprintf(fsec, " %02x", secbuffer[j]);
    fprintf(fsec, "\n\n");
#endif
#if SCREEN_PRINT
    if(isdifferent) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdbuffer,"%s",secbuffer,"%s",line);
#endif
}

void test_sscanf_format_s(FILE *fstd, FILE *fsec)
{
    char *formats[] = {
        "%-s",
        "%s",
        "%0s",
        "%4s",
        "%5s",
        "%6s",
        "%7s",
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))))
        "%hs",
#endif
#if UNSUPPORT_TEST ||  !(defined(SECUREC_VXWORKS_PLATFORM))
        "%ls",
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM))
        "%S",
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS))) ||defined(SECUREC_VXWORKS_PLATFORM))
        "%hS",
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM))
        "%lS",
#endif
        NULL
    };
    char *samples[][2] = {
        {"world",           "normal"  },
        {" world",           "normal"  },
        {"",                "edge"  },
         {" ",                "white space"  },
         {"\r",                "white \\r"  },
         {"\v",                "white \\v"  },
         {"\f",                "white \\f"  },
          {"\n",                "white \\n"  },
          {"\t",                "white \\t"  },
          {"\t \r\n",                "white \\t \\r \\n"  },
          {"  \r\n",                "white   \\r \\n"  },
        {NULL, NULL}
    };

    char stdstr[32] = {0};
    char secstr[32] = {0};
    int i; /*counter for different formats*/
    int k; /*counter for different samples*/
    int isdiff = 0;
    int retc = 0;
    int rets = 0;

    k = 0;
    i=0;
    while(NULL != formats[i])
    {
#if !UNSUPPORT_TEST && defined(SECUREC_VXWORKS_PLATFORM) && defined(RUNTIME_VERSION)
           if(0== strcmp(formats[i],"%hs") && 0 == strcmp("5.5.1",RUNTIME_VERSION))
           {
                ++i;
                continue;
           }
#endif
        isdiff = 0;
        /* print out standard c function result */
        memset(stdstr, 1, sizeof(stdstr));
        retc = sscanf(samples[k][0], formats[i], stdstr);
        /* print out secure c function result */
        memset(secstr, 1, sizeof(secstr));
        rets = sscanf_s(samples[k][0], formats[i], secstr, sizeof(secstr));
        
        /* compare the results */
        isdiff = (memcmp(stdstr, secstr, 32) || (retc != rets));
        makeoutputdata(fstd, fsec, formats[i], samples[k][0], samples[k][1], retc, rets, isdiff, stdstr, 32, secstr, 32, __LINE__);
        i++;
    }
    k++;
    do
    {
        isdiff = 0;
        /* print out standard c function result */
        memset(stdstr, 1, sizeof(stdstr));
        retc = sscanf(samples[k][0], formats[1], stdstr);
        /* print out secure c function result */
        memset(secstr, 1, sizeof(secstr));
        rets = sscanf_s(samples[k][0], formats[1], secstr, sizeof(secstr));
        
        /* compare the results */
        isdiff = (memcmp(stdstr, secstr, 32) || (retc != rets));
        makeoutputdata(fstd, fsec, formats[1], samples[k][0], samples[k][1], retc, rets, isdiff, stdstr, 32, secstr, 32, __LINE__);
        i++;
    }while(NULL != samples[++k][0]);

}

#if !(defined(SECUREC_VXWORKS_PLATFORM))
void test_swscanf_format_s(FILE *fstd, FILE *fsec)
{

    wchar_t *formatsw[] = { 
        L"%s",
        L"%3s",
        L"%10s",
        L"%010s",
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))))
        L"%hs",
#endif
#if UNSUPPORT_TEST ||  !(defined(SECUREC_VXWORKS_PLATFORM))
        L"%ls",
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM))
        L"%S",
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS))) ||defined(SECUREC_VXWORKS_PLATFORM))
        L"%hS",
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM))
        L"%lS",
#endif
        NULL
    };

    wchar_t samplew[] = L"w_hello";
    char fmt[32];
    char smp[32];
    int m = 0,i=0;
    int len = 0;
    int isdiff = 0;
    char stdstr[64];
    char secstr[64];
    int retc;
    int rets;
    
    while(formatsw[m] != NULL)
    {
        isdiff = 0;
        memset(stdstr, 0, sizeof(stdstr));
        memset(secstr, 0, sizeof(secstr));

        retc = swscanf(samplew, formatsw[m], stdstr);
        rets = swscanf_s(samplew, formatsw[m], secstr, sizeof(secstr)/sizeof(wchar_t));
        
        /* compare the results */
        isdiff = (memcmp(stdstr, secstr, 64) || (retc != rets));

        len = wcslen(formatsw[m]);
        for(i=0;i<len;++i)
        {
            *((char*)fmt + i) = (char)(formatsw[m][i]) ;
        }
        *((char*)fmt + i) = (char)0;

        len = wcslen(samplew);
        for(i=0;i<len;++i)
        {
            *((char*)smp + i) = (char)(samplew[i]) ;
        }
        *((char*)smp + i) = (char)0;

        makeoutputdata(fstd, fsec,  fmt, smp, smp, retc, rets, isdiff, stdstr, 64, secstr, 64, __LINE__);
        m++;
    }


}
#endif

void test_sscanf_format_regular(FILE *fstd, FILE *fsec)
{
    char *formats[] = {
        "%[0-9]",
        "%[^A-Z]",
        "%[^A-Z-]",
        "%[a-z]",
        "%[a|b]c",
        "%[]a-z0-9_-.]",
        "%{a-z0-9-]",
        "%[a-z0-9_-.",
        "%[^]]",
        NULL
    };
    char *samples[][2] = {
        {"123abc-ABC",             "normal"},
        {"hello-ac-xyz",           "normal"  },
        {"",                       "edge"  },
        {"bc",                     "edge"  },
        {"xaz",                    "edge"  },
        {"xz",                     "edge"  },
        {"a||c",                   "edge"  },
        {"abc]123",                "edge"  },
        {"abc-123",                "edge"  },
        {NULL, NULL}
    };

    char stdstr[32] = {0};
    char secstr[32] = {0};
    int i; /*counter for different formats*/
    int k; /*counter for different samples*/
    int retc = 0;
    int rets = 0;
    int isdiff = 0;

    k = 0;
    while(NULL != samples[k][0])
    {
        i=0;
        while(NULL != formats[i])
        {
            isdiff = 1;
            /*print out standard c function result*/
            memset(stdstr, 1, sizeof(stdstr));
            retc = sscanf(samples[k][0], formats[i], stdstr);
            
            /*print out secure c function result*/
            memset(secstr, 1, sizeof(secstr));
            rets = sscanf_s(samples[k][0], formats[i], secstr, sizeof(secstr));
            
            /* compare the results */
            isdiff = (memcmp(stdstr, secstr, 32) || (retc != rets));
            makeoutputdata(fstd, fsec, formats[i], samples[k][0], samples[k][1], retc, rets, isdiff, stdstr, 32, secstr, 32, __LINE__);
            i++;
        }
        k++;
    }
}

/*#if(defined(COMPATIBLE_LINUX_FORMAT))*/
#if (defined(COMPATIBLE_TESTCASE_LINUX_MANUAL))

/**                                                                           
 *@test test_sscanf_format_regular_add                                     
 *- @ sscanf_s                                          
 *- @对比测试sscanf函数格式串正则表达式,主要补充测试:*,white-space,    非white-space,a,$场景
 *- @tbrief                                           
 *  -#                                                                    
 *  -#                                                                    
 *  -#                                                                    
 *- @texpect拷贝成功  
 *- @tprior 2                                                                 
 *- @tremark                                                                
 */
void test_sscanf_format_regular_add(FILE *fstd, FILE *fsec)
{
    char *formats[] = {
        "%*[0-9]",
        "%*[^A-Z]",
        /*"%a[^A-Z-]",
        "%a[a-z]",
        "%a[a|b]c", 不支持a*/
        "   %[]a-z0-9_-.]",
        /*"%1$a[a-z]",*/
        /*"%1$a[a|b]c",*/
        NULL
    };
    char *samples[][2] = {
        {"123abc-ABC",             "normal"},
        {"hello-ac-xyz",           "normal"  },
        {"",                       "edge"  },
        {"bc",                     "edge"  },
        {"xaz",                    "edge"  },
        {"xz",                     "edge"  },
        {"a||c",                   "edge"  },
        {"abc]123",                "edge"  },
        {"abc-123",                "edge"  },
        {NULL, NULL}
    };

    char stdstr[32] = {0};
    char secstr[32] = {0};
    int i; /*counter for different formats*/
    int k; /*counter for different samples*/
    int retc = 0;
    int rets = 0;
    int isdiff = 0;

    k = 0;
    while(NULL != samples[k][0])
    {
        i=0;
        while(NULL != formats[i])
        {
            isdiff = 1;
            /*print out standard c function result*/
            memset(stdstr, 1, sizeof(stdstr));
            retc = sscanf(samples[k][0], formats[i], stdstr);
            
            /*print out secure c function result*/
            memset(secstr, 1, sizeof(secstr));
            rets = sscanf_s(samples[k][0], formats[i], secstr, sizeof(secstr));
            
            /* compare the results */
            isdiff = (memcmp(stdstr, secstr, 32) || (retc != rets));
            makeoutputdata(fstd, fsec, formats[i], samples[k][0], samples[k][1], retc, rets, isdiff, stdstr, 32, secstr, 32, __LINE__);
            i++;
        }
        k++;
    }
}

void test_sscanf_format_s_add(FILE *fstd, FILE *fsec)
{
    char *formats[] = {
        "%*s",
        "   %s",
        /*"%as", -- 不支持*/
        NULL
    };
    char *samples[][2] = {
        {"world",           "normal"  },
        {" world",           "normal"  },
        {"",                "edge"  },
        {NULL, NULL}
    };

    char stdstr[32] = {0};
    char secstr[32] = {0};
   /*char tmpstr[32] = {0};*/  
    int i; /*counter for different formats*/
    int k; /*counter for different samples*/
    int isdiff = 0;
    int retc = 0;
    int rets = 0;

    k = 0;
    i=0;
    while(NULL != formats[i])
    {
        isdiff = 0;
        /* print out standard c function result */
        memset(stdstr, 1, sizeof(stdstr));
        retc = sscanf(samples[k][0], formats[i], stdstr);
        /* print out secure c function result */
        memset(secstr, 1, sizeof(secstr));
        rets = sscanf_s(samples[k][0], formats[i], secstr, sizeof(secstr));
        
        /* compare the results */
        isdiff = (memcmp(stdstr, secstr, 32) || (retc != rets));
        makeoutputdata(fstd, fsec, formats[i], samples[k][0], samples[k][1], retc, rets, isdiff, stdstr, 32, secstr, 32, __LINE__);
        i++;
    }
    k++;
    {
        isdiff = 0;
        /* print out standard c function result */
        memset(stdstr, 1, sizeof(stdstr));
        retc = sscanf(samples[k][0], formats[1], stdstr);
        /* print out secure c function result */
        memset(secstr, 1, sizeof(secstr));
        rets = sscanf_s(samples[k][0], formats[1], secstr, sizeof(secstr));
        
        /* compare the results */
        isdiff = (memcmp(stdstr, secstr, 32) || (retc != rets));
        makeoutputdata(fstd, fsec, formats[1], samples[k][0], samples[k][1], retc, rets, isdiff, stdstr, 32, secstr, 32, __LINE__);
        i++;
    }
    k++;
    {
        isdiff = 0;
        /* print out standard c function result */
        memset(stdstr, 1, sizeof(stdstr));
        retc = sscanf(samples[k][0], formats[1], stdstr);
        /* print out secure c function result */
        memset(secstr, 1, sizeof(secstr));
        rets = sscanf_s(samples[k][0], formats[1], secstr, sizeof(secstr));
        
        /* compare the results */
        isdiff = (memcmp(stdstr, secstr, 32) || (retc != rets));
        makeoutputdata(fstd, fsec, formats[1], samples[k][0], samples[k][1], retc, rets, isdiff, stdstr, 32, secstr, 32, __LINE__);
        i++;
    }

    /* %2$s  
    k = 0;
    while(NULL != samples[k][0])
    {
        isdiff = 0;
      
        memset(stdstr, 1, sizeof(stdstr));
        retc = sscanf(samples[k][0], "%2$s", tmpstr, stdstr);
        
        memset(secstr, 1, sizeof(secstr));
        rets = sscanf_s(samples[k][0], "%2$s", tmpstr, secstr, sizeof(secstr));
        
        
        isdiff = (memcmp(stdstr, secstr, 32) || (retc != rets));
        makeoutputdata(fstd, fsec, "%2$s", samples[k][0], samples[k][1], retc, rets, isdiff, stdstr, 32, secstr, 32, __LINE__);
        
        k++;
    }*/
    
}
#endif

