
#include "securec.h"
#include "testutil.h"
#include "comp_funcs.h"
#include <string.h>

#define EPSINON 0.00001

#if defined(COMPATIBLE_LINUX_FORMAT)
#define IS_TEST_LINUX 1
#else
#undef IS_TEST_LINUX
#endif

void test_sscanf_format_c(FILE* fStd, FILE* fSec)
{
    char *formats[] = {
        "%c",
#if UNSUPPORT_TEST ||  !(defined(SECUREC_VXWORKS_PLATFORM))
        "%lc",
#endif
#if UNSUPPORT_TEST ||  !(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux)))
        "%hc",
#endif
        NULL
    };
    char *samples[][2] = {
        {"123",             "normal"},
        {"hello",           "edge"  },
        {"abcdefghijkl",    "overflow"},
        {NULL, NULL}
    };

    char *kuanformats[] = {
        "%0c",   
        "%1c",   
        "%3c",   
        NULL
    };

    char stdstr[32] = {0};
    char secstr[32] = {0};
    int i; 
    int k; 
    int j; 
    int sysret = 0, secret = 0;
    int issame = 0;

    fprintf(fStd, "-------------------------------c test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------c test begin--------------------------- \n"); /*lint !e668*/

    k = 0;
    while(NULL != samples[k][0])
    {
        i=0;
        while(NULL != formats[i])
        {
#if !UNSUPPORT_TEST && defined(SECUREC_VXWORKS_PLATFORM) && defined(RUNTIME_VERSION)
           if(0== strcmp(formats[i],"%hc") && 0 == strcmp("5.5.1",RUNTIME_VERSION))
           {
                ++i;
                continue;
           }
#endif
            issame = 1;
            memset(stdstr, 1, sizeof(stdstr));
            sysret = sscanf(samples[k][0], formats[i], stdstr);

            memset(secstr, 1, sizeof(secstr));
            secret = sscanf_s(samples[k][0], formats[i], secstr, sizeof(secstr));

            for(j = 0; j < 32; j++)
            {
                if(stdstr[j] != secstr[j])
                {
                    issame = 0;
                    break;
                }
            }
#if TXT_DOCUMENT_PRINT
            if(issame && (sysret == secret))
            {
                fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Equal\n", formats[i]);
                fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Equal\n", formats[i]);
            }
            else
            {
                fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Different\n", formats[i]);
                fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Different (%d)\n", formats[i], __LINE__);
            }
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n",  samples[k][0], sysret, stdstr[0], stdstr[1], stdstr[2], stdstr[3], stdstr[4], stdstr[5]);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n",  samples[k][0], secret, secstr[0], secstr[1], secstr[2], stdstr[3], stdstr[4], stdstr[5]);
#endif
#if SCREEN_PRINT
            if(!(issame && (sysret == secret))) 
               SSCANF(formats[i],samples[k][0],"normal",sysret,secret,stdstr,"%s",secstr,"%s",(long unsigned)__LINE__);
#endif
            i++;

        }
        k++;
    }

    i=0;
    while(NULL != kuanformats[i])
    {
        issame = 1;
        memset(stdstr, 1, sizeof(stdstr));
        sysret = sscanf("123", kuanformats[i], stdstr);

        memset(secstr, 1, sizeof(secstr));
        secret = sscanf_s("123", kuanformats[i], secstr, sizeof(secstr));

        for(j = 0; j < 32; j++)
        {
            if(stdstr[j] != secstr[j])
            {
                issame = 0;
                break;
            }
        }

#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Equal\n", kuanformats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Equal\n", kuanformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Different\n", kuanformats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Different (%d)\n", kuanformats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n", sysret, stdstr[0], stdstr[1], stdstr[2], stdstr[3], stdstr[4], stdstr[5]);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n", secret, secstr[0], secstr[1], secstr[2], stdstr[3], stdstr[4], stdstr[5]);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF(kuanformats[i],"123","normal",sysret,secret,stdstr,"%s",secstr,"%s",(long unsigned)__LINE__);
#endif
        i++;
    }

    fprintf(fStd, "-------------------------------c test end--------------------------- \n");
    fprintf(fSec, "-------------------------------c test end--------------------------- \n");

}   

void test_sscanf_format_C(FILE* fStd, FILE* fSec)
{
    char *formats[] = {
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM))
        "%C",
        "%lC",
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS))) ||defined(SECUREC_VXWORKS_PLATFORM))
        "%hC",
#endif
        NULL
    };
    char *samples[][2] = {
        {"123",             "normal"},
        {"hello",           "edge"  },
        {"abcdefghijkl",    "overflow"},
        {NULL, NULL}
    };

    char *kuanformats[] = {
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM))
        "%0C",   
        "%1C",   
        "%3C",   
#endif
        NULL
    };

    char stdstr[32] = {0};
    char secstr[32] = {0};
    int i; 
    int k; 
    int j; 
    int sysret = 0, secret = 0;
    int issame = 0;

    fprintf(fStd, "-------------------------------C test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------C test begin--------------------------- \n"); /*lint !e668*/

    k = 0;
    while(NULL != samples[k][0])
    {
        i=0;
        while(NULL != formats[i])
        {
            issame = 1;
            memset(stdstr, 1, sizeof(stdstr));
            sysret = sscanf(samples[k][0], formats[i], stdstr);

            memset(secstr, 1, sizeof(secstr));
            secret = sscanf_s(samples[k][0], formats[i], secstr, sizeof(secstr));

            for(j = 0; j < 32; j++)
            {
                if(stdstr[j] != secstr[j])
                {
                    issame = 0;
                    break;
                }
            }

#if TXT_DOCUMENT_PRINT
            if(issame && (sysret == secret))
            {
                fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Equal\n", formats[i]);
                fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Equal\n", formats[i]);
            }
            else
            {
                fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Different\n", formats[i]);
                fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Different (%d)\n", formats[i], __LINE__);
            }
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n",  samples[k][0], sysret, stdstr[0], stdstr[1], stdstr[2], stdstr[3], stdstr[4], stdstr[5]);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n",  samples[k][0], secret, secstr[0], secstr[1], secstr[2], stdstr[3], stdstr[4], stdstr[5]);
#endif
#if SCREEN_PRINT
            if(!(issame && (sysret == secret))) 
                SSCANF(formats[i],samples[k][0],"normal",sysret,secret,stdstr,"%s",secstr,"%s",(long unsigned)__LINE__);
#endif
            i++;

        }
        k++;
    }

    i=0;
    while(NULL != kuanformats[i])
    {
        issame = 1;
        memset(stdstr, 1, sizeof(stdstr));
        sysret = sscanf("123", kuanformats[i], stdstr);

        memset(secstr, 1, sizeof(secstr));
        secret = sscanf_s("123", kuanformats[i], secstr, sizeof(secstr));

        for(j = 0; j < 32; j++)
        {
            if(stdstr[j] != secstr[j])
            {
                issame = 0;
                break;
            }
        }

#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Equal\n", kuanformats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Equal\n", kuanformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Different\n", kuanformats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Different (%d)\n", kuanformats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n", sysret, stdstr[0], stdstr[1], stdstr[2], stdstr[3], stdstr[4], stdstr[5]);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n", secret, secstr[0], secstr[1], secstr[2], stdstr[3], stdstr[4], stdstr[5]);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF(kuanformats[i],"123","normal",sysret,secret,stdstr,"%s",secstr,"%s",(long unsigned)__LINE__);
#endif
        i++;
    }

    fprintf(fStd, "-------------------------------C test end--------------------------- \n");
    fprintf(fSec, "-------------------------------C test end--------------------------- \n");

}


/*#if(defined(COMPATIBLE_LINUX_FORMAT))*/
#if (defined(COMPATIBLE_TESTCASE_LINUX_MANUAL))

void test_sscanf_format_c_add(FILE* fStd, FILE* fSec)
{
    char *formats[] = {
        "%*c",
        "   %c",
        NULL
    };

    char *samples[][2] = {
        {"123",             "normal"},
        {"hello",           "edge"  },
        {"abcdefghijkl",    "overflow"},
        {NULL, NULL}
    };
    
    char *samples_interval[][2] = {
        {"1,1",             "normal"},
        {"hello,hello",           "edge"  },
        {"abcdefghijkl,abcdefghijkl",    "overflow"},
        {NULL, NULL}
    };    

    char stdstr[32] = {0};
    char secstr[32] = {0};
    char tmpstr[32] = {0};
    int i; 
    int k; 
    int j; 
    int sysret = 0, secret = 0;
    int issame = 0;

    
    fprintf(fStd, "-------------------------------c test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------c test begin--------------------------- \n"); /*lint !e668*/

    k = 0;
    while(NULL != samples[k][0])
    {
        i=0;
        while(NULL != formats[i])
        {
            issame = 1;
            memset(stdstr, 1, sizeof(stdstr));
            sysret = sscanf(samples[k][0], formats[i], stdstr);

            memset(secstr, 1, sizeof(secstr));
            secret = sscanf_s(samples[k][0], formats[i], secstr, sizeof(secstr));

            for(j = 0; j < 32; j++)
            {
                if(stdstr[j] != secstr[j])
                {
                    issame = 0;
                    break;
                }
            }
#if TXT_DOCUMENT_PRINT
            if(issame && (sysret == secret))
            {
                fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Equal\n", formats[i]);
                fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Equal\n", formats[i]);
            }
            else
            {
                fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Different\n", formats[i]);
                fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Different (%d)\n", formats[i], __LINE__);
            }
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n",  samples[k][0], sysret, stdstr[0], stdstr[1], stdstr[2], stdstr[3], stdstr[4], stdstr[5]);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n",  samples[k][0], secret, secstr[0], secstr[1], secstr[2], stdstr[3], stdstr[4], stdstr[5]);
#endif
#if SCREEN_PRINT
            if(!(issame && (sysret == secret))) 
               SSCANF(formats[i],samples[k][0],"normal",sysret,secret,stdstr,"%s",secstr,"%s",(long unsigned)__LINE__);
#endif
            i++;

        }
        k++;
    } 
 
    /* %c,%c */   
    k = 0;
    while(NULL != samples_interval[k][0])
    {
        issame = 1;
        memset(stdstr, 1, sizeof(stdstr));
        sysret = sscanf(samples_interval[k][0], "%c,%c", tmpstr, stdstr);

        memset(secstr, 1, sizeof(secstr));
        secret = sscanf_s(samples_interval[k][0], "%c,%c", tmpstr, sizeof(tmpstr),secstr, sizeof(secstr));

        for(j = 0; j < 32; j++)
        {
            if(stdstr[j] != secstr[j])
            {
                issame = 0;
                break;
            }
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Equal\n", "%c,%c");
            fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Equal\n", "%c,%c");
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Different\n", "%c,%c");
            fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Different (%d)\n", "%c,%c", __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n",  samples_interval[k][0], sysret, stdstr[0], stdstr[1], stdstr[2], stdstr[3], stdstr[4], stdstr[5]);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n",  samples_interval[k][0], secret, secstr[0], secstr[1], secstr[2], stdstr[3], stdstr[4], stdstr[5]);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
           SSCANF("%c,%c",samples_interval[k][0],"normal",sysret,secret,stdstr,"%s",secstr,"%s",(long unsigned)__LINE__);
#endif
    k++;
    }      
    
    /* %2$c   
    k = 0;
    while(NULL != samples_interval[k][0])
    {
        issame = 1;
        memset(stdstr, 1, sizeof(stdstr));
        sysret = sscanf(samples_interval[k][0], "%2$c", tmpstr, stdstr);

        memset(secstr, 1, sizeof(secstr));
        secret = sscanf_s(samples_interval[k][0], "%2$c", tmpstr, secstr, sizeof(secstr));

        for(j = 0; j < 32; j++)
        {
            if(stdstr[j] != secstr[j])
            {
                issame = 0;
                break;
            }
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Equal\n", "%2$c");
            fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Equal\n", "%2$c");
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)- comparedResult:Different\n", "%2$c");
            fprintf(fSec, "Expression:sscanf-(%s)- comparedResult:Different (%d)\n", "%2$c", __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n",  samples_interval[k][0], sysret, stdstr[0], stdstr[1], stdstr[2], stdstr[3], stdstr[4], stdstr[5]);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value: %c %c %c %c %c %c\n\n",  samples_interval[k][0], secret, secstr[0], secstr[1], secstr[2], stdstr[3], stdstr[4], stdstr[5]);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
           SSCANF("%2$c",samples_interval[k][0],"normal",sysret,secret,stdstr,"%s",secstr,"%s",__LINE__);
#endif
    k++;
    }  
    */  
}

#endif
