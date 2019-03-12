
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

#define SUPPORT_Q 1 /* when the platform support %qe/f/g, modify the value to 1 */

int Equal_f(float x,float y)
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
int Equal_l(double x,double y)
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
#ifndef VXWORKS_CAVIUM_5434
int Equal_ll(long double x,long double y)
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

void test_sscanf_format_a(FILE* fStd,FILE* fSec)
{
    float ostd = 0;
    float osec = 0;

    double diff = 0;

    int i = 0;
    int j = 0;
    int retStd = 0;
    int retSec = 0;
    int flag = 0; /* 0 means same, and 1 means different */

    char *format_a[] = 
    {
#if UNSUPPORT_TEST_A 
        "%a", "%0a", "%2a", "%8a", "%9a",
#endif
        NULL
    };

    char *samples_a[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"3.4e+38", "edge"},  
        {"-3.4e+38", "edge"},
#if OVERFLOW_MARK
        {"3.5e+38", "overflow"},
        {"-3.5e+38", "overflow"},
#endif
        {NULL, NULL}
    };

    /* %a test begin */
    printf("%s", "%a test begin\r\n");

    while(NULL != format_a[i]) /*lint !e661*/
    {
        j = 0;
        while(NULL != samples_a[j][0])
        {
            ostd = 0;
            osec = 0;
            diff = 0;
            retStd = 0;
            retSec = 0;
            flag = 0;

            /* std function */
            retStd = sscanf(samples_a[j][0], format_a[i], &ostd);

            /* sec function */
            retSec = sscanf_s(samples_a[j][0], format_a[i], &osec);

            /* compare result */
            diff = (osec - ostd);
            if((retSec == retStd) && ((diff >= - EPSINON) && (diff <= EPSINON)))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_a[i], samples_a[j][1]); /*lint !e668*/
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_a[i], samples_a[j][1]); /*lint !e668*/
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_a[i], samples_a[j][1]); /*lint !e668*/
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_a[i],samples_a[j][1], __LINE__); /*lint !e668*/
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%a\n\n", samples_a[j][0], retStd, ostd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%a\n\n", samples_a[j][0], retSec, osec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_a[i],samples_a[j][0],samples_a[j][1],retStd,retSec,ostd,"%a",osec,"%a",(long unsigned)__LINE__);
#endif
            j++;
        }

        i++;
    }

    printf("%s", "%a test end\r\n");

}

void test_sscanf_format_e(FILE* fStd,FILE* fSec)
{
    float ostd = 0;
    float osec = 0;

    double olstd = 0;
    double olsec = 0;

    long double ollstd = 0;
    long double ollsec = 0;

    int i = 0;
    int j = 0;
    int retStd = 0;
    int retSec = 0;
    int flag = 0; /* 0 means same, and 1 means different */

    char *format_e[] = 
    {
        "%e", "%0e", "%2e", "%8e", "%9e",
        NULL
    };
    char *format_lle[] = 
    {
#if !((defined(_MSC_VER) && 1200 !=_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
        "%lle",/* it's behavior is same to %e */
#endif
        NULL
    };

    char *samples_e[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"3.4e+38", "edge"},        
        {"-3.4e+38", "edge"},
#if OVERFLOW_MARK
        {"3.5e+38", "overflow(long double)"},
        {"-3.5e+38", "overflow(long double)"},
#endif
        {NULL, NULL}
    };
    
    char *format_le[] = 
    {
        "%le",
        NULL
    };

    char *samples_le[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"1.79e+308", "edge"},        
        {"-1.79e+308", "edge"},
#if OVERFLOW_MARK
        {"1.80e+308", "overflow(long double)"},
        {"-1.89e+308", "overflow(long double)"},
#endif
        {NULL, NULL}
    };
    
    char *format_Le[] = 
    {
#if !(defined(SECUREC_VXWORKS_PLATFORM))
        "%Le",
#endif
        NULL
    };

    char *format_qe[] =  /* the same to L, not in ANSI C */
    {
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
        "%qe",
#endif
        NULL
    };

    char *samples_Le[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"1.79e+308", "edge"},        
        {"-1.79e+308", "edge"},
#if OVERFLOW_MARK
        {"1.80e+308", "overflow(long double)"},
        {"-1.89e+308", "overflow(long double)"},
        {"1.79e+4899", "overflow(long double)"},
        {"1.79e+5000", "overflow(long double)"},
#endif
        {NULL, NULL}
    };

    /* %e test begin */
    printf("%s", "%e  test begin\r\n");
    fprintf(fStd, "-------------------------------e test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------e test begin--------------------------- \n"); /*lint !e668*/
    i = 0;
    while(NULL != format_e[i])
    {
        j = 0;
        while(NULL != samples_e[j][0])
        {
            ostd = 0;
            osec = 0;
            retStd = 0;
            retSec = 0;
            flag = 0;

            /* std function */
            retStd = sscanf(samples_e[j][0], format_e[i], &ostd);
            /* sec function */
            retSec = sscanf_s(samples_e[j][0], format_e[i], &osec);

            /* compare result */
            if((retSec == retStd) && Equal_f(osec,ostd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_e[i], samples_e[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_e[i], samples_e[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_e[i], samples_e[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_e[i],samples_e[j][1], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%e\n\n", samples_e[j][0], retStd, ostd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%e\n\n", samples_e[j][0], retSec, osec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_e[i],samples_e[j][0],samples_e[j][1],retStd,retSec,ostd,"%e",osec,"%e",(long unsigned)__LINE__);
#endif
            j++;
        }

        i++;
    }
    printf("%s", "%e test end\r\n");

    /* %lle test begin */
    printf("%s", " %lle test begin\r\n");
    i = 0;
    while(NULL != format_lle[i])
    {
        j = 0;
        while(NULL != samples_Le[j][0])
        {
            ollstd = 0;
            ollsec = 0;
            retStd = 0;
            retSec = 0;
            flag = 0;

            /* std function */
            retStd = sscanf(samples_Le[j][0], format_lle[i], &ollstd);
            /* sec function */
            retSec = sscanf_s(samples_Le[j][0], format_lle[i], &ollsec);

            /* compare result */
            if((retSec == retStd) && Equal_ll(ollsec,ollstd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_lle[i], samples_Le[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_lle[i], samples_Le[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_lle[i], samples_Le[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_lle[i],samples_Le[j][1], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%Le\n\n", samples_Le[j][0], retStd, ollstd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%Le\n\n", samples_Le[j][0], retSec, ollsec);
#endif
#if SCREEN_PRINT
            if(flag) 
               SSCANF(format_lle[i],samples_Le[j][0],samples_Le[j][1],retStd,retSec,ollstd,"%Le",ollsec,"%Le",(long unsigned)__LINE__);
#endif
            j++;
        }
        i++;
    }
    printf("%s", "%lle test end\r\n");

    /* %le test */
    printf("%s", "%le test begin\r\n");
    i =0;
    while(NULL != format_le[i])
    {
        j = 0;
        while(NULL != samples_le[j][0])
        {
            olstd = 0;
            olsec = 0;
            retStd = 0;
            retSec = 0;
            flag = 0;

            /* std function */
            retStd = sscanf(samples_le[j][0], format_le[i], &olstd);

            /* sec function */
            retSec = sscanf_s(samples_le[j][0], format_le[i], &olsec);

            /* compare result */
            if((retSec == retStd) && Equal_l(olsec,olstd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_le[i], samples_le[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_le[i], samples_le[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_le[i], samples_le[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_le[i],samples_le[j][1], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%le\n\n", samples_le[j][0], retStd, olstd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%le\n\n", samples_le[j][0], retSec, olsec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_le[i],samples_le[j][0],samples_le[j][1],retStd,retSec,olstd,"%le",olsec,"%le",(long unsigned)__LINE__);
#endif
            j++;
        }

        i++;
    }

    printf("%s", "%le test end\r\n");


    /* %Le test */
    printf("%s", "%Le test begin\r\n");
    i = 0;
    while(NULL != format_Le[i])
    {
        j = 0;
        while(NULL != samples_Le[j][0])
        {
            ollstd = 0;
            ollsec = 0;
            retStd = 0;
            retSec = 0;

            /* std function */
            retStd = sscanf(samples_Le[j][0], format_Le[i], &ollstd);
            /* sec function */
            retSec = sscanf_s(samples_Le[j][0], format_Le[i], &ollsec);

            /* compare result */
            if((retSec == retStd) && Equal_ll(ollsec,ollstd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_Le[i], samples_Le[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_Le[i], samples_Le[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_Le[i], samples_Le[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_Le[i],samples_Le[j][1], __LINE__);
            }


            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%Le\n\n", samples_Le[j][0], retStd, ollstd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%Le\n\n", samples_Le[j][0], retSec, ollsec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_Le[i],samples_Le[j][0],samples_Le[j][1],retStd,retSec,ollstd,"%Le",ollsec,"%Le",(long unsigned)__LINE__);
#endif            
            j++;
        }

        i++;
    }
    printf("%s", "%Le test end\r\n");
if(SUPPORT_Q) /*lint !e506*/
{
    /* %qe test */
    printf("%s", "%qe test begin\r\n");
    i = 0;
    while(NULL != format_qe[i]) /*lint !e661*/
    {
        j = 0;
        while(NULL != samples_Le[j][0])
        {
            ollstd = 0;
            ollsec = 0;
            retStd = 0;
            retSec = 0;

            /* std function */
            retStd = sscanf(samples_Le[j][0], format_qe[i], &ollstd);
            /* sec function */
            retSec = sscanf_s(samples_Le[j][0], format_qe[i], &ollsec);

            /* compare result */
            if((retSec == retStd) && Equal_ll(ollsec,ollstd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

            /* output the input, output and return value */
#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_qe[i], samples_Le[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_qe[i], samples_Le[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_qe[i], samples_Le[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_qe[i],samples_Le[j][1], __LINE__);
            }

            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%Le\n\n", samples_Le[j][0], retStd, ollstd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%Le\n\n", samples_Le[j][0], retSec, ollsec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_qe[i],samples_Le[j][0],samples_Le[j][1],retStd,retSec,ollstd,"%Le",ollsec,"%Le",(long unsigned)__LINE__);
#endif
            j++;
        }

        i++;
    }
    printf("%s", "%qe test end\r\n");
}
#if UNSUPPORT_TEST
#if (defined(_MSC_VER) && (1200 !=_MSC_VER) ) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux) || defined(_AIX)
{
    ollstd = 0;
    ollsec = 0;
    retStd = 0;
    retSec = 0;
    flag = 0;

    /* std function */
    retStd = sscanf("1.79e+308", "%lle", &ollstd);
    /* sec function */
    retSec = sscanf_s("1.79e+308", "%lle", &ollsec);

    /* compare result */
    if((retSec == retStd) && Equal_ll(ollsec,ollstd))
    {
        flag = 0; /* equal */
    }
    else
    {
        flag = 1; /* different */
    }

#if TXT_DOCUMENT_PRINT
    if(0 == flag) /* equal */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lle", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lle", "edge");
    }
    else  /* different */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%lle", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%lle","edge", __LINE__);
    }
    /* output the input, output and return value */
    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lle\n\n", "1.79e+308", retStd, ollstd);
    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lle\n\n", "1.79e+308", retSec, ollsec);
#endif
#if SCREEN_PRINT
    if(flag) 
        SSCANF("%lle","1.79e+308","edge",retStd,retSec,ollstd,"%lle",ollsec,"%lle",(long unsigned)__LINE__);
#endif
}
#endif
#if (defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
{
    ollstd = 0;
    ollsec = 0;
    retStd = 0;
    retSec = 0;
    flag = 0;

    /* std function */
    retStd = sscanf("1.79e+308", "%qe", &ollstd);
    /* sec function */
    retSec = sscanf_s("1.79e+308", "%qe", &ollsec);

    /* compare result */
    if((retSec == retStd) && Equal_ll(ollsec,ollstd))
    {
        flag = 0; /* equal */
    }
    else
    {
        flag = 1; /* different */
    }

#if TXT_DOCUMENT_PRINT
    if(0 == flag) /* equal */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%qe", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%qe", "edge");
    }
    else  /* different */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%qe", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%qe","edge", __LINE__);
    }
    /* output the input, output and return value */
    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%qe\n\n", "1.79e+308", retStd, ollstd);
    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%qe\n\n", "1.79e+308", retSec, ollsec);
#endif
#if SCREEN_PRINT
    if(flag) 
        SSCANF("%qe","1.79e+308","edge",retStd,retSec,ollstd,"%qe",ollsec,"%qe",(long unsigned)__LINE__);
#endif
}
#endif
#if defined(SECUREC_VXWORKS_PLATFORM)
{
    ollstd = 0;
    ollsec = 0;
    retStd = 0;
    retSec = 0;

    /* std function */
    retStd = sscanf("1.79e+308", "%Le", &ollstd);

    /* sec function */
    retSec = sscanf_s("1.79e+308", "%Le", &ollsec);

    /* compare result */
    if((retSec == retStd) && Equal_ll(ollsec,ollstd))
    {
        flag = 0; /* equal */
    }
    else
    {
        flag = 1; /* different */
    }

#if TXT_DOCUMENT_PRINT
    if(0 == flag) /* equal */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Le", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Le", "edge");
    }
    else  /* different */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%Le", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%Le","edge", __LINE__);
    }


    /* output the input, output and return value */
    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%Le\n\n", "1.79e+308", retStd, ollstd);
    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%Le\n\n", "1.79e+308", retSec, ollsec);
#endif
#if SCREEN_PRINT
    if(flag) 
        SSCANF("%Le","1.79e+308","edge",retStd,retSec,ollstd,"%Le",ollsec,"%Le",(long unsigned)__LINE__);
#endif
}
#endif
#endif
fprintf(fStd, "-------------------------------e test end--------------------------- \n");
fprintf(fSec, "-------------------------------e test end--------------------------- \n");
}

void test_sscanf_format_f(FILE* fStd,FILE* fSec)
{
    float ostd = 0;
    float osec = 0;

    double olstd = 0;
    double olsec = 0;

    long double ollstd = 0;
    long double ollsec = 0;

    int i = 0;
    int j = 0;
    int retStd = 0;
    int retSec = 0;
    int flag = 0; /* 0 means same, and 1 means different */

    char *format_f[] = 
    {
        "%f", "%0f", "%2f", "%8f", "%9f", 
        NULL
    };
    char *format_llf[] = 
    {
#if !((defined(_MSC_VER) && 1200 !=_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
        "%llf", /* it's behavior is same to %e */
#endif
        NULL
    };

    char *samples_f[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"3.4e+38", "edge"}, 
        {"-3.4e+38", "edge"},
#if OVERFLOW_MARK
        {"3.5e+38", "overflow(long double)"},
        {"-3.5e+38", "overflow(long double)"},
#endif
        {NULL, NULL}
    };
    
    char *format_lf[] = 
    {
        "%lf",
        NULL
    };

    char *samples_lf[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"1.79e+308", "edge"},        
        {"-1.79e+308", "edge"},
#if OVERFLOW_MARK
        {"1.80e+308", "overflow(long double)"},
        {"-1.89e+308", "overflow(long double)"},
#endif
        {NULL, NULL}
    };
    
    char *format_Lf[] = 
    {
#if !(defined(SECUREC_VXWORKS_PLATFORM))
        "%Lf",
#endif
        NULL
    };
    char *format_qf[] =  /* the same to L, not in ANSI C */
    {
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
        "%qf",
#endif
        NULL
    };

    char *samples_Lf[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"1.79e+308", "edge"}, 
        {"-1.79e+308", "edge"},
#if OVERFLOW_MARK
        {"1.80e+308", "overflow(long double)"},
        {"-1.89e+308", "overflow(long double)"},
        {"1.79e+4899", "overflow(long double)"},
        {"1.79e+5000", "overflow(long double)"},
#endif
        {NULL, NULL}
    };

    /* %f test begin */
    printf("%s", "%f test begin\r\n");
    fprintf(fStd, "-------------------------------f test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------f test begin--------------------------- \n"); /*lint !e668*/
    i = 0;
    while(NULL != format_f[i])
    {
        j = 0;
        while(NULL != samples_f[j][0])
        {
            ostd = 0;
            osec = 0;
            retStd = 0;
            retSec = 0;
            flag = 0;

            /* std function */
           retStd = sscanf(samples_f[j][0], format_f[i], &ostd);

           /* sec function */
           retSec = sscanf_s(samples_f[j][0], format_f[i], &osec);

            /* compare result */
            if((retSec == retStd) && Equal_f(osec,ostd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_f[i], samples_f[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_f[i], samples_f[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_f[i], samples_f[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_f[i],samples_f[j][1], __LINE__);
            }
            
            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%f\n\n", samples_f[j][0], retStd, ostd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%f\n\n", samples_f[j][0], retSec, osec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_f[i],samples_f[j][0],samples_f[j][1],retStd,retSec,ostd,"%f",osec,"%f",(long unsigned)__LINE__);
#endif
            j++;
        }

        i++;
    }

    printf("%s", "%f test end\r\n");

    /* %llf test begin */
    printf("%s", "%llf test begin\r\n");
    i = 0;
    while(NULL != format_llf[i])
    {
        j = 0;
        while(NULL != samples_Lf[j][0])
        {
            ollstd = 0;
            ollsec = 0;
            retStd = 0;
            retSec = 0;
            flag = 0;

            /* std function */
            retStd = sscanf(samples_Lf[j][0], format_llf[i], &ollstd);
            /* sec function */
            retSec = sscanf_s(samples_Lf[j][0], format_llf[i], &ollsec);

            /* compare result */
            if((retSec == retStd) && Equal_ll(ollsec,ollstd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_llf[i], samples_Lf[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_llf[i], samples_Lf[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_llf[i], samples_Lf[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_llf[i],samples_Lf[j][1], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%Lf\n\n", samples_Lf[j][0], retStd, ollstd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%Lf\n\n", samples_Lf[j][0], retSec, ollsec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_llf[i],samples_Lf[j][0],samples_Lf[j][1],retStd,retSec,ollstd,"%Lf",ollsec,"%Lf",(long unsigned)__LINE__);
#endif
            j++;
        }
        i++;
    }

    printf("%s", "%llf test end\r\n");

    /* %lf test */
    printf("%s", "%lf test begin\r\n");
    i =0;
    while(NULL != format_lf[i])
    {
        j = 0;
        while(NULL != samples_lf[j][0])
        {
            olstd = 0;
            olsec = 0;
            retStd = 0;
            retSec = 0;
            flag = 0;

            /* std function */
            retStd = sscanf(samples_lf[j][0], format_lf[i], &olstd);

            /* sec function */
            retSec = sscanf_s(samples_lf[j][0], format_lf[i], &olsec);

            /* compare result */
            if((retSec == retStd) && Equal_l(olsec,olstd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_lf[i], samples_lf[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_lf[i], samples_lf[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_lf[i], samples_lf[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_lf[i],samples_lf[j][1], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lf\n\n", samples_lf[j][0], retStd, olstd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lf\n\n", samples_lf[j][0], retSec, olsec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_lf[i],samples_lf[j][0],samples_lf[j][1],retStd,retSec,olstd,"%lf",olsec,"%lf",(long unsigned)__LINE__);
#endif
            j++;
        }

        i++;
    }

    printf("%s", "%lf test end\r\n");


    /* %Lf test */
    printf("%s", "%Lf test begin\r\n");
    i = 0;
    while(NULL != format_Lf[i])
    {
        j = 0;
        while(NULL != samples_Lf[j][0])
        {
            ollstd = 0;
            ollsec = 0;
            retStd = 0;
            retSec = 0;

            /* std function */
            retStd = sscanf(samples_Lf[j][0], format_Lf[i], &ollstd);

            /* sec function */
            retSec = sscanf_s(samples_Lf[j][0], format_Lf[i], &ollsec);

            /* compare result */
            if((retSec == retStd) && Equal_ll(ollsec,ollstd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_Lf[i], samples_Lf[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_Lf[i], samples_Lf[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_Lf[i], samples_Lf[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_Lf[i],samples_Lf[j][1], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%Lf\n\n", samples_Lf[j][0], retStd, ollstd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%Lf\n\n", samples_Lf[j][0], retSec, ollsec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_Lf[i],samples_Lf[j][0],samples_Lf[j][1],retStd,retSec,ollstd,"%Lf",ollsec,"%Lf",(long unsigned)__LINE__);
#endif            
            j++;
        }

        i++;
    }
    printf("%s", "%Lf test end\r\n");

if(SUPPORT_Q) /*lint !e506*/
{
    /* %qf test */
    printf("%s", "%qf test begin\r\n");
    i = 0;
    while(NULL != format_qf[i]) /*lint !e661*/
    {
        j = 0;
        while(NULL != samples_Lf[j][0])
        {
            ollstd = 0;
            ollsec = 0;
            retStd = 0;
            retSec = 0;

            /* std function */
            retStd = sscanf(samples_Lf[j][0], format_qf[i], &ollstd);

            /* sec function */
            retSec = sscanf_s(samples_Lf[j][0], format_qf[i], &ollsec);

            /* compare result */
            if((retSec == retStd) && Equal_ll(ollsec,ollstd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_qf[i], samples_Lf[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_qf[i], samples_Lf[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_qf[i], samples_Lf[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_qf[i],samples_Lf[j][1], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%Lf\n\n", samples_Lf[j][0], retStd, ollstd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%Lf\n\n", samples_Lf[j][0], retSec, ollsec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_qf[i],samples_Lf[j][0],samples_Lf[j][1],retStd,retSec,ollstd,"%Lf",ollsec,"%Lf",(long unsigned)__LINE__);
#endif
            j++;
        }

        i++;
    }
    printf("%s", "%qf test end\r\n");
}
#if UNSUPPORT_TEST
#if (defined(_MSC_VER) && (1200 !=_MSC_VER) ) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux) || defined(_AIX)
{
    ollstd = 0;
    ollsec = 0;
    retStd = 0;
    retSec = 0;
    flag = 0;

    /* std function */
    retStd = sscanf("1.79e+308", "%llf", &ollstd);
    /* sec function */
    retSec = sscanf_s("1.79e+308", "%llf", &ollsec);

    /* compare result */
    if((retSec == retStd) && Equal_ll(ollsec,ollstd))
    {
        flag = 0; /* equal */
    }
    else
    {
        flag = 1; /* different */
    }

#if TXT_DOCUMENT_PRINT
    if(0 == flag) /* equal */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%llf", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%llf", "edge");
    }
    else  /* different */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%llf", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%llf","edge", __LINE__);
    }
    /* output the input, output and return value */
    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llf\n\n", "1.79e+308", retStd, ollstd);
    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llf\n\n", "1.79e+308", retSec, ollsec);
#endif
#if SCREEN_PRINT
    if(flag) 
        SSCANF("%llf","1.79e+308","edge",retStd,retSec,ollstd,"%llf",ollsec,"%llf",(long unsigned)__LINE__);
#endif
}
#endif
#if (defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
{
    ollstd = 0;
    ollsec = 0;
    retStd = 0;
    retSec = 0;
    flag = 0;

    /* std function */
    retStd = sscanf("1.79e+308", "%qf", &ollstd);
    /* sec function */
    retSec = sscanf_s("1.79e+308", "%qf", &ollsec);

    /* compare result */
    if((retSec == retStd) && Equal_ll(ollsec,ollstd))
    {
        flag = 0; /* equal */
    }
    else
    {
        flag = 1; /* different */
    }

#if TXT_DOCUMENT_PRINT
    if(0 == flag) /* equal */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%qf", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%qf", "edge");
    }
    else  /* different */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%qf", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%qf","edge", __LINE__);
    }
    /* output the input, output and return value */
    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%qf\n\n", "1.79e+308", retStd, ollstd);
    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%qf\n\n", "1.79e+308", retSec, ollsec);
#endif
#if SCREEN_PRINT
    if(flag) 
        SSCANF("%qf","1.79e+308","edge",retStd,retSec,ollstd,"%qf",ollsec,"%qf",(long unsigned)__LINE__);
#endif
}
#endif
#if defined(SECUREC_VXWORKS_PLATFORM)
{
    ollstd = 0;
    ollsec = 0;
    retStd = 0;
    retSec = 0;

    /* std function */
    retStd = sscanf("1.79e+308", "%Lf", &ollstd);

    /* sec function */
    retSec = sscanf_s("1.79e+308", "%Lf", &ollsec);

    /* compare result */
    if((retSec == retStd) && Equal_ll(ollsec,ollstd))
    {
        flag = 0; /* equal */
    }
    else
    {
        flag = 1; /* different */
    }

#if TXT_DOCUMENT_PRINT
    if(0 == flag) /* equal */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lf", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lf", "edge");
    }
    else  /* different */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%Lf", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%Lf","edge", __LINE__);
    }


    /* output the input, output and return value */
    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%Lf\n\n", "1.79e+308", retStd, ollstd);
    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%Lf\n\n", "1.79e+308", retSec, ollsec);
#endif
#if SCREEN_PRINT
    if(flag) 
        SSCANF("%Lf","1.79e+308","edge",retStd,retSec,ollstd,"%Lf",ollsec,"%Lf",(long unsigned)__LINE__);
#endif
}
#endif
#endif
fprintf(fStd, "-------------------------------f test end--------------------------- \n");
fprintf(fSec, "-------------------------------f test end--------------------------- \n");

}

void test_sscanf_format_g(FILE* fStd,FILE* fSec)
{
    float ostd = 0;
    float osec = 0;

    double olstd = 0;
    double olsec = 0;

    long double ollstd = 0;
    long double ollsec = 0;

    int i = 0;
    int j = 0;
    int retStd = 0;
    int retSec = 0;
    int flag = 0; /* 0 means same, and 1 means different */

    char *format_g[] = 
    {
        "%g", "%0g", "%2g", "%8g", "%9g", 
        NULL
    };
    char *format_llg[] = 
    {
#if !((defined(_MSC_VER) && 1200 !=_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
        "%llg" /* it's behavior is same to %e */,
#endif
        NULL
    };

    char *samples_g[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"3.1415926e+35", "normal"},
        {"3.4e+38", "edge"}, 
        {"-3.4e+38", "edge"},
#if OVERFLOW_MARK
        {"3.5e+38", "overflow(long double)"},
        {"-3.5e+38", "overflow(long double)"},
#endif
        {NULL, NULL}
    };
    
    char *format_lg[] = 
    {
        "%lg",
        NULL
    };

    char *samples_lg[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"1.79e+308", "edge"},    
        {"-1.79e+308", "edge"},
#if OVERFLOW_MARK
        {"1.80e+308", "overflow(long double)"},
        {"-1.89e+308", "overflow(long double)"},
#endif
        {NULL, NULL}
    };
    
    char *format_Lg[] = 
    {
#if !(defined(SECUREC_VXWORKS_PLATFORM))
        "%Lg",
#endif
        NULL
    };

    char *format_qg[] =  /* the same to L, not in ANSI C */
    {
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
        "%qg",
#endif
        NULL
    };

    char *samples_Lg[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"1.79e+308", "edge"}, 
        {"-1.79e+308", "edge"},
#if OVERFLOW_MARK
        {"1.80e+308", "overflow(long double)"},
        {"-1.89e+308", "overflow(long double)"},
        {"1.79e+4899", "overflow(long double)"},
        {"1.79e+5000", "overflow(long double)"},
#endif
        {NULL, NULL}
    };

    /* %f test begin */
    printf("%s", "%g test begin\r\n");
    fprintf(fStd, "-------------------------------g test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------g test begin--------------------------- \n"); /*lint !e668*/
    i = 0;
    while(NULL != format_g[i])
    {
        j = 0;
        while(NULL != samples_g[j][0])
        {
            ostd = 0;
            osec = 0;
            retStd = 0;
            retSec = 0;
            flag = 0;

             /* std function */
            retStd = sscanf(samples_g[j][0], format_g[i], &ostd);
    
            /* sec function */
            retSec = sscanf_s(samples_g[j][0], format_g[i], &osec);

            /* compare result */
            if((retSec == retStd) && Equal_f(osec,ostd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_g[i], samples_g[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_g[i], samples_g[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_g[i], samples_g[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_g[i],samples_g[j][1], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%g\n\n", samples_g[j][0], retStd, ostd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%g\n\n", samples_g[j][0], retSec, osec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_g[i],samples_g[j][0],samples_g[j][1],retStd,retSec,ostd,"%g",osec,"%g",(long unsigned)__LINE__);
#endif
            j++;
        }

        i++;
    }
    printf("%s", "%g test end\r\n");

    /* %f test begin */
    printf("%s", "%%llg test begin\r\n");
    i = 0;
    while(NULL != format_llg[i])
    {
        j = 0;
        while(NULL != samples_Lg[j][0])
        {
            ollstd = 0;
            ollsec = 0;
            retStd = 0;
            retSec = 0;
            flag = 0;

            /* std function */
            retStd = sscanf(samples_Lg[j][0], format_llg[i], &ollstd);
            /* sec function */
            retSec = sscanf_s(samples_Lg[j][0], format_llg[i], &ollsec);

            /* compare result */
            if((retSec == retStd) && Equal_ll(ollsec,ollstd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_llg[i], samples_Lg[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_llg[i], samples_Lg[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_llg[i], samples_Lg[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_llg[i],samples_Lg[j][1], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%Lg\n\n", samples_Lg[j][0], retStd, ollstd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%Lg\n\n", samples_Lg[j][0], retSec, ollsec);
#endif
#if SCREEN_PRINT
            if(flag) 
               SSCANF(format_llg[i],samples_Lg[j][0],samples_Lg[j][1],retStd,retSec,ollstd,"%Lg",ollsec,"%Lg",(long unsigned)__LINE__);
#endif
            j++;
        }

        i++;
    }
    printf("%s", "%llg test end\r\n");

    /* %lf test */
    printf("%s", "%lg test begin\r\n");
    i =0;
    while(NULL != format_lg[i])
    {
        j = 0;
        while(NULL != samples_lg[j][0])
        {
            olstd = 0;
            olsec = 0;
            retStd = 0;
            retSec = 0;
            flag = 0;

            /* std function */
            retStd = sscanf(samples_lg[j][0], format_lg[i], &olstd);

            /* sec function */
            retSec = sscanf_s(samples_lg[j][0], format_lg[i], &olsec);

            /* compare result */
            if((retSec == retStd) && Equal_l(olsec,olstd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_lg[i], samples_lg[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_lg[i], samples_lg[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_lg[i], samples_lg[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_lg[i],samples_lg[j][1], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lg\n\n", samples_lg[j][0], retStd, olstd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lg\n\n", samples_lg[j][0], retSec, olsec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_lg[i],samples_lg[j][0],samples_lg[j][1],retStd,retSec,olstd,"%lg",olsec,"%lg",(long unsigned)__LINE__);
#endif
            j++;
        }

        i++;
    }
    printf("%s", "%lg test end\r\n");

    /* %Lg test */
    printf("%s", "%Lg test begin\r\n");
    i = 0;
    while(NULL != format_Lg[i])
    {
        j = 0;
        while(NULL != samples_Lg[j][0])
        {
            ollstd = 0;
            ollsec = 0;
            retStd = 0;
            retSec = 0;

            /* std function */
            retStd = sscanf(samples_Lg[j][0], format_Lg[i], &ollstd);

            /* sec function */
            retSec = sscanf_s(samples_Lg[j][0], format_Lg[i], &ollsec);

            /* compare result */
            if((retSec == retStd) && Equal_ll(ollsec,ollstd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_Lg[i], samples_Lg[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_Lg[i], samples_Lg[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_Lg[i], samples_Lg[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_Lg[i],samples_Lg[j][1], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%Lg\n\n", samples_Lg[j][0], retStd, ollstd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%Lg\n\n", samples_Lg[j][0], retSec, ollsec);
#endif
#if SCREEN_PRINT
            if(flag) 
               SSCANF(format_Lg[i],samples_Lg[j][0],samples_Lg[j][1],retStd,retSec,ollstd,"%Lg",ollsec,"%Lg",(long unsigned)__LINE__);
#endif    
            j++;
        }

        i++;
    }
    printf("%s", "%Lg test end\r\n");

if(SUPPORT_Q) /*lint !e506*/
{
    /* %qg test */
    printf("%s", "%qg test begin\r\n");
    i = 0;
    while(NULL != format_qg[i]) /*lint !e661*/
    {
        j = 0;
        while(NULL != samples_Lg[j][0])
        {
            ollstd = 0;
            ollsec = 0;
            retStd = 0;
            retSec = 0;

            /* std function */
            retStd = sscanf(samples_Lg[j][0], format_qg[i], &ollstd);

            /* sec function */
            retSec = sscanf_s(samples_Lg[j][0], format_qg[i], &ollsec);

            /* compare result */
            if((retSec == retStd) && Equal_ll(ollsec,ollstd))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_qg[i], samples_Lg[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_qg[i], samples_Lg[j][1]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_qg[i], samples_Lg[j][1]);
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_qg[i],samples_Lg[j][1], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%Lg\n\n", samples_Lg[j][0], retStd, ollstd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%Lg\n\n", samples_Lg[j][0], retSec, ollsec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_qg[i],samples_Lg[j][0],samples_Lg[j][1],retStd,retSec,ollstd,"%Lg",ollsec,"%Lg",(long unsigned)__LINE__);
#endif
            j++;
        }

        i++;
    }
    printf("%s", "%qg test end\r\n");
}

#if UNSUPPORT_TEST
#if (defined(_MSC_VER) && (1200 !=_MSC_VER) ) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux) || defined(_AIX)
{
    ollstd = 0;
    ollsec = 0;
    retStd = 0;
    retSec = 0;
    flag = 0;

    /* std function */
    retStd = sscanf("1.79e+308", "%llg", &ollstd);
    /* sec function */
    retSec = sscanf_s("1.79e+308", "%llg", &ollsec);

    /* compare result */
    if((retSec == retStd) && Equal_ll(ollsec,ollstd))
    {
        flag = 0; /* equal */
    }
    else
    {
        flag = 1; /* different */
    }

#if TXT_DOCUMENT_PRINT
    if(0 == flag) /* equal */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%llg", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%llg", "edge");
    }
    else  /* different */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%llg", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%llg","edge", __LINE__);
    }
    /* output the input, output and return value */
    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llg\n\n", "1.79e+308", retStd, ollstd);
    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llg\n\n", "1.79e+308", retSec, ollsec);
#endif
#if SCREEN_PRINT
    if(flag) 
        SSCANF("%llg","1.79e+308","edge",retStd,retSec,ollstd,"%llg",ollsec,"%llg",(long unsigned)__LINE__);
#endif
}
#endif
#if (defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
{
    ollstd = 0;
    ollsec = 0;
    retStd = 0;
    retSec = 0;
    flag = 0;

    /* std function */
    retStd = sscanf("1.79e+308", "%qg", &ollstd);
    /* sec function */
    retSec = sscanf_s("1.79e+308", "%qg", &ollsec);

    /* compare result */
    if((retSec == retStd) && Equal_ll(ollsec,ollstd))
    {
        flag = 0; /* equal */
    }
    else
    {
        flag = 1; /* different */
    }

#if TXT_DOCUMENT_PRINT
    if(0 == flag) /* equal */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%qg", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%qg", "edge");
    }
    else  /* different */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%qg", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%qg","edge", __LINE__);
    }
    /* output the input, output and return value */
    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%qg\n\n", "1.79e+308", retStd, ollstd);
    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%qg\n\n", "1.79e+308", retSec, ollsec);
#endif
#if SCREEN_PRINT
    if(flag) 
        SSCANF("%qg","1.79e+308","edge",retStd,retSec,ollstd,"%qg",ollsec,"%qg",(long unsigned)__LINE__);
#endif
}
#endif
#if defined(SECUREC_VXWORKS_PLATFORM)
{
    ollstd = 0;
    ollsec = 0;
    retStd = 0;
    retSec = 0;

    /* std function */
    retStd = sscanf("1.79e+308", "%Lg", &ollstd);

    /* sec function */
    retSec = sscanf_s("1.79e+308", "%Lg", &ollsec);

    /* compare result */
    if((retSec == retStd) && Equal_ll(ollsec,ollstd))
    {
        flag = 0; /* equal */
    }
    else
    {
        flag = 1; /* different */
    }

#if TXT_DOCUMENT_PRINT
    if(0 == flag) /* equal */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lg", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lg", "edge");
    }
    else  /* different */
    {
        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%Lg", "edge");
        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%Lg","edge", __LINE__);
    }


    /* output the input, output and return value */
    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%Lg\n\n", "1.79e+308", retStd, ollstd);
    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%Lg\n\n", "1.79e+308", retSec, ollsec);
#endif
#if SCREEN_PRINT
    if(flag) 
        SSCANF("%Lg","1.79e+308","edge",retStd,retSec,ollstd,"%Lg",ollsec,"%Lg",(long unsigned)__LINE__);
#endif
}
#endif
#endif
fprintf(fStd, "-------------------------------g test end--------------------------- \n");
fprintf(fSec, "-------------------------------g test end--------------------------- \n");
}


/*#if(defined(COMPATIBLE_LINUX_FORMAT))*/
#if (defined(COMPATIBLE_TESTCASE_LINUX_MANUAL))

/**                                                                           
 *@test test_sscanf_format_e_add                                     
 *- @ sscanf_s                                          
 *- @ï¿½Ô±È²ï¿½ï¿½ï¿½sscanfï¿½ï¿½ï¿½ï¿½ï¿½Ê½ï¿½ï¿½e,ï¿½ï¿½Òªï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿?*,white-space,    ï¿½ï¿½white-space,$ï¿½ï¿½ï¿½ï¿½
 *- @tbrief                                           
 *  -#                                                                    
 *  -#                                                                    
 *  -#                                                                    
 *- @texpectï¿½ï¿½ï¿½ï¿½ï¿½É¹ï¿½  
 *- @tprior 2                                                                 
 *- @tremark                                                                
 */ 
 
void  test_sscanf_format_e_add(FILE* fStd,FILE* fSec)
{

    char *format_e[] = 
    {
#if (UNSUPPORT_TEST) || !(defined(SECUREC_VXWORKS_PLATFORM))
    "%*e",
#endif
    "   \n\n\n%e\n\n",
    "%*3e,%e",
       /* "%2$e",*/
        /*"%1$e",*/
        NULL
    };
    char *samples_e[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"3.4e+38", "edge"},        
        {"-3.4e+38", "edge"},
        {NULL, NULL}
    };

      char *samples_e_interval[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"3.4e+38", "edge"},        
        {"-3.4e+38", "edge"},
        {NULL, NULL}
    };
       
    int i = 0;
    int j = 0;
    int retStd = 0;
    int retSec = 0;
    //int ret = 0;
    float ostd = 0;
    float osec = 0;

    float olstd = 0;
    float olsec = 0;
   
    //double sRes=0,Res=0;
    int flag = 0; /* 0 means same, and 1 means different */
    i=0;
        /* %e test begin */
     printf("%s", "%e  test begin\r\n");
    fprintf(fStd, "-------------------------------e add test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------e add test begin--------------------------- \n"); /*lint !e668*/

     while(NULL != samples_e_interval[j][0])
        {
            ostd = 0;
            osec = 0;
            olstd = 0;
            olsec = 0;               
            retStd = 0;
            retSec = 0;
            flag = 0;
                    /* std function */
                    retStd = sscanf(samples_e_interval[j][0], "%e,%e", &olstd,&ostd);
                    /* sec function */
                    retSec = sscanf_s(samples_e_interval[j][0], "%e,%e", &olstd,&ostd);

                    /* compare result */
                    if((retSec == retStd) && Equal_f(osec,ostd))
                    {
                        flag = 0; /* equal */
                    }
                    else
                    {
                        flag = 1; /* different */
                    }

        #if TXT_DOCUMENT_PRINT
                    if(0 == flag) /* equal */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%e,%e", samples_e_interval[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%e,%e", samples_e_interval[j][1]);
                    }
                    else  /* different */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%e,%e", samples_e_interval[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%e,%e",samples_e_interval[j][1], __LINE__);
                    }

                    /* output the input, output and return value */
                    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%e\n\n", samples_e_interval[j][0], retStd, ostd);
                    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%e\n\n", samples_e_interval[j][0], retSec, osec);
        #endif
        #if SCREEN_PRINT
                    if(flag) 
                        SSCANF("%e,%e",samples_e_interval[j][0],samples_e_interval[j][1],retStd,retSec,ostd,"%e",osec,"%e",(long unsigned)__LINE__);
        #endif
            j++;
        }
       
    while(NULL != format_e[i])
    {
        j = 0;
        while(NULL != samples_e[j][0])
        {
            ostd = 0;
            osec = 0;
            olstd = 0;
            olsec = 0;            
            retStd = 0;
            retSec = 0;
            flag = 0;
         if(strcmp(format_e[i],"%2$e")==0||strcmp(format_e[i],"%1$e")==0)  //16Î»ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½
         {
                    /* std function */
                    retStd = sscanf(samples_e[j][0], format_e[i], &ostd,&olstd);
                    /* sec function */
                    retSec = sscanf_s(samples_e[j][0], format_e[i], &osec,&olsec);

                    /* compare result */
                    if((retSec == retStd) && Equal_f(osec,ostd)&&Equal_f(olstd,olsec))
                    {
                        flag = 0; /* equal */
                    }
                    else
                    {
                        flag = 1; /* different */
                    }

        #if TXT_DOCUMENT_PRINT
                    if(0 == flag) /* equal */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_e[i], samples_e[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_e[i], samples_e[j][1]);
                    }
                    else  /* different */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_e[i], samples_e[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_e[i],samples_e[j][1], __LINE__);
                    }

                    /* output the input, output and return value */
                    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%e,%e\n\n", samples_e[j][0], retStd, ostd,olstd);
                    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%e,%e\n\n", samples_e[j][0], retSec, osec,olsec);
        #endif
        #if SCREEN_PRINT
                    if(flag) 
              {
                printf("sscanf(%s)(%s)(%lu):", format_e[i], samples_e[j][1],(long unsigned)__LINE__);\
                printf("%s\n", samples_e[j][0]);\
                printf("system: %d,", retStd);\
                printf("%e,%e", ostd,olstd);\
                printf("   secure: %d,", retSec);\
                printf("%e,%e", osec,olsec);\
                printf("\n\n");              
            }
        #endif         
         }
         else
         {
                    /* std function */
                    retStd = sscanf(samples_e[j][0], format_e[i], &ostd);
                    /* sec function */
                    retSec = sscanf_s(samples_e[j][0], format_e[i], &osec);

                    /* compare result */
                    if((retSec == retStd) && Equal_f(osec,ostd))
                    {
                        flag = 0; /* equal */
                    }
                    else
                    {
                        flag = 1; /* different */
                    }

        #if TXT_DOCUMENT_PRINT
                    if(0 == flag) /* equal */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_e[i], samples_e[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_e[i], samples_e[j][1]);
                    }
                    else  /* different */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_e[i], samples_e[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_e[i],samples_e[j][1], __LINE__);
                    }

                    /* output the input, output and return value */
                    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%e\n\n", samples_e[j][0], retStd, ostd);
                    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%e\n\n", samples_e[j][0], retSec, osec);
        #endif
        #if SCREEN_PRINT
                    if(flag) 
                        SSCANF(format_e[i],samples_e[j][0],samples_e[j][1],retStd,retSec,ostd,"%e",osec,"%e",(long unsigned)__LINE__);
        #endif
         }
            j++;
        }

        i++;
    }
    printf("%s", "%e test end\r\n"); 
    fprintf(fStd, "-------------------------------e add test end--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------e add test end--------------------------- \n"); /*lint !e668*/
}
 
/**                                                                           
 *@test test_sscanf_format_E_add                                     
 *- @ sscanf_s                                          
 *- @ï¿½Ô±È²ï¿½ï¿½ï¿½sscanfï¿½ï¿½ï¿½ï¿½ï¿½Ê½ï¿½ï¿½E,ï¿½ï¿½Òªï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿?ï¿½ï¿½ï¿½ï¿½,*,white-space,    ï¿½ï¿½white-space,$ï¿½ï¿½ï¿½ï¿½
 *- @tbrief                                           
 *  -#                                                                    
 *  -#                                                                    
 *  -#                                                                    
 *- @texpectï¿½ï¿½ï¿½ï¿½ï¿½É¹ï¿½  
 *- @tprior 2                                                                 
 *- @tremark                                                                
 */ 
void  test_sscanf_format_E_add(FILE* fStd,FILE* fSec)
{
    char *format_E[] = 
    {
        "%E", 
        "%0E", 
        "%2E", 
        "%8E", 
        "%9E",
#if (UNSUPPORT_TEST) || !(defined(SECUREC_VXWORKS_PLATFORM))
    "%*E",
#endif
    "   \n\n\n%E\n\n",
    "%*3E,%E",
        /*"%2$E",*/
        /*"%1$E",    */
        //"%"
        NULL
    };
    char *samples_E[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"3.4e+38", "edge"},        
        {"-3.4e+38", "edge"},
        {NULL, NULL}
    };

    char *samples_E_interval[][2] = 
    {
        {"3.1415926e+00,3.1415926e+00", "normal"},
        {"3.4e+38,3.4e+38", "edge"},        
        {"-3.4e+38,-3.4e+38", "edge"},
        {NULL, NULL}
    };
    
    int i = 0;
    int j = 0;
    int retStd = 0;
    int retSec = 0;
    //int ret = 0;
    float ostd = 0;
    float osec = 0;

    float olstd = 0;
    float olsec = 0;
    
    //double sRes=0,Res=0;
    int flag = 0; /* 0 means same, and 1 means different */
    i=0;
        /* %e test begin */
     printf("%s", "%E  add test begin\r\n");
    fprintf(fStd, "-------------------------------E add test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------E add test begin--------------------------- \n"); /*lint !e668*/

    while(NULL != samples_E_interval[j][0])
        {
            ostd = 0;
            osec = 0;
            olstd = 0;
            olsec = 0;               
            retStd = 0;
            retSec = 0;
            flag = 0;
                    /* std function */
                    retStd = sscanf(samples_E_interval[j][0], "%E,%E", &olstd,&ostd);
                    /* sec function */
                    retSec = sscanf_s(samples_E_interval[j][0], "%E,%E", &olstd,&osec);

                    /* compare result */
                    if((retSec == retStd) && Equal_f(osec,ostd))
                    {
                        flag = 0; /* equal */
                    }
                    else
                    {
                        flag = 1; /* different */
                    }

        #if TXT_DOCUMENT_PRINT
                    if(0 == flag) /* equal */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%E,%E", samples_E_interval[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%E,%E", samples_E_interval[j][1]);
                    }
                    else  /* different */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%E,%E", samples_E_interval[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%E,%E",samples_E_interval[j][1], __LINE__);
                    }

                    /* output the input, output and return value */
                    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%E\n\n", samples_E_interval[j][0], retStd, ostd);
                    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%E\n\n", samples_E_interval[j][0], retSec, osec);
        #endif
        #if SCREEN_PRINT
                    if(flag) 
                        SSCANF("%E,%E",samples_E_interval[j][0],samples_E_interval[j][1],retStd,retSec,ostd,"%E",osec,"%E",(long unsigned)__LINE__);
        #endif
            j++;
        }
    
    while(NULL != format_E[i])
    {
        j = 0;
        while(NULL != samples_E[j][0])
        {
            ostd = 0;
            osec = 0;
            olstd = 0;
            olsec = 0;               
            retStd = 0;
            retSec = 0;
            flag = 0;
         if(strcmp(format_E[i],"%2$E")==0||strcmp(format_E[i],"%1$E")==0)  //16Î»ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½
         {
                    /* std function */
                    retStd = sscanf(samples_E[j][0], format_E[i], &ostd,&olstd);
                    /* sec function */
                    retSec = sscanf_s(samples_E[j][0], format_E[i], &osec,&olsec);

                    /* compare result */
                    if((retSec == retStd) && Equal_f(osec,ostd)&&Equal_f(olstd,olsec))
                    {
                        flag = 0; /* equal */
                    }
                    else
                    {
                        flag = 1; /* different */
                    }

        #if TXT_DOCUMENT_PRINT
                    if(0 == flag) /* equal */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_E[i], samples_E[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_E[i], samples_E[j][1]);
                    }
                    else  /* different */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_E[i], samples_E[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_E[i],samples_E[j][1], __LINE__);
                    }

                    /* output the input, output and return value */
                    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%E,%E\n\n", samples_E[j][0], retStd, ostd,olstd);
                    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%E,%E\n\n", samples_E[j][0], retSec, osec,olsec);
        #endif
        #if SCREEN_PRINT
                    if(flag) 
              {
                printf("sscanf(%s)(%s)(%lu):", format_E[i], samples_E[j][1],(long unsigned)__LINE__);\
                printf("%s\n", samples_E[j][0]);\
                printf("system: %d,", retStd);\
                printf("%E,%E", ostd,olstd);\
                printf("   secure: %d,", retSec);\
                printf("%E,%E", osec,olsec);\
                printf("\n\n");              
            }
        #endif         
         }
         else
         {
                    /* std function */
                    retStd = sscanf(samples_E[j][0], format_E[i], &ostd);
                    /* sec function */
                    retSec = sscanf_s(samples_E[j][0], format_E[i], &osec);

                    /* compare result */
                    if((retSec == retStd) && Equal_f(osec,ostd))
                    {
                        flag = 0; /* equal */
                    }
                    else
                    {
                        flag = 1; /* different */
                    }

        #if TXT_DOCUMENT_PRINT
                    if(0 == flag) /* equal */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_E[i], samples_E[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_E[i], samples_E[j][1]);
                    }
                    else  /* different */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_E[i], samples_E[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_E[i],samples_E[j][1], __LINE__);
                    }

                    /* output the input, output and return value */
                    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%E\n\n", samples_E[j][0], retStd, ostd);
                    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%E\n\n", samples_E[j][0], retSec, osec);
        #endif
        #if SCREEN_PRINT
                    if(flag) 
                        SSCANF(format_E[i],samples_E[j][0],samples_E[j][1],retStd,retSec,ostd,"%E",osec,"%E",(long unsigned)__LINE__);
        #endif
             }
            j++;
        }

        i++;
    }
    printf("%s", "%E add test end\r\n"); 
    fprintf(fStd, "-------------------------------E add test end--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------E add test end--------------------------- \n"); /*lint !e668*/

}
/**                                                                           
 *@test test_sscanf_format_f_add                                     
 *- @ sscanf_s                                          
 *- @ï¿½Ô±È²ï¿½ï¿½ï¿½sscanfï¿½ï¿½ï¿½ï¿½ï¿½Ê½ï¿½ï¿½f,ï¿½ï¿½Òªï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿?*,white-space,    ï¿½ï¿½white-space,$ï¿½ï¿½ï¿½ï¿½
 *- @tbrief                                           
 *  -#                                                                    
 *  -#                                                                    
 *  -#                                                                    
 *- @texpectï¿½ï¿½ï¿½ï¿½ï¿½É¹ï¿½  
 *- @tprior 2                                                                 
 *- @tremark                                                                
 */ 
void  test_sscanf_format_f_add(FILE* fStd,FILE* fSec)
{
    char *format_f[] = 
    {
#if (UNSUPPORT_TEST) || !(defined(SECUREC_VXWORKS_PLATFORM))
    "%*f",
#endif
    "   \n\n\n%f\n\n",
    "%*3f,%f",
       /* "%2$f",*/
       /* "%1$f",*/
        NULL
    };
    char *samples_f[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"3.4e+38", "edge"},        
        {"-3.4e+38", "edge"},
        {NULL, NULL}
    };

        char *samples_f_interval[][2] = 
    {
        {"3.1415926e+00,3.1415926e+00", "normal"},
        {"3.4e+38,3.4e+38", "edge"},        
        {"-3.4e+38,-3.4e+38", "edge"},
        {NULL, NULL}
    };
        
    int i = 0;
    int j = 0;
    int retStd = 0;
    int retSec = 0;

    float ostd = 0;
    float osec = 0;

    float olstd = 0;
    float olsec = 0;
    int flag = 0; /* 0 means same, and 1 means different */
    i=0;
        /* %e test begin */
     printf("%s", "%f  add test begin\r\n");
    fprintf(fStd, "-------------------------------f add test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------f add test begin--------------------------- \n"); /*lint !e668*/

    while(NULL != samples_f_interval[j][0])
        {
            ostd = 0;
            osec = 0;
              olstd = 0;
            olsec = 0;            
            retStd = 0;
            retSec = 0;
            flag = 0;

                    /* std function */
                    retStd = sscanf(samples_f_interval[j][0], "%f,%f", &olstd,&ostd);
                    /* sec function */
                    retSec = sscanf_s(samples_f_interval[j][0], "%f,%f",&olsec, &osec);

                    /* compare result */
                    if((retSec == retStd) && Equal_f(osec,ostd))
                    {
                        flag = 0; /* equal */
                    }
                    else
                    {
                        flag = 1; /* different */
                    }

        #if TXT_DOCUMENT_PRINT
                    if(0 == flag) /* equal */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%f,%f", samples_f_interval[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%f,%f", samples_f_interval[j][1]);
                    }
                    else  /* different */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%f,%f", samples_f_interval[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%f,%f",samples_f_interval[j][1], __LINE__);
                    }

                    /* output the input, output and return value */
                    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%f\n\n", samples_f_interval[j][0], retStd, ostd);
                    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%f\n\n", samples_f_interval[j][0], retSec, osec);
        #endif
        #if SCREEN_PRINT
                    if(flag) 
                        SSCANF("%f,%f",samples_f_interval[j][0],samples_f_interval[j][1],retStd,retSec,ostd,"%f",osec,"%f",(long unsigned)__LINE__);
        #endif
            j++;
        }
    
    while(NULL != format_f[i])
    {
        j = 0;
        while(NULL != samples_f[j][0])
        {
            ostd = 0;
            osec = 0;
              olstd = 0;
            olsec = 0;            
            retStd = 0;
            retSec = 0;
            flag = 0;
        if(strcmp(format_f[i],"%2$f")==0||strcmp(format_f[i],"%1$f")==0)  //16Î»ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½
         {
                    /* std function */
                    retStd = sscanf(samples_f[j][0], format_f[i], &ostd,&olstd);
                    /* sec function */
                    retSec = sscanf_s(samples_f[j][0], format_f[i], &osec,&olsec);

                    /* compare result */
                    if((retSec == retStd) && Equal_f(osec,ostd)&&Equal_f(olstd,olsec))
                    {
                        flag = 0; /* equal */
                    }
                    else
                    {
                        flag = 1; /* different */
                    }

        #if TXT_DOCUMENT_PRINT
                    if(0 == flag) /* equal */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_f[i], samples_f[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_f[i], samples_f[j][1]);
                    }
                    else  /* different */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_f[i], samples_f[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_f[i],samples_f[j][1], __LINE__);
                    }

                    /* output the input, output and return value */
                    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%f,%f\n\n", samples_f[j][0], retStd, ostd,olstd);
                    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%f,%f\n\n", samples_f[j][0], retSec, osec,olsec);
        #endif
        #if SCREEN_PRINT
                    if(flag) 
              {
                printf("sscanf(%s)(%s)(%lu):", format_f[i], samples_f[j][1],(long unsigned)__LINE__);\
                printf("%s\n", samples_f[j][0]);\
                printf("system: %d,", retStd);\
                printf("%f,%f", ostd,olstd);\
                printf("   secure: %d,", retSec);\
                printf("%f,%f", osec,olsec);\
                printf("\n\n");             
            }
        #endif         
         }
         else
         {
                    /* std function */
                    retStd = sscanf(samples_f[j][0], format_f[i], &ostd);
                    /* sec function */
                    retSec = sscanf_s(samples_f[j][0], format_f[i], &osec);

                    /* compare result */
                    if((retSec == retStd) && Equal_f(osec,ostd))
                    {
                        flag = 0; /* equal */
                    }
                    else
                    {
                        flag = 1; /* different */
                    }

        #if TXT_DOCUMENT_PRINT
                    if(0 == flag) /* equal */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_f[i], samples_f[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_f[i], samples_f[j][1]);
                    }
                    else  /* different */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_f[i], samples_f[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_f[i],samples_f[j][1], __LINE__);
                    }

                    /* output the input, output and return value */
                    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%f\n\n", samples_f[j][0], retStd, ostd);
                    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%f\n\n", samples_f[j][0], retSec, osec);
        #endif
        #if SCREEN_PRINT
                    if(flag) 
                        SSCANF(format_f[i],samples_f[j][0],samples_f[j][1],retStd,retSec,ostd,"%f",osec,"%f",(long unsigned)__LINE__);
        #endif
             }
            j++;
        }

        i++;
    }
    printf("%s", "%f add test end\r\n"); 
    fprintf(fStd, "-------------------------------f add test end--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------f add test end--------------------------- \n"); /*lint !e668*/

}
/**                                                                           
 *@test test_sscanf_format_g_add                                     
 *- @ sscanf_s                                          
 *- @ï¿½Ô±È²ï¿½ï¿½ï¿½sscanfï¿½ï¿½ï¿½ï¿½ï¿½Ê½ï¿½ï¿½g,ï¿½ï¿½Òªï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿?*,white-space,    ï¿½ï¿½white-space,$ï¿½ï¿½ï¿½ï¿½
 *- @tbrief                                           
 *  -#                                                                    
 *  -#                                                                    
 *  -#                                                                    
 *- @texpectï¿½ï¿½ï¿½ï¿½ï¿½É¹ï¿½  
 *- @tprior 2                                                                 
 *- @tremark                                                                
 */ 
void  test_sscanf_format_g_add(FILE* fStd,FILE* fSec)
{
    char *format_g[] = 
    {
#if (UNSUPPORT_TEST) || !(defined(SECUREC_VXWORKS_PLATFORM))
    "%*g",
#endif
    "   \n\n\n%g\n\n",
       /* "%2$g",*/
        /*"%1$g",*/
        NULL
    };
    char *samples_g[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"3.4e+38", "edge"},        
        {"-3.4e+38", "edge"},
        {NULL, NULL}
    };
       char *samples_g_interval[][2] = 
    {
        {"3.1415926e+00,3.1415926e+00", "normal"},
        {"3.4e+38,3.4e+38", "edge"},        
        {"-3.4e+38,-3.4e+38", "edge"},
        {NULL, NULL}
    };
       
    int i = 0;
    int j = 0;
    int retStd = 0;
    int retSec = 0;

    float ostd = 0;
    float osec = 0;

    float olstd = 0;
    float olsec = 0;

      /*double sRes=0,Res=0; */
    int flag = 0; /* 0 means same, and 1 means different */
    i=0;
        /* %e test begin */
     printf("%s", "%g  add test begin\r\n");
    fprintf(fStd, "-------------------------------g add test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------g add test begin--------------------------- \n"); /*lint !e668*/

        while(NULL != samples_g_interval[j][0])
        {
            ostd = 0;
            osec = 0;
              olstd = 0;
            olsec = 0;             
            retStd = 0;
            retSec = 0;
            flag = 0;

                    /* std function */
                    retStd = sscanf(samples_g_interval[j][0], "%g,%g", &olstd,&ostd);
                    /* sec function */
                    retSec = sscanf_s(samples_g_interval[j][0], "%g,%g",&olsec, &osec);

                    /* compare result */
                    if((retSec == retStd) && Equal_f(osec,ostd))
                    {
                        flag = 0; /* equal */
                    }
                    else
                    {
                        flag = 1; /* different */
                    }

        #if TXT_DOCUMENT_PRINT
                    if(0 == flag) /* equal */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n",  "%g,%g", samples_g_interval[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n",  "%g,%g", samples_g_interval[j][1]);
                    }
                    else  /* different */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n",  "%g,%g", samples_g_interval[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n",  "%g,%g",samples_g_interval[j][1], __LINE__);
                    }

                    /* output the input, output and return value */
                    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%g\n\n", samples_g_interval[j][0], retStd, ostd);
                    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%g\n\n", samples_g_interval[j][0], retSec, osec);
        #endif
        #if SCREEN_PRINT
                    if(flag) 
                        SSCANF( "%g,%g",samples_g_interval[j][0],samples_g_interval[j][1],retStd,retSec,ostd,"%g",osec,"%g",(long unsigned)__LINE__);
        #endif
            j++;
            }
        
    while(NULL != format_g[i])
    {
        j = 0;
        while(NULL != samples_g[j][0])
        {
            ostd = 0;
            osec = 0;
              olstd = 0;
            olsec = 0;             
            retStd = 0;
            retSec = 0;
            flag = 0;
         if(strcmp(format_g[i],"%2$g")==0||strcmp(format_g[i],"%1$g")==0)  //16Î»ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½
         {
                    /* std function */
                    retStd = sscanf(samples_g[j][0], format_g[i], &ostd,&olstd);
                    /* sec function */
                    retSec = sscanf_s(samples_g[j][0], format_g[i], &osec,&olsec);

                    /* compare result */
                    if((retSec == retStd) && Equal_f(osec,ostd)&&Equal_f(olstd,olsec))
                    {
                        flag = 0; /* equal */
                    }
                    else
                    {
                        flag = 1; /* different */
                    }

        #if TXT_DOCUMENT_PRINT
                    if(0 == flag) /* equal */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_g[i], samples_g[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_g[i], samples_g[j][1]);
                    }
                    else  /* different */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_g[i], samples_g[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_g[i],samples_g[j][1], __LINE__);
                    }

                    /* output the input, output and return value */
                    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%g,%g\n\n", samples_g[j][0], retStd, ostd,olstd);
                    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%g,%g\n\n", samples_g[j][0], retSec, osec,olsec);
        #endif
        #if SCREEN_PRINT
                    if(flag) 
              {
                printf("sscanf(%s)(%s)(%lu):", format_g[i], samples_g[j][1],(long unsigned)__LINE__);\
                printf("%s\n", samples_g[j][0]);\
                printf("system: %d,", retStd);\
                printf("%g,%g", ostd,olstd);\
                printf("   secure: %d,", retSec);\
                printf("%g,%g", osec,olsec);\
                printf("\n\n");              
            }
        #endif         
         }
         else
         {
                    /* std function */
                    retStd = sscanf(samples_g[j][0], format_g[i], &ostd);
                    /* sec function */
                    retSec = sscanf_s(samples_g[j][0], format_g[i], &osec);

                    /* compare result */
                    if((retSec == retStd) && Equal_f(osec,ostd))
                    {
                        flag = 0; /* equal */
                    }
                    else
                    {
                        flag = 1; /* different */
                    }

        #if TXT_DOCUMENT_PRINT
                    if(0 == flag) /* equal */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_g[i], samples_g[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_g[i], samples_g[j][1]);
                    }
                    else  /* different */
                    {
                        fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_g[i], samples_g[j][1]);
                        fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_g[i],samples_g[j][1], __LINE__);
                    }

                    /* output the input, output and return value */
                    fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%g\n\n", samples_g[j][0], retStd, ostd);
                    fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%g\n\n", samples_g[j][0], retSec, osec);
        #endif
        #if SCREEN_PRINT
                    if(flag) 
                        SSCANF(format_g[i],samples_g[j][0],samples_g[j][1],retStd,retSec,ostd,"%g",osec,"%g",(long unsigned)__LINE__);
        #endif
         }
            j++;
        }

        i++;
    }
    printf("%s", "%g add test end\r\n"); 
    fprintf(fStd, "-------------------------------g add test end--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------g add test end--------------------------- \n"); /*lint !e668*/

}

void test_sscanf_format_a_add(FILE* fStd,FILE* fSec)
{
    float ostd = 0;
    float osec = 0;
    float temp = 0;

    double diff = 0;

    int i = 0;
    int j = 0;
    int retStd = 0;
    int retSec = 0;
    int flag = 0; /* 0 means same, and 1 means different */

    char *format_a[] = 
    {
        "%*a", 
        "   %*3a%a", 
        NULL
    };

    char *samples_a[][2] = 
    {
        {"3.1415926e+00", "normal"},
        {"3.4e+38", "edge"},  
        {"-3.4e+38", "edge"},
#if OVERFLOW_MARK
        {"3.5e+38", "overflow"},
        {"-3.5e+38", "overflow"},
#endif
        {NULL, NULL}
    };
    
    char *samples_a_interval[][2] = 
    {
        {"3.1415926e+00,3.1415926e+00", "normal"},
        {"3.4e+38,3.4e+38", "edge"},  
        {"-3.4e+38,-3.4e+38", "edge"},
#if OVERFLOW_MARK
        {"3.5e+38,3.5e+38", "overflow"},
        {"-3.5e+38,-3.5e+38", "overflow"},
#endif
        {NULL, NULL}
    };    

    while(NULL != format_a[i]) /*lint !e661*/
    {
        j = 0;
        while(NULL != samples_a[j][0])
        {
            ostd = 0;
            osec = 0;
            diff = 0;
            retStd = 0;
            retSec = 0;
            flag = 0;

            /* std function */
            retStd = sscanf(samples_a[j][0], format_a[i], &ostd);

            /* sec function */
            retSec = sscanf_s(samples_a[j][0], format_a[i], &osec);

            /* compare result */
            diff = (osec - ostd);
            if((retSec == retStd) && ((diff >= - EPSINON) && (diff <= EPSINON)))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_a[i], samples_a[j][1]); /*lint !e668*/
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", format_a[i], samples_a[j][1]); /*lint !e668*/
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", format_a[i], samples_a[j][1]); /*lint !e668*/
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", format_a[i],samples_a[j][1], __LINE__); /*lint !e668*/
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%a\n\n", samples_a[j][0], retStd, ostd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%a\n\n", samples_a[j][0], retSec, osec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF(format_a[i],samples_a[j][0],samples_a[j][1],retStd,retSec,ostd,"%a",osec,"%a",(long unsigned)__LINE__);
#endif
            j++;
        }

        i++;
    }
    
        /*%a,%a*/
        j = 0;
        while(NULL != samples_a_interval[j][0])
        {
            ostd = 0;
            osec = 0;
            diff = 0;
            retStd = 0;
            retSec = 0;
            flag = 0;

            /* std function */
            retStd = sscanf(samples_a_interval[j][0], "%a,%a", &temp, &ostd);

            /* sec function */
            retSec = sscanf_s(samples_a_interval[j][0], "%a,%a", &temp, &osec);

            /* compare result */
            diff = (osec - ostd);
            if((retSec == retStd) && ((diff >= - EPSINON) && (diff <= EPSINON)))
            {
                flag = 0; /* equal */
            }
            else
            {
                flag = 1; /* different */
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) /* equal */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%a,%a", samples_a_interval[j][1]); /*lint !e668*/
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%a,%a", samples_a_interval[j][1]); /*lint !e668*/
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%a,%a", samples_a_interval[j][1]); /*lint !e668*/
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%a,%a",samples_a_interval[j][1], __LINE__); /*lint !e668*/
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%a\n\n", samples_a_interval[j][0], retStd, ostd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%a\n\n", samples_a_interval[j][0], retSec, osec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF("%a,%a",samples_a_interval[j][0],samples_a_interval[j][1],retStd,retSec,ostd,"%a",osec,"%a",(long unsigned)__LINE__);
#endif
            j++;
        }  


        /*%2$a
        j = 0;
        while(NULL != samples_a[j][0])
        {
            ostd = 0;
            osec = 0;
            diff = 0;
            retStd = 0;
            retSec = 0;
            flag = 0;

          
            retStd = sscanf(samples_a[j][0], "%2$a", &temp, &ostd);

            
            retSec = sscanf_s(samples_a[j][0], "%2$a", &temp, &osec);

            
            diff = (osec - ostd);
            if((retSec == retStd) && ((diff >= - EPSINON) && (diff <= EPSINON)))
            {
                flag = 0; 
            }
            else
            {
                flag = 1; 
            }

#if TXT_DOCUMENT_PRINT
            if(0 == flag) 
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%2$a", samples_a[j][1]); 
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%2$a", samples_a[j][1]); 
            }
            else  
            {
                fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%2$a", samples_a[j][1]); 
                fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%2$a",samples_a[j][1], __LINE__); 
            }

           
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%a\n\n", samples_a[j][0], retStd, ostd);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%a\n\n", samples_a[j][0], retSec, osec);
#endif
#if SCREEN_PRINT
            if(flag) 
                SSCANF("%2$a",samples_a[j][0],samples_a_interval[j][1],retStd,retSec,ostd,"%a",osec,"%a",(long unsigned)__LINE__);
#endif
            j++;
        }  
        */

}

#endif
