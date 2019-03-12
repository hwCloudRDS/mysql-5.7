
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

#define  MAX_BUFF_SIZE 512

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
                      
void test_printf_format_a(FILE* fStd,FILE* fSec)
{
    char strStd[MAX_BUFF_SIZE] = {0x00};
    char strSec[MAX_BUFF_SIZE] = {0x00};

    int i = 0;
    int j = 0;
    int retStd = 0;
    int retSec = 0;

    int flag = 0; /* 0 means same, and 1 means different */

    char* format_a[] = 
    {
#if UNSUPPORT_TEST_A
        "%a", "%.0a", "%.2a", "%.6a", "%.7a", /*"%'a",*/
#endif
        NULL
    };

    double samples_a[] = 
    {
        3.1415926e+00, 
        3.4e+38,        
        -3.4e+38,
#if OVERFLOW_MARK
        3.5e+38,
        -3.5e+38,
#endif
        0
    };

    char* flag_a[] = 
    {
        "3.1415926e+00", 
        "3.4e+38",        
        "-3.4e+38",
#if OVERFLOW_MARK
        "3.5e+38",
        "-3.5e+38",
#endif
        NULL
    };

    char *samples_a_decri[] =
    {
        "normal",
        "edge",  
        "edge",
#if OVERFLOW_MARK
        "overflow",
        "overflow",
#endif
        NULL
    };

    printf("%s\n", "%a test begin");

    i = 0;
    while(NULL != format_a[i]) /*lint !e661*/
    {
        j = 0;
        while((0 != samples_a[j]) && (NULL != samples_a_decri[j]))
        {
            retStd = 0;
            retSec = 0;
            flag = 0;
            memset(strStd, 0, MAX_BUFF_SIZE);
            memset(strSec, 0, MAX_BUFF_SIZE);

            /* std function */
            retStd = sprintf(strStd, format_a[i], samples_a[j]);

            /* sec function */
            retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_a[i], samples_a[j]);

            /* compare result */
            if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_a[i], samples_a_decri[j]); /*lint !e668*/
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_a[i], samples_a_decri[j]); /*lint !e668*/
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_a[i], samples_a_decri[j]); /*lint !e668*/
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_a[i],samples_a_decri[j], __LINE__); /*lint !e668*/
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_a[j], retStd, strStd);
            fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_a[j], retSec, strSec);
#endif
#if SCREEN_PRINT
            if(flag)
            {
                SPRINTF(format_a[i],flag_a[j],samples_a_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
            }
#endif
            j++;
        }
        i++;
    }

    printf("%s\n", "%a test end");

}

void test_printf_format_e_2(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

        char *formats[] = {
                "%-10e",
                "%-20e",
                "%+10e",
                "%+20e",
                "% 10e",
                "% 20e",
                "%010e",
                "%020e",
                "%.2e",
                "%.8e",
                NULL
        };

        double sample[] = 
        {
                -3.4e+38,
                3.1415926e+00,
                3.4e+38,
                0
        };

        char *flag[][2] = 
        {
                {"-3.4e+38",       "edge"  },
                {"3.1415926e+00",       "normal" },
                {"3.4e+38",      "edge"  }
        };

        int isdiff=0;
        int retc, rets;
        char stdbuf[256];
        char secbuf[256];
        int k=0;
        int m=0;

        fprintf(fstd, "-------------------------------e test 2 begin--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------e test 2 begin--------------------------- \n"); /*lint !e668*/

        k = 0;
        while(formats[k] != NULL)
        {
                m = 0;
                while(sample[m] < -1.0  || sample[m] > 1.0)
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

        fprintf(fstd, "-------------------------------e test 2 end--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------e test 2 end--------------------------- \n"); /*lint !e668*/

}

void test_printf_format_e(FILE* fStd, FILE* fSec)
{
    char strStd[MAX_BUFF_SIZE] = {0x00};
    char strSec[MAX_BUFF_SIZE] = {0x00};

    int i = 0;
    int j = 0;
    int retStd = 0;
    int retSec = 0;

    int flag = 0; /* 0 means same, and 1 means different */

    char* format_e[] = 
    {
        "%e", "%#.0e", "%.0e","%.2e", "%.6e", "%.7e",
        NULL
    };

    double samples_e[] = 
    {
        3.1415926e+00, 
        3.4e+38,        
        -3.4e+38,
#if OVERFLOW_MARK
        3.5e+38,
        -3.5e+38,
#endif
        0
    };

    char* flag_e[] = 
    {
        "3.1415926e+00", 
        "3.4e+38",        
        "-3.4e+38",
#if OVERFLOW_MARK
        "3.5e+38",
        "-3.5e+38",
#endif
        NULL
    };

    char *samples_e_decri[] =
    {
        "normal",
        "edge",       
        "edge",
#if OVERFLOW_MARK
        "overflow(long double)",
        "overflow(long double)",
#endif
        NULL
    };

    char* format_le[] = 
    {
        "%le", 
        NULL
    };

    double samples_le[] = 
    {
        3.1415926e+00,
        1.79e+308,
        -1.79e+308,
#if OVERFLOW_MARK
       /* 1.80e+308,*/
      /* -1.89e+308, */
#endif
        0
    };

    char* flag_le[] = 
    {
        "3.1415926e+00",
        "1.79e+308",
        "-1.79e+308",
#if OVERFLOW_MARK
       /* "1.80e+308",*/
      /* "-1.89e+308", */
#endif
        NULL
    };

    char* format_Le[] = /* this same to le*/
    {         
        "%Le",
        NULL
    };
#ifndef VXWORKS_CAVIUM_5434
    long double samples_Le[] = 
    {
        3.1415926e+00,
        1.79e+308,        
        -1.79e+308,
#if OVERFLOW_MARK
        /* 1.80e+308,*/
        /* -1.89e+308, */
#endif
        0
    };

    char* flag_Le[] = 
    {
        "3.1415926e+00",
        "1.79e+308",        
        "-1.79e+308",
#if OVERFLOW_MARK
        /* "1.80e+308",*/
        /* "-1.89e+308", */
#endif
        NULL
    };
#endif
    char *samples_le_decri[] =
    {
        "normal",
        "edge",       
        "edge",
#if OVERFLOW_MARK
        /* "overflow(long double)", */
        /* "overflow(long double)", */
#endif
        NULL
    };

    printf("%s\n", "%e test begin");
    fprintf(fStd, "-------------------------------e test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------e test begin--------------------------- \n"); /*lint !e668*/

    i = 0;
    while(NULL != format_e[i])
    {
        j = 0;
        while((0 != samples_e[j]) && (NULL != samples_e_decri[j]))
        {
            retStd = 0;
            retSec = 0;
            flag = 0;
            memset(strStd, 0, MAX_BUFF_SIZE);
            memset(strSec, 0, MAX_BUFF_SIZE);

            /* std function */
            retStd = sprintf(strStd, format_e[i], samples_e[j]);

            /* sec function */
            retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_e[i], samples_e[j]);

            /* compare result */
            if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_e[i], samples_e_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_e[i], samples_e_decri[j]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_e[i], samples_e_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_e[i],samples_e_decri[j], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_e[j], retStd, strStd);
            fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_e[j], retSec, strSec);
#endif
#if SCREEN_PRINT
            if(flag)
            {
                SPRINTF(format_e[i],flag_e[j],samples_e_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
            }
#endif
            j++;
        }
        i++;
    }

    printf("%s\n", "%e test end");

    printf("%s\n", "%le test begin");

    i = 0;
    while(NULL != format_le[i])
    {
        j = 0;
        while((0 != samples_le[j]) && (NULL != samples_le_decri[j]))
        {
            retStd = 0;
            retSec = 0;
            flag = 0;
            memset(strStd, 0, MAX_BUFF_SIZE);
            memset(strSec, 0, MAX_BUFF_SIZE);

            /* std function */
            retStd = sprintf(strStd, format_le[i], samples_le[j]);

            /* sec function */
            retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_le[i], samples_le[j]);

            /* compare result */
            if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_le[i], samples_le_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_le[i], samples_le_decri[j]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_le[i], samples_le_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_le[i],samples_le_decri[j], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_le[j], retStd, strStd);
            fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_le[j], retSec, strSec);
#endif
#if SCREEN_PRINT
            if(flag)
            {
               SPRINTF(format_le[i],flag_le[j],samples_le_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
            }
#endif
            j++;
        }
        i++;
    }

    printf("%s\n", "%le test end");
#ifndef VXWORKS_CAVIUM_5434
    printf("%s\n", "%Le test begin");
    i = 0;
    while(NULL != format_Le[i])
    {
        j = 0;
        while((0 != samples_Le[j]) && (NULL != samples_le_decri[j]))
        {
            retStd = 0;
            retSec = 0;
            flag = 0;
            memset(strStd, 0, MAX_BUFF_SIZE);
            memset(strSec, 0, MAX_BUFF_SIZE);

            /* std function */
            retStd = sprintf(strStd, format_Le[i], samples_Le[j]);

            /* sec function */
            retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_Le[i], samples_Le[j]);

            /* compare result */
            if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_Le[i], samples_le_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_Le[i], samples_le_decri[j]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_Le[i], samples_le_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_Le[i],samples_le_decri[j], __LINE__);
            }
            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_Le[j], retStd, strStd);
            fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_Le[j], retSec, strSec);
#endif
#if SCREEN_PRINT
            if(flag)
            {
                SPRINTF(format_Le[i],flag_Le[j],samples_le_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
            }
#endif
            j++;
        }
        i++;
    }
    printf("%s\n", "%Le test end");
#endif
    fprintf(fStd, "-------------------------------e test end--------------------------- \n");
    fprintf(fSec, "-------------------------------e test end--------------------------- \n");
}


void test_printf_format_f(FILE* fStd, FILE* fSec)
{
    char strStd[MAX_BUFF_SIZE] = {0x00};
    char strSec[MAX_BUFF_SIZE] = {0x00};

    int i = 0;
    int j = 0;
    int retStd = 0;
    int retSec = 0;

    int flag = 0; /* 0 means same, and 1 means different */

    char* format_f[] = 
    {
        "%f", "%#.0f", "%.0f","%.2f", "%.6f", "%.7f",/*"%'f",*/
        NULL
    };

    double samples_f[] = 
    {
        3.1415926e+00, 
        3.4e+38,        
        -3.4e+38,
#if OVERFLOW_MARK
        3.5e+38,
        -3.5e+38,
#endif
        0
    };

    char* flag_f[] = 
    {
        "3.1415926e+00", 
        "3.4e+38",        
        "-3.4e+38",
#if OVERFLOW_MARK
        "3.5e+38",
        "-3.5e+38",
#endif
        NULL
    };
    char *samples_f_decri[] =
    {
        "normal",
        "edge",        
        "edge",
#if OVERFLOW_MARK
        "overflow(long double)",
        "overflow(long double)",
#endif
        NULL
    };

    char* format_lf[] = 
    {
        "%lf", 
        NULL
    };


    double samples_lf[] = 
    {
        3.1415926e+00,
        1.79e+308, /*linux64 will crash */
        -1.79e+308,/* linux 64 will crash */
#if OVERFLOW_MARK
        /* 1.80e+308,*/
        /* -1.89e+308, */
#endif
        0
    };

    char* flag_lf[] = 
    {
        "3.1415926e+00",
        "1.79e+308", /*linux64 will crash */
        "-1.79e+308",/* linux 64 will crash */
#if OVERFLOW_MARK
        /* "1.80e+308",*/
        /* "-1.89e+308", */
#endif
        NULL
    };

    char* format_Lf[] = 
    {
        "%Lf",
        NULL
    };
#ifndef VXWORKS_CAVIUM_5434
    long double samples_Lf[] = 
    {
        3.1415926e+00,
        1.79e+308,         
        -1.79e+308,
#if OVERFLOW_MARK
        /* 1.80e+308,*/
        /* -1.89e+308, */
#endif
        0
    };

    char* flag_Lf[] = 
    {
        "3.1415926e+00",
        "1.79e+308",         
        "-1.79e+308",
#if OVERFLOW_MARK
        /* "1.80e+308",*/
        /* "-1.89e+308", */
#endif
        NULL
    };
#endif
    char *samples_lf_decri[] =
    {
        "normal",
        "edge",
        "edge",
#if OVERFLOW_MARK
        /* "overflow(long double)", */
        /* "overflow(long double)", */
#endif
        NULL
    };

    printf("%s\n", "%f test begin");
    fprintf(fStd, "-------------------------------f test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------f test begin--------------------------- \n"); /*lint !e668*/
    i = 0;
    while(NULL != format_f[i])
    {
        j = 0;
        while((0 != samples_f[j]) && (NULL != samples_f_decri[j]))
        {
            retStd = 0;
            retSec = 0;
            flag = 0;
            memset(strStd, 0, MAX_BUFF_SIZE);
            memset(strSec, 0, MAX_BUFF_SIZE);

            /* std function */
            retStd = sprintf(strStd, format_f[i], samples_f[j]);

            /* sec function */
            retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_f[i], samples_f[j]);

            /* compare result */
            if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_f[i], samples_f_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_f[i], samples_f_decri[j]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_f[i], samples_f_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_f[i],samples_f_decri[j], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_f[j], retStd, strStd);
            fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_f[j], retSec, strSec);
#endif
#if SCREEN_PRINT
            if(flag)
            {
                SPRINTF(format_f[i],flag_f[j],samples_f_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
            }
#endif
            j++;
        }
        i++;
    }

    printf("%s\n", "%f test end");

    printf("%s\n", "%lf test begin");

    i = 0;
    while(NULL != format_lf[i])
    {
        j = 0;
        while((0 != samples_lf[j]) && (NULL != samples_lf_decri[j]))
        {
            retStd = 0;
            retSec = 0;
            flag = 0;
            memset(strStd, 0, MAX_BUFF_SIZE);
            memset(strSec, 0, MAX_BUFF_SIZE);

            /* std function */
            retStd = sprintf(strStd, format_lf[i], samples_lf[j]);

            /* sec function */
            retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_lf[i], samples_lf[j]);

            /* compare result */
            if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_lf[i], samples_lf_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_lf[i], samples_lf_decri[j]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_lf[i], samples_lf_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_lf[i],samples_lf_decri[j], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_lf[j], retStd, strStd);
            fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_lf[j], retSec, strSec);
#endif
#if SCREEN_PRINT
            if(flag)
            {
                SPRINTF(format_lf[i],flag_lf[j],samples_lf_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
            }
#endif
            j++;
        }
        i++;
    }
    printf("%s\n", "%lf test end");
#ifndef VXWORKS_CAVIUM_5434
    printf("%s\n", "%Lf test begin");

    i = 0;
    while(NULL != format_Lf[i])
    {
        j = 0;
        while((0 != samples_Lf[j]) && (NULL != samples_lf_decri[j]))
        {
            retStd = 0;
            retSec = 0;
            flag = 0;
            memset(strStd, 0, MAX_BUFF_SIZE);
            memset(strSec, 0, MAX_BUFF_SIZE);

            /* std function */
            retStd = sprintf(strStd, format_Lf[i], samples_Lf[j]);

            /* sec function */
            retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_Lf[i], samples_Lf[j]);

            /* compare result */
            if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_Lf[i], samples_lf_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_Lf[i], samples_lf_decri[j]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_Lf[i], samples_lf_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_Lf[i],samples_lf_decri[j], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_Lf[j], retStd, strStd);
            fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_Lf[j], retSec, strSec);
#endif
#if SCREEN_PRINT
            if(flag)
            {
                SPRINTF(format_Lf[i],flag_Lf[j],samples_lf_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
            }
#endif
            j++;
        }
        i++;
    }
    printf("%s\n", "%Lf test end");
#endif
    fprintf(fStd, "-------------------------------f test end--------------------------- \n");
    fprintf(fSec, "-------------------------------f test end--------------------------- \n");
}

void test_printf_format_f_2(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

        char *formats[] = {
                "%-10f",
                "%-20f",
                "%+10f",
                "%+20f",
                "% 10f",
                "% 20f",
                "%010f",
                "%020f",
                "%.2f",
                "%.8f",
                /*"%'f",*/
                NULL
        };

        double sample[] = 
        {
                -3.4e+38,
                3.1415926e+00,
                3.4e+38,
                0
        };

        char *flag[][2] = 
        {
                {"-3.4e+38",       "edge"  },
                {"3.1415926e+00",       "normal" },
                {"3.4e+38",      "edge"  }
        };

        int isdiff=0;
        int retc, rets;
        char stdbuf[256];
        char secbuf[256];
        int k=0;
        int m=0;

        fprintf(fstd, "-------------------------------f test 2 begin--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------f test 2 begin--------------------------- \n"); /*lint !e668*/

        k = 0;
        while(formats[k] != NULL)
        {
                m = 0;
                while(sample[m] < -1.0  || sample[m] > 1.0)
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

        fprintf(fstd, "-------------------------------f test 2 end--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------f test 2 end--------------------------- \n"); /*lint !e668*/

}

void test_printf_format_g(FILE* fStd, FILE* fSec)
{
    char strStd[MAX_BUFF_SIZE] = {0x00};
    char strSec[MAX_BUFF_SIZE] = {0x00};

    int i = 0;
    int j = 0;
    int retStd = 0;
    int retSec = 0;

    int flag = 0; /* 0 means same, and 1 means different */

    char* format_g[] = 
    {
        "%g", "%#.0g", "%.0g", "%.2g", "%.6g", "%.gf",/*"%'g",*/
        NULL
    };

    double samples_g[] = 
    {
        3.1415926e+00, 
        3.1415926e+38, 
        3.4e+38,        
        -3.4e+38,
#if OVERFLOW_MARK
        3.5e+38,
        -3.5e+38,
#endif
        0
    };

    char* flag_g[] = 
    {
        "3.1415926e+00", 
        "3.1415926e+38", 
        "3.4e+38",        
        "-3.4e+38",
#if OVERFLOW_MARK
        "3.5e+38",
        "-3.5e+38",
#endif
        NULL
    };

    char *samples_g_decri[] =
    {
        "normal",
        "normal",
        "edge",
        "edge",
#if OVERFLOW_MARK
        "overflow(long double)",
        "overflow(long double)",
#endif
        NULL
    };

    char* format_lg[] = 
    {
        "%lg", 
        NULL
    };


    double samples_lg[] = 
    {
        3.1415926e+00,
        1.79e+308,/* linux64 crash */    
        -1.79e+308,/* linux64 crash */
#if OVERFLOW_MARK
        /* 1.80e+308,*/
        /* -1.89e+308, */
#endif
        0
    };

    char* flag_lg[] = 
    {
        "3.1415926e+00",
        "1.79e+308",/* linux64 crash */    
        "-1.79e+308",/* linux64 crash */
#if OVERFLOW_MARK
        /* "1.80e+308",*/
        /* "-1.89e+308", */
#endif
        NULL
    };

    char* format_Lg[] =  /* the same to lg*/
    {
        "%Lg",
        NULL
    };
#ifndef VXWORKS_CAVIUM_5434
    long double samples_Lg[] = 
    {
        3.1415926e+00,
        1.79e+308, 
        -1.79e+308,
#if OVERFLOW_MARK
        /* 1.80e+308,*/
        /* -1.89e+308, */
#endif
        0
    };

    char* flag_Lg[] = 
    {
        "3.1415926e+00",
        "1.79e+308", 
        "-1.79e+308",
#if OVERFLOW_MARK
        /* "1.80e+308",*/
        /* "-1.89e+308", */
#endif
        NULL
    };
#endif
    char *samples_lg_decri[] =
    {
        "normal",
        "edge",
        "edge",
#if OVERFLOW_MARK
        /* "overflow(long double)", */
        /* "overflow(long double)", */
#endif
        NULL
    };

    printf("%s\n", "%g test begin");
    fprintf(fStd, "-------------------------------g test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------g test begin--------------------------- \n"); /*lint !e668*/
    i = 0;
    while(NULL != format_g[i])
    {
        j = 0;
        while((0 != samples_g[j]) && (NULL != samples_g_decri[j]))
        {
            retStd = 0;
            retSec = 0;
            flag = 0;
            memset(strStd, 0, MAX_BUFF_SIZE);
            memset(strSec, 0, MAX_BUFF_SIZE);

            /* std function */
            retStd = sprintf(strStd, format_g[i], samples_g[j]);

            /* sec function */
            retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_g[i], samples_g[j]);

            /* compare result */
            if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_g[i], samples_g_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_g[i], samples_g_decri[j]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_g[i], samples_g_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_g[i],samples_g_decri[j], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_g[j], retStd, strStd);
            fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_g[j], retSec, strSec);
#endif
#if SCREEN_PRINT
            if(flag)
            {
                SPRINTF(format_g[i],flag_g[j],samples_g_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
            }
#endif
            j++;
        }
        i++;
    }

    printf("%s\n", "%g test end");

    printf("%s\n", "%lg test begin");

    i = 0;
    while(NULL != format_lg[i])
    {
        j = 0;
        while((0 != samples_lg[j]) && (NULL != samples_lg_decri[j]))
        {
            retStd = 0;
            retSec = 0;
            flag = 0;
            memset(strStd, 0, MAX_BUFF_SIZE);
            memset(strSec, 0, MAX_BUFF_SIZE);

            /* std function */
            retStd = sprintf(strStd, format_lg[i], samples_lg[j]);

            /* sec function */
            retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_lg[i], samples_lg[j]);

            /* compare result */
            if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_lg[i], samples_lg_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_lg[i], samples_lg_decri[j]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_lg[i], samples_lg_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_lg[i],samples_lg_decri[j], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_lg[j], retStd, strStd);
            fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_lg[j], retSec, strSec);
#endif
#if SCREEN_PRINT
            if(flag)
            {
                SPRINTF(format_lg[i],flag_lg[j],samples_lg_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
            }
#endif
            j++;
        }
        i++;
    }

    printf("%s\n", "%lg test end");
#ifndef VXWORKS_CAVIUM_5434
    printf("%s\n", " %Lg test begin");
    i = 0;
    while(NULL != format_Lg[i])
    {
        j = 0;
        while((0 != samples_Lg[j]) && (NULL != samples_lg_decri[j]))
        {
            retStd = 0;
            retSec = 0;
            flag = 0;
            memset(strStd, 0, MAX_BUFF_SIZE);
            memset(strSec, 0, MAX_BUFF_SIZE);

            /* std function */
            retStd = sprintf(strStd, format_Lg[i], samples_Lg[j]);

            /* sec function */
            retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_Lg[i], samples_Lg[j]);

            /* compare result */
            if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_Lg[i], samples_lg_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_Lg[i], samples_lg_decri[j]);
            }
            else  /* different */
            {
                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_Lg[i], samples_lg_decri[j]);
                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_Lg[i],samples_lg_decri[j], __LINE__);
            }

            /* output the input, output and return value */
            fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_Lg[j], retStd, strStd);
            fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_Lg[j], retSec, strSec);
#endif
#if SCREEN_PRINT
            if(flag)
            {
                SPRINTF(format_Lg[i],flag_Lg[j],samples_lg_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
            }
#endif
            j++;
        }
        i++;
    }

    printf("%s\n", " %Lg test end");
#endif
    fprintf(fStd, "-------------------------------g test end--------------------------- \n");
    fprintf(fSec, "-------------------------------g test end--------------------------- \n");

}

void test_printf_format_g_2(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

        char *formats[] = {
                "%-10g",
                "%-20g",
                "%+10g",
                "%+20g",
                "% 10g",
                "% 20g",
                "%010g",
                "%020g",
                "%.2g",
                "%.8g",
                NULL
        };

        double sample[] = 
        {
                -3.4e+38,
                3.1415926e+00,
                3.4e+38,
                0
        };

        char *flag[][2] = 
        {
                {"-3.4e+38",       "edge"  },
                {"3.1415926e+00",       "normal" },
                {"3.4e+38",      "edge"  }
        };

        int isdiff=0;
        int retc, rets;
        char stdbuf[256];
        char secbuf[256];
        int k=0;
        int m=0;

        fprintf(fstd, "-------------------------------g test 2 begin--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------g test 2 begin--------------------------- \n"); /*lint !e668*/

        k = 0;
        while(formats[k] != NULL)
        {
                m = 0;
                while(sample[m] < -1.0  || sample[m] > 1.0)
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

        fprintf(fstd, "-------------------------------g test 2 end--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------g test 2 end--------------------------- \n"); /*lint !e668*/

}


void test_printf_format_E_2(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

        char *formats[] = {
                "%-10E",
                "%-20E",
                "%+10E",
                "%+20E",
                "% 10E",
                "% 20E",
                "%010E",
                "%020E",
                "%.2E",
                "%.8E",
                NULL
        };

        double sample[] = 
        {
                -3.4e+38,
                3.1415926e+00,
                3.4e+38,
                0
        };

        char *flag[][2] = 
        {
                {"-3.4e+38",       "edge"  },
                {"3.1415926e+00",       "normal" },
                {"3.4e+38",      "edge"  }
        };

        int isdiff=0;
        int retc, rets;
        char stdbuf[256];
        char secbuf[256];
        int k=0;
        int m=0;

        fprintf(fstd, "-------------------------------E test 2 begin--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------E test 2 begin--------------------------- \n"); /*lint !e668*/

        k = 0;
        while(formats[k] != NULL)
        {
                m = 0;
                while(sample[m] < -1.0  || sample[m] > 1.0)
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

        fprintf(fstd, "-------------------------------E test 2 end--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------E test 2 end--------------------------- \n"); /*lint !e668*/

}

void test_printf_format_E(FILE* fStd, FILE* fSec)
{
        char strStd[MAX_BUFF_SIZE] = {0x00};
        char strSec[MAX_BUFF_SIZE] = {0x00};

        int i = 0;
        int j = 0;
        int retStd = 0;
        int retSec = 0;

        int flag = 0; /* 0 means same, and 1 means different */

        char* format_e[] = 
        {
                "%E", "%#.0E", "%.0E","%.2E", "%.6E", "%.7E",
                NULL
        };

        double samples_e[] = 
        {
                3.1415926e+00, 
                3.4e+38,        
                -3.4e+38,
#if OVERFLOW_MARK
                3.5e+38,
                -3.5e+38,
#endif
                0
        };

        char* flag_e[] = 
        {
                "3.1415926e+00", 
                "3.4e+38",        
                "-3.4e+38",
#if OVERFLOW_MARK
                "3.5e+38",
                "-3.5e+38",
#endif
                NULL
        };

        char *samples_e_decri[] =
        {
                "normal",
                "edge",       
                "edge",
#if OVERFLOW_MARK
                "overflow(long double)",
                "overflow(long double)",
#endif
                NULL
        };

        char* format_le[] = 
        {
                "%lE", 
                NULL
        };

        double samples_le[] = 
        {
                3.1415926e+00,
                1.79e+308,
                -1.79e+308,
#if OVERFLOW_MARK
                /* 1.80e+308,*/
                /* -1.89e+308, */
#endif
                0
        };

        char* flag_le[] = 
        {
                "3.1415926e+00",
                "1.79e+308",
                "-1.79e+308",
#if OVERFLOW_MARK
                /* "1.80e+308",*/
                /* "-1.89e+308", */
#endif
                NULL
        };
#ifndef VXWORKS_CAVIUM_5434
        char* format_Le[] = /* this same to le*/
        {         
                "%LE",
                NULL
        };

        long double samples_Le[] = 
        {
                3.1415926e+00,
                1.79e+308,        
                -1.79e+308,
#if OVERFLOW_MARK
                /* 1.80e+308,*/
                /* -1.89e+308, */
#endif
                0
        };

        char* flag_Le[] = 
        {
                "3.1415926e+00",
                "1.79e+308",        
                "-1.79e+308",
#if OVERFLOW_MARK
                /* "1.80e+308",*/
                /* "-1.89e+308", */
#endif
                NULL
        };
#endif
        char *samples_le_decri[] =
        {
                "normal",
                "edge",       
                "edge",
#if OVERFLOW_MARK
                /* "overflow(long double)", */
                /* "overflow(long double)", */
#endif
                NULL
        };

        printf("%s\n", "%E test begin");
        fprintf(fStd, "-------------------------------E test begin--------------------------- \n"); /*lint !e668*/
        fprintf(fSec, "-------------------------------E test begin--------------------------- \n"); /*lint !e668*/

        i = 0;
        while(NULL != format_e[i])
        {
                j = 0;
                while((0 != samples_e[j]) && (NULL != samples_e_decri[j]))
                {
                        retStd = 0;
                        retSec = 0;
                        flag = 0;
                        memset(strStd, 0, MAX_BUFF_SIZE);
                        memset(strSec, 0, MAX_BUFF_SIZE);

                        /* std function */
                        retStd = sprintf(strStd, format_e[i], samples_e[j]);

                        /* sec function */
                        retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_e[i], samples_e[j]);

                        /* compare result */
                        if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_e[i], samples_e_decri[j]);
                                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_e[i], samples_e_decri[j]);
                        }
                        else  /* different */
                        {
                                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_e[i], samples_e_decri[j]);
                                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_e[i],samples_e_decri[j], __LINE__);
                        }

                        /* output the input, output and return value */
                        fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_e[j], retStd, strStd);
                        fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_e[j], retSec, strSec);
#endif
#if SCREEN_PRINT
                        if(flag)
                        {
                                SPRINTF(format_e[i],flag_e[j],samples_e_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
                        }
#endif
                        j++;
                }
                i++;
        }

        printf("%s\n", "%E test end");

        printf("%s\n", "%lE test begin");

        i = 0;
        while(NULL != format_le[i])
        {
                j = 0;
                while((0 != samples_le[j]) && (NULL != samples_le_decri[j]))
                {
                        retStd = 0;
                        retSec = 0;
                        flag = 0;
                        memset(strStd, 0, MAX_BUFF_SIZE);
                        memset(strSec, 0, MAX_BUFF_SIZE);

                        /* std function */
                        retStd = sprintf(strStd, format_le[i], samples_le[j]);

                        /* sec function */
                        retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_le[i], samples_le[j]);

                        /* compare result */
                        if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_le[i], samples_le_decri[j]);
                                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_le[i], samples_le_decri[j]);
                        }
                        else  /* different */
                        {
                                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_le[i], samples_le_decri[j]);
                                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_le[i],samples_le_decri[j], __LINE__);
                        }

                        /* output the input, output and return value */
                        fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_le[j], retStd, strStd);
                        fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_le[j], retSec, strSec);
#endif
#if SCREEN_PRINT
                        if(flag)
                        {
                                SPRINTF(format_le[i],flag_le[j],samples_le_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
                        }
#endif
                        j++;
                }
                i++;
        }

        printf("%s\n", "%lE test end");
#ifndef VXWORKS_CAVIUM_5434
        printf("%s\n", "%Le test begin");
        i = 0;
        while(NULL != format_Le[i])
        {
                j = 0;
                while((0 != samples_Le[j]) && (NULL != samples_le_decri[j]))
                {
                        retStd = 0;
                        retSec = 0;
                        flag = 0;
                        memset(strStd, 0, MAX_BUFF_SIZE);
                        memset(strSec, 0, MAX_BUFF_SIZE);

                        /* std function */
                        retStd = sprintf(strStd, format_Le[i], samples_Le[j]);

                        /* sec function */
                        retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_Le[i], samples_Le[j]);

                        /* compare result */
                        if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_Le[i], samples_le_decri[j]);
                                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_Le[i], samples_le_decri[j]);
                        }
                        else  /* different */
                        {
                                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_Le[i], samples_le_decri[j]);
                                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_Le[i],samples_le_decri[j], __LINE__);
                        }
                        /* output the input, output and return value */
                        fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_Le[j], retStd, strStd);
                        fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_Le[j], retSec, strSec);
#endif
#if SCREEN_PRINT
                        if(flag)
                        {
                                SPRINTF(format_Le[i],flag_Le[j],samples_le_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
                        }
#endif
                        j++;
                }
                i++;
        }
        printf("%s\n", "%Le test end");
#endif
        fprintf(fStd, "-------------------------------E test end--------------------------- \n");
        fprintf(fSec, "-------------------------------E test end--------------------------- \n");
}

void test_printf_format_G(FILE* fStd, FILE* fSec)
{
        char strStd[MAX_BUFF_SIZE] = {0x00};
        char strSec[MAX_BUFF_SIZE] = {0x00};

        int i = 0;
        int j = 0;
        int retStd = 0;
        int retSec = 0;

        int flag = 0; /* 0 means same, and 1 means different */

        char* format_g[] = 
        {
                "%G", "%#.0G", "%.0G", "%.2G", "%.6G", "%.Gf",/*"%'G",*/
                NULL
        };

        double samples_g[] = 
        {
                3.1415926e+00, 
                3.1415926e+38, 
                3.4e+38,        
                -3.4e+38,
#if OVERFLOW_MARK
                3.5e+38,
                -3.5e+38,
#endif
                0
        };

        char* flag_g[] = 
        {
                "3.1415926e+00", 
                "3.1415926e+38", 
                "3.4e+38",        
                "-3.4e+38",
#if OVERFLOW_MARK
                "3.5e+38",
                "-3.5e+38",
#endif
                NULL
        };

        char *samples_g_decri[] =
        {
                "normal",
                "normal",
                "edge",
                "edge",
#if OVERFLOW_MARK
                "overflow(long double)",
                "overflow(long double)",
#endif
                NULL
        };

        char* format_lg[] = 
        {
                "%lG", 
                NULL
        };


        double samples_lg[] = 
        {
                3.1415926e+00,
                1.79e+308,/* linux64 crash */    
                -1.79e+308,/* linux64 crash */
#if OVERFLOW_MARK
                /* 1.80e+308,*/
                /* -1.89e+308, */
#endif
                0
        };

        char* flag_lg[] = 
        {
                "3.1415926e+00",
                "1.79e+308",/* linux64 crash */    
                "-1.79e+308",/* linux64 crash */
#if OVERFLOW_MARK
                /* "1.80e+308",*/
                /* "-1.89e+308", */
#endif
                NULL
        };
#ifndef VXWORKS_CAVIUM_5434
        char* format_Lg[] =  /* the same to lg*/
        {
                "%LG",
                NULL
        };

        long double samples_Lg[] = 
        {
                3.1415926e+00,
                1.79e+308, 
                -1.79e+308,
#if OVERFLOW_MARK
                /* 1.80e+308,*/
                /* -1.89e+308, */
#endif
                0
        };

        char* flag_Lg[] = 
        {
                "3.1415926e+00",
                "1.79e+308", 
                "-1.79e+308",
#if OVERFLOW_MARK
                /* "1.80e+308",*/
                /* "-1.89e+308", */
#endif
                NULL
        };
#endif
        char *samples_lg_decri[] =
        {
                "normal",
                "edge",
                "edge",
#if OVERFLOW_MARK
                /* "overflow(long double)", */
                /* "overflow(long double)", */
#endif
                NULL
        };

        printf("%s\n", "%G test begin");
        fprintf(fStd, "-------------------------------G test begin--------------------------- \n"); /*lint !e668*/
        fprintf(fSec, "-------------------------------G test begin--------------------------- \n"); /*lint !e668*/
        i = 0;
        while(NULL != format_g[i])
        {
                j = 0;
                while((0 != samples_g[j]) && (NULL != samples_g_decri[j]))
                {
                        retStd = 0;
                        retSec = 0;
                        flag = 0;
                        memset(strStd, 0, MAX_BUFF_SIZE);
                        memset(strSec, 0, MAX_BUFF_SIZE);

                        /* std function */
                        retStd = sprintf(strStd, format_g[i], samples_g[j]);

                        /* sec function */
                        retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_g[i], samples_g[j]);

                        /* compare result */
                        if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_g[i], samples_g_decri[j]);
                                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_g[i], samples_g_decri[j]);
                        }
                        else  /* different */
                        {
                                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_g[i], samples_g_decri[j]);
                                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_g[i],samples_g_decri[j], __LINE__);
                        }

                        /* output the input, output and return value */
                        fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_g[j], retStd, strStd);
                        fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_g[j], retSec, strSec);
#endif
#if SCREEN_PRINT
                        if(flag)
                        {
                                SPRINTF(format_g[i],flag_g[j],samples_g_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
                        }
#endif
                        j++;
                }
                i++;
        }

        printf("%s\n", "%G test end");

        printf("%s\n", "%lG test begin");

        i = 0;
        while(NULL != format_lg[i])
        {
                j = 0;
                while((0 != samples_lg[j]) && (NULL != samples_lg_decri[j]))
                {
                        retStd = 0;
                        retSec = 0;
                        flag = 0;
                        memset(strStd, 0, MAX_BUFF_SIZE);
                        memset(strSec, 0, MAX_BUFF_SIZE);

                        /* std function */
                        retStd = sprintf(strStd, format_lg[i], samples_lg[j]);

                        /* sec function */
                        retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_lg[i], samples_lg[j]);

                        /* compare result */
                        if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_lg[i], samples_lg_decri[j]);
                                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_lg[i], samples_lg_decri[j]);
                        }
                        else  /* different */
                        {
                                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_lg[i], samples_lg_decri[j]);
                                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_lg[i],samples_lg_decri[j], __LINE__);
                        }

                        /* output the input, output and return value */
                        fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_lg[j], retStd, strStd);
                        fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_lg[j], retSec, strSec);
#endif
#if SCREEN_PRINT
                        if(flag)
                        {
                                SPRINTF(format_lg[i],flag_lg[j],samples_lg_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
                        }
#endif
                        j++;
                }
                i++;
        }

        printf("%s\n", "%lG test end");
#ifndef VXWORKS_CAVIUM_5434
        printf("%s\n", " %LG test begin");
        i = 0;
        while(NULL != format_Lg[i])
        {
                j = 0;
                while((0 != samples_Lg[j]) && (NULL != samples_lg_decri[j]))
                {
                        retStd = 0;
                        retSec = 0;
                        flag = 0;
                        memset(strStd, 0, MAX_BUFF_SIZE);
                        memset(strSec, 0, MAX_BUFF_SIZE);

                        /* std function */
                        retStd = sprintf(strStd, format_Lg[i], samples_Lg[j]);

                        /* sec function */
                        retSec = sprintf_s(strSec, MAX_BUFF_SIZE, format_Lg[i], samples_Lg[j]);

                        /* compare result */
                        if((retSec == retStd) && (0 == strcmp(strStd, strSec)))
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
                                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_Lg[i], samples_lg_decri[j]);
                                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Equal\n", format_Lg[i], samples_lg_decri[j]);
                        }
                        else  /* different */
                        {
                                fprintf(fStd, "Expression:sprintf-(%s)-%s comparedResult:Different\n", format_Lg[i], samples_lg_decri[j]);
                                fprintf(fSec, "Expression:sprintf-(%s)-%s comparedResult:Different (%d)\n", format_Lg[i],samples_lg_decri[j], __LINE__);
                        }

                        /* output the input, output and return value */
                        fprintf(fStd, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_Lg[j], retStd, strStd);
                        fprintf(fSec, "input value:%s\nreturn value :%d\noutput value:%s\n\n", flag_Lg[j], retSec, strSec);
#endif
#if SCREEN_PRINT
                        if(flag)
                        {
                                SPRINTF(format_Lg[i],flag_Lg[j],samples_lg_decri[j],retStd,retSec,strStd,strSec,(long unsigned)__LINE__);
                        }
#endif
                        j++;
                }
                i++;
        }

        printf("%s\n", " %Lg test end");
#endif
        fprintf(fStd, "-------------------------------G test end--------------------------- \n");
        fprintf(fSec, "-------------------------------G test end--------------------------- \n");

}

void test_printf_format_G_2(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

        char *formats[] = {
                "%-10G",
                "%-20G",
                "%+10G",
                "%+20G",
                "% 10G",
                "% 20G",
                "%010G",
                "%020G",
                "%.2G",
                "%.8G",
                NULL
        };

        double sample[] = 
        {
                -3.4e+38,
                3.1415926e+00,
                3.4e+38,
                0
        };

        char *flag[][2] = 
        {
                {"-3.4e+38",       "edge"  },
                {"3.1415926e+00",       "normal" },
                {"3.4e+38",      "edge"  }
        };

        int isdiff=0;
        int retc, rets;
        char stdbuf[256];
        char secbuf[256];
        int k=0;
        int m=0;

        fprintf(fstd, "-------------------------------G test 2 begin--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------G test 2 begin--------------------------- \n"); /*lint !e668*/

        k = 0;
        while(formats[k] != NULL)
        {
                m = 0;
                while(sample[m] < -1.0  || sample[m] > 1.0)
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

        fprintf(fstd, "-------------------------------G test 2 end--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------G test 2 end--------------------------- \n"); /*lint !e668*/

}


void test_printf_format_float_Xing(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

        char *formats[] = {
                "%*e",
                /*"%2$*1$e",*/
                "%*E",
                /*"%2$*1$E",*/
                "%*f",
               /* "%2$*1$f",*/
                "%*F",
               /* "%2$*1$F",*/
                "%*g",
               /* "%2$*1$g",*/
                "%*G",
               /* "%2$*1$G",*/
                NULL
        };

        double sample[] = 
        {
                -3.4e+38,
                3.1415926e+00,
                3.4e+38,
                0
        };

        char *flag[][2] = 
        {
                {"-3.4e+38",       "edge"  },
                {"3.1415926e+00",       "normal" },
                {"3.4e+38",      "edge"  }
        };

        int isdiff=0;
        int retc, rets;
        char stdbuf[256];
        char secbuf[256];
        int k=0;
        int m=0;

        fprintf(fstd, "-------------------------------* $ test begin--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------* $ test begin--------------------------- \n"); /*lint !e668*/

        k = 0;
        while(formats[k] != NULL)
        {
                m = 0;
                while(sample[m] < -1.0  || sample[m] > 1.0)
                {
                        isdiff = 0;
                        memset(stdbuf, 1, sizeof(stdbuf));
                        memset(secbuf, 1, sizeof(secbuf));
                        /* print out standard c function result */
                        retc = sprintf(stdbuf, formats[k], 4, sample[m]);
                        /* print out secure c function result */
                        rets = sprintf_s(secbuf, sizeof(secbuf), formats[k], 4, sample[m]);
                        /* compare the results */
                        isdiff = memcmp(stdbuf, secbuf, 32);
                        outputdataprintf(fstd, fsec, formats[k], flag[m][0], flag[m][1], retc, rets, isdiff, 
                                stdbuf, secbuf, __LINE__);
                        m++;
                }

                k++;
        }

#endif

        fprintf(fstd, "-------------------------------* $  test end--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------* $  test end--------------------------- \n"); /*lint !e668*/

}

void test_printf_format_F(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

        char *formats[] = {
                "%F",
                "%-10F",
                "%-20F",
                "%+10F",
                "%+20F",
                "% 10F",
                "% 20F",
                "%010F",
                "%020F",
                "%#10F",
                "%#20F",
                "%.2F",
                "%.8F",
                /*"%'F",*/
                NULL
        };

        double sample[] = 
        {
                -3.4e+38,
                3.1415926e+00,
                3.4e+38,
                0
        };

        char *flag[][2] = 
        {
                {"-3.4e+38",       "edge"  },
                {"3.1415926e+00",       "normal" },
                {"3.4e+38",      "edge"  }
        };

        int isdiff=0;
        int retc, rets;
        char stdbuf[256];
        char secbuf[256];
        int k=0;
        int m=0;

        fprintf(fstd, "-------------------------------F test begin--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------F test begin--------------------------- \n"); /*lint !e668*/

        k = 0;
        while(formats[k] != NULL)
        {
                m = 0;
                while(sample[m] < -1.0  || sample[m] > 1.0)
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

        fprintf(fstd, "-------------------------------F test end--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------F test end--------------------------- \n"); /*lint !e668*/

}

void test_printf_format_F_2(FILE *fstd, FILE *fsec)
{
#if !(defined(__SOLARIS))/*(defined(COMPATIBLE_LINUX_FORMAT))*/

        char *formats[] = {
                "%LF",
                NULL
        };

        double sample[] = 
        {
                -1.79e+38,
                3.1415926e+00,
                1.79e+38,
                0
        };

        char *flag[][2] = 
        {
                {"-1.79e+308",       "edge"  },
                {"3.1415926e+00",       "normal" },
                {"1.79e+308",      "edge"  }
        };

        int isdiff=0;
        int retc, rets;
        char stdbuf[256];
        char secbuf[256];
        int k=0;
        int m=0;

        fprintf(fstd, "-------------------------------F test 2 begin--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------F test 2 begin--------------------------- \n"); /*lint !e668*/

        k = 0;
        while(formats[k] != NULL)
        {
                m = 0;
                while(sample[m] < -1.0  || sample[m] > 1.0)
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

        fprintf(fstd, "-------------------------------F test 2 end--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------F test 2 end--------------------------- \n"); /*lint !e668*/

}
