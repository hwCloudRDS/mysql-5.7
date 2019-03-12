#include "securec.h"
#include "testutil.h"
#include "comp_funcs.h"
#include <string.h>
#include <locale.h>
#include <stdio.h>
#ifndef SECUREC_VXWORKS_PLATFORM
#include <wchar.h>
#endif

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

int indirect_swprintf(wchar_t *string, size_t sizeInWords, const wchar_t* format, ...);

/*not win ,not vxworks*/
#if ( !(defined(SECUREC_VXWORKS_PLATFORM)) && !(defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER)) ) 
int indirect_swprintf_sys(wchar_t *string, size_t sizeInWords, const wchar_t* format, ...)
{
    va_list args;
    int ret = 0;
    
    va_start( args, format );
    ret = vswprintf(string, sizeInWords, format, args ) ;
    va_end(args);
    return ret;
    
}
void test_vswprintf_format_s(FILE *fstd, FILE *fsec)
{
    char* oriLocale = NULL;  
    char* newLocale = NULL; 

    oriLocale = setlocale(0, NULL);
    newLocale = setlocale(0,"zh_CN.UTF-8");

    wchar_t *formatsw[] = {/* 涓枃 */
        L"%s",
        NULL
    };
    wchar_t samplew[] = L"中文";
    char    sample[]  = "中文";

    int m = 0;
    int isdiff = 0;
    wchar_t stdbuf[32];
    wchar_t secbuf[32];
    char fmt[32];
    char smp[32];
    int i, len;
    int retc;
    int rets;

    fprintf(fstd, "-------------------------------vswprintf s test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------vswprintf s test begin--------------------------- \n"); /*lint !e668*/
    
    while(formatsw[m] != NULL)
    {
        isdiff = 0;
        memset(stdbuf, 0, sizeof(stdbuf));
        memset(secbuf, 0, sizeof(secbuf));

        retc = indirect_swprintf_sys(stdbuf, 32,formatsw[m], sample);
        rets = indirect_swprintf(secbuf, 32, formatsw[m], sample);
        /*
        wprintf(L"%s\n", stdbuf);
        wprintf(L"%d\n",stdbuf[0]);
        wprintf(L"%d\n",stdbuf[1]);
        wprintf(L"%d\n",stdbuf[2]);
        wprintf(L"%d\n",stdbuf[3]);
        wprintf(L"%d\n",stdbuf[4]);

        wprintf(L"%s\n", secbuf);
        wprintf(L"%d\n",secbuf[0]);
        wprintf(L"%d\n",secbuf[1]);
        wprintf(L"%d\n",secbuf[2]);
        wprintf(L"%d\n",secbuf[3]);
        wprintf(L"%d\n",secbuf[4]);
        */
        /*
        fputws (L"sys:", stdout );
        fputws ( stdbuf, stdout );
        fputws ( L"\n", stdout );
        fputws (L"sec:", stdout );
        fputws ( secbuf, stdout );
        fputws ( L"\n", stdout );       
        */
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

        OutputTestResult("vswprintf", fstd, fsec, fmt, smp, "normal", retc, rets, isdiff, 
            (char*)stdbuf, sizeof(stdbuf), (char*)secbuf, sizeof(secbuf), __LINE__);
        m++;
    }

    (void)setlocale(0, oriLocale);    /*restore original locale*/

    fprintf(fstd, "-------------------------------vswprintf s test end--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------vswprintf s test end--------------------------- \n"); /*lint !e668*/
}
#endif

