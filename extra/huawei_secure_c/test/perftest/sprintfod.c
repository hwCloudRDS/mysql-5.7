/*******************************************************************************
* Copyright @ Huawei Technologies Co., Ltd. 1998-2014. All rights reserved.  
* File name: snprintf.c
* History:   
*     1. Date:
*         Author:    
*         Modification:
********************************************************************************
*/

#include <math.h>

#include "securec.h"
#include "securecutil.h"
#include <stdarg.h>
#include <string.h>
#include "secureprintoutput.h"
#include <stdio.h>

/***************************/
/*remove this def style #define TCHAR char*/
typedef char TCHAR;
#define _T(x) x
#define write_char write_char_a
#define write_multi_char write_multi_char_a
#define write_string write_string_a
/***************************/

/*extern const UINT8T securec__lookuptable_s[];*/

static char* cvt(double arg, long double longarg, int ndigits, int* decpt, int* sign, char* buf, int eflag, int longflag)
{
    int r2;
    double fi, fj;
#if defined(COMPATIBLE_LINUX_FORMAT)
    long double fil, fjl;
#endif
    char* p, *p1;

    if (ndigits < 0)
    {
        ndigits = 0;
    }
    if ((longflag == 0) && (ndigits >= CVTBUFSIZE - 1))
    {
        ndigits = CVTBUFSIZE - 2;
    }
    else if ((longflag == 1) && (ndigits >= CVTBUFSIZE_LB - 1))
    {
        ndigits = CVTBUFSIZE_LB - 2;
    }

    r2 = 0;
    *sign = 0;
    p = &buf[0];
#if defined(COMPATIBLE_LINUX_FORMAT)
    if(longflag == 1)
    {
        if (longarg < 0)
        {
            *sign = 1;
            longarg = -longarg;
        }
        longarg = modfl(longarg, &fil);
        p1 = &buf[CVTBUFSIZE_LB];

        if (fil != 0)
        {
            p1 = &buf[CVTBUFSIZE_LB];
            while (fil != 0 && p1 > buf)    _CHECK_BUFFER_OVERLAP
            {
                fjl = modfl(fil / 10, &fil);
                *--p1 = (int)((fjl + .03) * 10) + '0'; /*lint !e734, it should be '0'-'9'*/
                r2++;
            }
            while (p1 < &buf[CVTBUFSIZE_LB] )    _CHECK_BUFFER_OVERLAP
            {
                *p++ = *p1++;
            }
        }
        else if (longarg > 0)
        {
            while ((fjl = longarg * 10) < 1)
            {
                longarg = fjl;
                r2--;
            }
        }
    }
    else if (longflag == 0)
#endif
    {
        if (arg < 0)
        {
            *sign = 1;
            arg = -arg;
        }
        arg = modf(arg, &fi);
        
        p1 = &buf[CVTBUFSIZE];

        if (fi != 0)
        {
            p1 = &buf[CVTBUFSIZE];
            while (fi != 0 && p1 > buf)    _CHECK_BUFFER_OVERLAP
            {
                fj = modf(fi / 10, &fi);
                *--p1 = (int)((fj + .03) * 10) + '0'; /*lint !e734, it should be '0'-'9'*/
                r2++;
            }
            while (p1 < &buf[CVTBUFSIZE] )    _CHECK_BUFFER_OVERLAP
            {
                *p++ = *p1++;
            }
        }
        else if (arg > 0)
        {
            while ((fj = arg * 10) < 1)
            {
                arg = fj;
                r2--;
            }
        }
    }

    p1 = &buf[ndigits];
    if (eflag == 0) 
    {
        p1 += r2; 
    }
    *decpt = r2;
    if (p1 < &buf[0])    _CHECK_BUFFER_OVERLAP
    {
        buf[0] = '\0';
        return buf;
    }
#if defined(COMPATIBLE_LINUX_FORMAT)
    if (longflag == 1)
    {
        while (p <= p1 && p < &buf[CVTBUFSIZE_LB])    _CHECK_BUFFER_OVERLAP
        {
            longarg *= 10;
            longarg = modfl(longarg, &fjl);
            *p++ = (int) fjl + '0';  /*lint !e734*/
        }
        if (p1 >= &buf[CVTBUFSIZE_LB])    _CHECK_BUFFER_OVERLAP
        {
            buf[CVTBUFSIZE_LB - 1] = '\0';
            return buf;
        }
    }
    else if (longflag == 0)
#endif
    {
        while (p <= p1 && p < &buf[CVTBUFSIZE])    _CHECK_BUFFER_OVERLAP
        {
            arg *= 10;
            arg = modf(arg, &fj);
            *p++ = (int) fj + '0';  /*lint !e734*/
        }
        if (p1 >= &buf[CVTBUFSIZE])    _CHECK_BUFFER_OVERLAP
        {
            buf[CVTBUFSIZE - 1] = '\0';
            return buf;
        }
    }
    p = p1;
    *p1 += 5;
    while (*p1 > '9')
    {
        *p1 = '0';
        if (p1 > buf)    _CHECK_BUFFER_OVERLAP
        {
            ++*--p1;
        }
        else
        {
            *p1 = '1';
            (*decpt)++;
            if (eflag == 0)
            {
                if (p > buf)    _CHECK_BUFFER_OVERLAP
                {
                    *p = '0'; 
                }
                p++;
            }
        }
    }
    *p = '\0';
    return buf;
}

static char* ecvtbuf_hw(double arg, long double longvalue, int ndigits, int* decpt, int* sign, char* buf, int longflag)
{
    return cvt(arg, longvalue, ndigits, decpt, sign, buf, 1, longflag);
}

static char* fcvtbuf_hw(double arg, long double longvalue, int ndigits, int* decpt, int* sign, char* buf, int longflag)
{
    return cvt(arg, longvalue, ndigits, decpt, sign, buf, 0, longflag);
}

void cfltcvt(double value, long double longvalue, char* buffer, int bufSize, char fmt, int precision, int capexp, int longflag)
{
    int decpt, sign, expVal, pos;
    char* digits = NULL;
    char *cvtbuf = NULL;
    char* oriPos = buffer;
    int magnitude;
    char oriFmt = fmt;
    int littleDigit = 0;
    char* gPos = NULL;

#if defined(COMPATIBLE_LINUX_FORMAT)
    if (longflag)
    {
        cvtbuf = (char *)malloc(CVTBUFSIZE_LB);
    }
    else
#endif
    {
        cvtbuf = (char *)malloc(CVTBUFSIZE);
    }
    if (NULL == cvtbuf)
    {
        buffer[0] = '\0';
        return;
    }
    if (fmt == 'g')
    {
        /*digits =*/
        (void)ecvtbuf_hw(value, longvalue, precision, &decpt, &sign, cvtbuf, longflag);
        magnitude = decpt - 1;
        if (magnitude < -4  ||  magnitude > precision - 1)
        {
            fmt = 'e';
            precision -= 1;
        }
        else
        {
            fmt = 'f';
            precision -= decpt;
        }
    }

    if (fmt == 'e')
    {
        digits = ecvtbuf_hw(value, longvalue, precision + 1, &decpt, &sign, cvtbuf, longflag);

        if (sign) 
        { 
            *buffer++ = '-'; 
        }
        *buffer++ = *digits;
        if (precision > 0)
        {
            *buffer++ = '.';
        }
        (void)memcpy_s(buffer, (size_t)bufSize, digits + 1, (size_t)precision); /*lint !e732*/
        buffer += precision;
        littleDigit = precision;
        gPos = buffer;
        if('g' == oriFmt)
        {
            while(littleDigit-- > 0)
            {
                gPos--;
                if('0' == *gPos)
                {
                    *gPos = '\0';
                    if(0 == littleDigit)
                    {
                        gPos--;
                        if('.' == *gPos)
                        {
                            *gPos = '\0';
                        }
                        buffer = ++gPos;
                    }
                }
                else
                {
                    buffer = ++gPos;
                    break;
                }
            }
        }
        *buffer++ = capexp ? 'E' : 'e';

        if (decpt == 0)
        {
            if (value == 0.0)
            {
                expVal = 0;
            }
            else
            {
                expVal = -1;
            }
        }
        else
        {
            expVal = decpt - 1;
        }

        if (expVal < 0)
        {
            *buffer++ = '-';
            expVal = -expVal;
        }
        else
        {
            *buffer++ = '+';
        }

#ifdef COMPATIBLE_LINUX_FORMAT
        if (longflag && expVal >= 1000)
        {
            buffer[3] = expVal % 10 + '0';
            expVal = expVal / 10;
            buffer[2] = expVal % 10 + '0';
            expVal = expVal / 10;
            buffer[1] = expVal % 10 + '0';
            expVal = expVal / 10;
            buffer[0] = expVal % 10 + '0';
            buffer += 4;
        }
        else
#endif
        {
            buffer[2] = (expVal % 10) + '0';
            expVal = expVal / 10;
            buffer[1] = (expVal % 10) + '0';
            expVal = expVal / 10;
    
#if  (defined(COMPATIBLE_LINUX_FORMAT) || defined(_VXWORKS_PLATFORM_))
            if ((expVal % 10) + '0' == '0')
            {
                buffer[0] = buffer[1]; 
                buffer[1] = buffer[2];
                buffer[2] = '\0';
                buffer += 2;
            }
            else
            {
                buffer[0] = (expVal % 10) + '0';
                buffer += 3;
            }
#else
            buffer[0] = (expVal % 10) + '0';
            buffer += 3;
#endif
        }


    }
    else if (fmt == 'f')
    {
        digits = fcvtbuf_hw(value, longvalue, precision, &decpt, &sign, cvtbuf, longflag);


        if (sign)
        {
            *buffer++ = '-';
        }
        if (*digits)
        {
            if (decpt <= 0)
            {
                *buffer++ = '0';
                *buffer++ = '.';
                for (pos = 0; pos < -decpt; pos++)
                {
                    *buffer++ = '0';
                }
                while (*digits)
                {
                    if (buffer - oriPos >= bufSize)    _CHECK_BUFFER_OVERLAP
                    {
                        break;
                    }
                    *buffer++ = *digits++;
                }
            }
            else
            {
                pos = 0;
                while (*digits)
                {
                    if (buffer - oriPos >= bufSize)    _CHECK_BUFFER_OVERLAP
                    {
                        break;
                    }
                    if (pos++ == decpt)
                    { 
                        *buffer++ = '.'; 
                    }
                    *buffer++ = *digits++;
                }
            }


        }
        else
        {
            *buffer++ = '0';
            if (precision > 0)
            {
                *buffer++ = '.';
                for (pos = 0; pos < precision; pos++)
                {
                    *buffer++ = '0';
                }
            }
        }
        if('g' == oriFmt)
        {
            littleDigit = precision;
            gPos = buffer;
            while(littleDigit-- > 0)
            {
                gPos--;
                if('0' == *gPos)
                {
                    *gPos = '\0';
                    if(0 == littleDigit)
                    {
                        gPos--;
                        if('.' == *gPos)
                            *gPos = '\0';
                        buffer = ++gPos;
                    }
                }
                else
                {
                    buffer = ++gPos;
                    break;
                }
            }
        }   
    }

    if ( buffer - oriPos >= bufSize)    _CHECK_BUFFER_OVERLAP
    {
        /*buffer overflow*/
        (void)memset_s(oriPos, (size_t)bufSize, 0, (size_t)bufSize);
    }else
    {
        *buffer = '\0';
    }
    
    if(NULL != cvtbuf)
    {
        free(cvtbuf);
        cvtbuf = NULL;
    }
}

#include "outputod.inl"

/*******************************************************************************
 * <NAME>
 *    sprintf_s
 *
 * <SYNOPSIS>
 *    int sprintf_s(char* strDest, size_t destMax, const char* format, ...);
 *
 * <FUNCTION DESCRIPTION>
 *    The sprintf_s function formats and stores a series of characters and values
 *    in strDest. Each argument (if any) is converted and output according to 
 *    the corresponding format specification in format. The format consists of
 *    ordinary characters and has the same form and function as the format argument
 *    for printf. A null character is appended after the last character written.
 *    If copying occurs between strings that overlap, the behavior is undefined.
 *
 * <INPUT PARAMETERS>
 *    strDest                Storage location for output.
 *    destMax                Maximum number of characters to store.
 *    format                 Format-control string.
 *
 * <OUTPUT PARAMETERS>
 *    strDest                is updated
 *
 * <RETURN VALUE>
 *    sprintf_s returns the number of bytes stored in strDest, not counting the
 *    terminating null character.
 *    The number of characters written, or -1 if an error occurred. If strDest 
 *    or format is a null pointer, sprintf_s returns -1.
 *******************************************************************************
*/

#define __putc_nolock(_c,_stream)    (--(_stream)->_cnt >= 0 ? 0xff & (*(_stream)->_ptr++ = (char)(_c)) :  EOF)


int vsnprintf_helperOld (char* string, size_t count, const char* format, va_list arglist)
{
    SECUREC_XPRINTF_STREAM str;
    int retval;
    
    str._cnt = (int)count;
    str._ptr = string;

    retval = securec_output_sOld(&str, format, arglist );

    if ((retval >= 0) && (__putc_nolock('\0', &str) != EOF))
    {
        return (retval);
    }

    if (string != NULL)
    {
        string[count - 1] = 0;
    }

    if (str._cnt < 0)
    {
        /* the buffer was too small; we return -2 to indicate truncation */
        return -2;
    }
    return -1;
}

int vsprintf_sOld (char* strDest, size_t destMax, const char* format, va_list arglist)
{
    int retvalue = -1;

    if (format == NULL || strDest == NULL || destMax == 0 || destMax > SECUREC_STRING_MAX_LEN)
    {
        if (strDest != NULL && destMax > 0)
        {
            strDest[0] = '\0';
        }
        SECUREC_ERROR_INVALID_PARAMTER("vsprintf_s");
        return -1;
    }

    retvalue = vsnprintf_helperOld(strDest, destMax, format, arglist);

    if (retvalue < 0)
    {
        strDest[0] = '\0';
        if (retvalue == -2)
        {
            /*Buffer is too small*/
            SECUREC_ERROR_INVALID_RANGE("vsprintf_s");
        }
        SECUREC_ERROR_INVALID_PARAMTER("vsprintf_s");
        return -1;
    }

    return retvalue;
}

int sprintf_sOld (char* strDest, size_t destMax, const char* format, ...)
{
    int ret = 0;
    va_list arglist;

    va_start(arglist, format);
    ret = vsprintf_sOld(strDest, destMax, format, arglist);
    va_end(arglist);

    return ret;
}


