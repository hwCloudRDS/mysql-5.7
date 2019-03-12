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

/* LSD remark

*/

#define IGNORE_BUG        

#include "securec.h"
#include "base_funcs.h"
#include <assert.h>
#include <string.h>

#define LEN   ( 128 )

#if (defined(_WIN32) || defined(_WIN64) || defined(COMPATIBLE_LINUX_FORMAT))
extern int wprintf (const wchar_t* format, ...);
extern int wcscmp (const wchar_t* wcs1, const wchar_t* wcs2);
extern wchar_t* wcscpy (wchar_t* destination, const wchar_t* source);
#endif

void TestStrcpy_s()
{
    errno_t rc;
    int32_t  ind;
    char   str1[LEN];
    char   str2[LEN]="";

    rc = strcpy_s(NULL, LEN, str2);    /*NULL pointer case*/
    assert( EINVAL == rc);

    /*--------------------------------------------------*/

    (void)strcpy_s(str1, LEN, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    rc = strcpy_s(str1, 5, NULL);    /*src NULL pointer case*/
    assert ((rc & 0x7F) == EINVAL);

    assert(str1[0] == '\0') ;

    /*--------------------------------------------------*/

    rc = strcpy_s(str1, 0, str2);    /*size is 0*/
    assert ((rc & 0x7F) == ERANGE);

    /*--------------------------------------------------*/

    rc = strcpy_s(str1, (size_t)(SECUREC_STRING_MAX_LEN+1), str2);    /*over maxi limit*/
    assert ((rc & 0x7F) == ERANGE);

    /*--------------------------------------------------*/
    /*--------------------------------------------------*/

    rc = strcpy_s(str1, LEN, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    str2[0] = '\0';
    assert(rc == EOK);
    rc = strcpy_s(str1, LEN/2, str2);    /*src is balnk*/
    assert ((rc & 0x7F) == EOK);
    assert(str1[0] == '\0');

    /*--------------------------------------------------*/

    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    rc = strcpy_s(str1, LEN, str1);    /*full overlap*/
    assert ((rc & 0x7F) == EOK);
    assert(str1[0] == 'a');
    assert (strcmp(str1,  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);

    /*--------------------------------------------------*/

    strcpy(&str1[0], "keep it simple");

    rc = strcpy_s(&str1[0], LEN, &str1[5]);    /*part overlap*/

    assert (rc == EOVERLAP_AND_RESET);


    /*--------------------------------------------------*/

    strcpy(&str1[0], "keep it simple");
    str2[0] = '\0';

    rc = strcpy_s(str1, LEN, str2);    /*blank src*/
    assert ((rc & 0x7F) == EOK);

    assert (*str1 == '\0');

    /*--------------------------------------------------*/

    str1[0] = '\0';
    strcpy(&str2[0], "keep it simple");

    rc = strcpy_s(str1, LEN, str2);
    assert ((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(str1, str2);
    assert (ind == 0);

    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "keep it simple");

    rc = strcpy_s(str1, LEN, str2);    /*different copy*/
    assert ((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(str1, str2);
    assert (ind == 0);

    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "keep it simple");

    rc = strcpy_s(str1, 1, str2);
    assert ((rc & 0x7F) == ERANGE);

    assert (*str1 == '\0');

    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "keep it simple");

    rc = strcpy_s(str1, 2, str2);
    assert ((rc & 0x7F) == ERANGE);

    assert (*str1 == '\0');

    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "it");

    rc = strcpy_s(str1, 3, str2);
    assert ((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(str1, str2);
    assert (ind == 0);

    /*--------------------------------------------------*/

    strcpy(str1, "qq12345weqeqeqeq");
    strcpy(str2, "it");

    rc = strcpy_s(str1, 10, str2);
    assert ((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcpy */
    ind = strcmp(str1, str2);
    assert (ind == 0);

    /*   for (i=0; i<10; i++) {
    printf("str1[%i] = %d \n", i, str1[i]);
    }
    */

    strcpy(str1, "123456789012345678901234567890123");
    rc = strcpy_s(str1, 14, str1 + 20);/* srcStrLen > DIRECT_ASSIGNMENT_THRESHOLD */
    assert ((rc & 0x7F) == EOK);

}

void testOverlap(void)
{
    errno_t rc;
    int32_t  i;
    char   str1[LEN];
    /*char lsdStr[] = "123\0abcdef";*/
    char catStr[20] = "0123456789";

    for(i = 0; i <LEN - 1; ++i) {
        str1[i] = 'a' + (i %26);
    }
    str1[i] = '\0';

    rc = strcpy_s(str1, LEN, str1);    
    assert( EOK == rc);

    rc = strcpy_s(str1, LEN, str1 +10);    
    assert( EOVERLAP_AND_RESET == rc);

    rc = strcpy_s(str1, LEN, "abcdefghijklmnopqrst");    
    assert(rc == EOK);
    rc = strcpy_s(str1+ 10, LEN, str1);    
    assert( EOVERLAP_AND_RESET == rc);

    rc = strcat_s(catStr,  sizeof(catStr), catStr + 5);    
    assert( EOVERLAP_AND_RESET == rc);

    rc = strcpy_s(catStr, sizeof(catStr), "0123456789"); 
    assert(rc == EOK);
    rc = strncat_s(catStr+ 4,  sizeof(catStr) -4, catStr, 2);    
    assert( EOK == rc);
    assert(strcmp(catStr, "012345678901") ==0);

    rc = strcpy_s(catStr, sizeof(catStr), "0123456789");    
    assert(rc == EOK);
    rc = strncat_s(catStr+ 4,  sizeof(catStr) -4, catStr, 3);    
    assert( EOK == rc);
    assert(strcmp(catStr, "0123456789012") ==0);

    rc = strcpy_s(catStr, sizeof(catStr), "0123456789");    
    assert( EOK == rc);
    rc = strncat_s(catStr+ 4,  sizeof(catStr) -4, catStr, 4);    
    assert( EOVERLAP_AND_RESET == rc);
    assert(strcmp(catStr + 4, "") ==0);


    rc = strcpy_s(catStr, sizeof(catStr), "0123456789");    
    assert(rc == EOK);
    rc = strncat_s(catStr+ 4,  sizeof(catStr) -4, catStr, 9);    
    assert( EOVERLAP_AND_RESET == rc);

}

void TestStrncpy_s()
{
    errno_t rc;
    size_t nlen;
    int32_t ind;
    char   str1[LEN];
    char   str2[LEN]="";
    char   dest[LEN];

    /*--------------------------------------------------*/

    nlen = 5;
    rc = strncpy_s(NULL, LEN, str2, nlen);    /*test dest is NULL*/
    assert((rc & 0x7F) == EINVAL);

    /*--------------------------------------------------*/

    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    nlen = 5;
    rc = strncpy_s(str1, 5, NULL, nlen);
    assert((rc & 0x7F) == EINVAL);

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/

    nlen = 5;
    rc = strncpy_s(str1, 0, str2, nlen);
    assert((rc & 0x7F) == ERANGE);
    assert(str1[0] == 0);

    /*--------------------------------------------------*/

    rc = strncpy_s(str1, (size_t)-2, str2, nlen);
    assert((rc & 0x7F) == ERANGE);

    /*--------------------------------------------------*/
    /*--------------------------------------------------*/

    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    str2[0] = '\0';

    rc = strncpy_s(str1, 5, str2, 0);
    assert((rc & 0x7F) == EOK) ;    /*the return value is different to safeC ESZEROL*/

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/
    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    strcpy(str2, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    rc = strncpy_s(str1, 5, str2, (size_t)(SECUREC_STRING_MAX_LEN+1));    /*src over range*/
    assert((rc & 0x7F) == ERANGE);


    /*--------------------------------------------------*/

    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    str2[0] = '\0';
    nlen = 5;

    rc = strncpy_s(&str1[0], LEN/2, &str2[0], nlen);
    assert((rc & 0x7F) == EOK) ;

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/

    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    nlen = 5;

    /* test overlap */
    rc = strncpy_s(str1, LEN, str1, nlen);
    assert((rc & 0x7F) == EOK);

    assert(str1[0] == 'a');

    /*--------------------------------------------------*/

    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    nlen = 18;

    rc = strncpy_s(&str1[0], LEN, &str1[5], nlen);
    assert(rc == EOVERLAP_AND_RESET);

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/

    strcpy(str1, "keep it simple");
    str2[0] = '\0';

    nlen = 10;
    rc = strncpy_s(str1, LEN, str2, nlen);
    assert((rc & 0x7F) == EOK);

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/

    str1[0] = '\0';
    strcpy(str2, "keep it simple");

    nlen = 20;
    rc = strncpy_s(str1, LEN, str2, nlen);    /*overwrite dest*/
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(str1, str2);
    assert(ind == 0);


    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "keep it simple");

    nlen = 32;
    rc = strncpy_s(str1, LEN, str2, nlen);
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(str1, str2);
    assert(ind == 0) ;

    /*--------------------------------------------------*/
    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "keep it simple");

    rc = strncpy_s(str1, 1, str2, nlen);    /*over dest range*/
    assert((rc & 0x7F) == ERANGE);

    assert(*str1 == '\0');

    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "keep it simple");

    rc = strncpy_s(str1, 2, str2, nlen);
    assert((rc & 0x7F) == ERANGE);

    assert(*str1 == '\0');

    /*--------------------------------------------------*/
    /* TR example */

    strcpy(dest, "                            ");
    strcpy(str1, "hello");

    rc = strncpy_s(dest, 6, str1, 100);
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(dest, str1);
    assert(ind == 0);

    /*--------------------------------------------------*/
    /* TR example */

    strcpy(dest, "                            ");
    strcpy(str2, "goodbye");

    rc = strncpy_s(dest, 5, str2, 7);
    assert((rc & 0x7F) == ERANGE);
    assert(dest[0] == 0);

    /*--------------------------------------------------*/
    /* TR example */

    strcpy(dest, "                            ");
    strcpy(str2, "goodbye");

    rc = strncpy_s(dest, 5, str2, 4);
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(dest, "good");
    assert(ind == 0);

    /*--------------------------------------------------*/

    strcpy(dest, "                            ");
    strcpy(str2, "good");

    /*   strnlen("good") < 5   */
    rc = strncpy_s(dest, 5, str2, 8);
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(dest, "good");
    assert(ind == 0);

    /*--------------------------------------------------*/

    strcpy(str1, "qq12345weqeqeqeq");
    strcpy(str2, "it");

    nlen = 10;
    rc = strncpy_s(str1, 10, str2, nlen);
    assert((rc & 0x7F) == EOK) ;

    /* be sure the results are the same as strcmp */
    ind = strcmp(str1, str2);
    assert(ind == 0) ;
}
#ifndef SECUREC_VXWORKS_PLATFORM
void TestWcscpy_s()
{
    errno_t rc;
    int32_t  ind;
    wchar_t   str1[LEN];
    wchar_t   str2[LEN]=L"";
    wchar_t * prc = NULL;
    rc = wcscpy_s(NULL, LEN, str2);    /*NULL pointer case*/
    assert( EINVAL == rc);

    /*--------------------------------------------------*/

    rc = wcscpy_s(str1, LEN, L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert(rc == EOK);
    rc = wcscpy_s(str1, 5, NULL);    /*src NULL pointer case*/
    assert ((rc & 0x7F) == EINVAL);

    assert(str1[0] == '\0') ;

    /*--------------------------------------------------*/

    rc = wcscpy_s(str1, 0, str2);    /*size is 0*/
    assert ((rc & 0x7F) == ERANGE);

    /*--------------------------------------------------*/

    rc = wcscpy_s(str1, (size_t)(SECUREC_STRING_MAX_LEN+1), str2);    /*over maxi limit*/
    assert ((rc & 0x7F) == ERANGE);

    /*--------------------------------------------------*/
    /*--------------------------------------------------*/

    rc = wcscpy_s(str1, LEN, L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert(rc == EOK);
    str2[0] = '\0';

    rc = wcscpy_s(str1, LEN/2, str2);    /*src is balnk*/
    assert ((rc & 0x7F) == EOK);
    assert(str1[0] == '\0');

    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    rc = wcscpy_s(str1, LEN, str1);    /*full overlap*/
    assert ((rc & 0x7F) == EOK);
    assert(str1[0] == 'a');
    assert (wcscmp(str1,  L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
    /*--------------------------------------------------*/
    prc = wcscpy(&str1[0], L"keep it simple");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    rc = wcscpy_s(&str1[0], LEN, &str1[5]);    /*part overlap*/

    assert (rc == EOVERLAP_AND_RESET);

    /*--------------------------------------------------*/
    prc = wcscpy(&str1[0], L"keep it simple");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    str2[0] = '\0';

    rc = wcscpy_s(str1, LEN, str2);    /*blank src*/
    assert ((rc & 0x7F) == EOK);

    assert (*str1 == '\0');

    /*--------------------------------------------------*/

    str1[0] = '\0';
    prc = wcscpy(&str2[0], L"keep it simple");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    rc = wcscpy_s(str1, LEN, str2);
    assert ((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = wcscmp(str1, str2);
    assert (ind == 0);

    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"qqweqeqeqeq");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str2, L"keep it simple");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    rc = wcscpy_s(str1, LEN, str2);    /*different copy*/
    assert ((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = wcscmp(str1, str2);
    assert (ind == 0);

    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"qqweqeqeqeq");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str2, L"keep it simple");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    rc = wcscpy_s(str1, 1, str2);
    assert ((rc & 0x7F) == ERANGE);

    assert (*str1 == '\0');

    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"qqweqeqeqeq");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str2, L"keep it simple");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    rc = wcscpy_s(str1, 2, str2);
    assert ((rc & 0x7F) == ERANGE);

    assert (*str1 == '\0');

    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"qqweqeqeqeq");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str2, L"it");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    rc = wcscpy_s(str1, 3, str2);
    assert ((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = wcscmp(str1, str2);
    assert (ind == 0);

    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"qq12345weqeqeqeq");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str2, L"it");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    rc = wcscpy_s(str1, 10, str2);
    assert ((rc & 0x7F) == EOK);

    /* be sure the results are the same as wcscpy */

    ind = wcscmp(str1, str2);
    assert (ind == 0);

    /*   for (i=0; i<10; i++) {
    printf("str1[%i] = %d \n", i, str1[i]);
    }
    */
}
#endif

#ifndef SECUREC_VXWORKS_PLATFORM
void TestWcsncpy_s()
{
    errno_t rc;
    size_t nlen;
    int32_t ind;
    wchar_t   str1[LEN];
    wchar_t   str2[LEN]=L"";
    wchar_t   dest[LEN];
    wchar_t *prc = NULL;

    /*--------------------------------------------------*/

    nlen = 5;
    rc = wcsncpy_s(NULL, LEN, str2, nlen);    /*test dest is NULL*/
    assert((rc & 0x7F) == EINVAL);

    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    nlen = 5;
    rc = wcsncpy_s(str1, 5, NULL, nlen);
    assert((rc & 0x7F) == EINVAL);

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/

    nlen = 5;
    rc = wcsncpy_s(str1, 0, str2, nlen);
    assert((rc & 0x7F) == ERANGE);
    assert(str1[0] == 0);

    /*--------------------------------------------------*/

    rc = wcsncpy_s(str1, (size_t)-2, str2, nlen);
    assert((rc & 0x7F) == ERANGE);

    /*--------------------------------------------------*/
    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    str2[0] = '\0';

    rc = wcsncpy_s(str1, 5, str2, 0);
    assert((rc & 0x7F) == EOK) ;    /*the return value is different to safeC ESZEROL*/

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str2, L"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    rc = wcsncpy_s(str1, 5, str2, (size_t)(SECUREC_STRING_MAX_LEN+1));    /*src over range*/
    assert((rc & 0x7F) == ERANGE);


    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    str2[0] = '\0';
    nlen = 5;

    rc = wcsncpy_s(&str1[0], LEN/2, &str2[0], nlen);
    assert((rc & 0x7F) == EOK) ;

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    nlen = 5;

    /* test overlap */
    rc = wcsncpy_s(str1, LEN, str1, nlen);
    assert((rc & 0x7F) == EOK);

    assert(str1[0] == 'a');

    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    nlen = 18;

    rc = wcsncpy_s(&str1[0], LEN, &str1[5], nlen);
    assert(rc == EOVERLAP_AND_RESET);

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"keep it simple");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    str2[0] = '\0';

    nlen = 10;
    rc = wcsncpy_s(str1, LEN, str2, nlen);
    assert((rc & 0x7F) == EOK);

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/

    str1[0] = '\0';
    prc = wcscpy(str2, L"keep it simple");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    nlen = 20;
    rc = wcsncpy_s(str1, LEN, str2, nlen);    /*overwrite dest*/
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as wcscmp */
    ind = wcscmp(str1, str2);
    assert(ind == 0);


    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"qqweqeqeqeq");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str2, L"keep it simple");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    nlen = 32;
    rc = wcsncpy_s(str1, LEN, str2, nlen);
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as wcscmp */
    ind = wcscmp(str1, str2);
    assert(ind == 0) ;

    /*--------------------------------------------------*/
    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"qqweqeqeqeq");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str2, L"keep it simple");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    rc = wcsncpy_s(str1, 1, str2, nlen);    /*over dest range*/
    assert((rc & 0x7F) == ERANGE);

    assert(*str1 == '\0');

    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"qqweqeqeqeq");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str2, L"keep it simple");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    rc = wcsncpy_s(str1, 2, str2, nlen);
    assert((rc & 0x7F) == ERANGE);

    assert(*str1 == '\0');

    /*--------------------------------------------------*/
    /* TR example */
    prc = wcscpy(dest, L"                            ");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str1, L"hello");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    rc = wcsncpy_s(dest, 6, str1, 100);
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as wcscmp */
    ind = wcscmp(dest, str1);
    assert(ind == 0);

    /*--------------------------------------------------*/
    /* TR example */
    prc = wcscpy(dest, L"                            ");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str2, L"goodbye");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    rc = wcsncpy_s(dest, 5, str2, 7);
    assert((rc & 0x7F) == ERANGE);
    assert(dest[0] == 0);

    /*--------------------------------------------------*/
    /* TR example */
    prc = wcscpy(dest, L"                            ");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str2, L"goodbye");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    rc = wcsncpy_s(dest, 5, str2, 4);
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as wcscmp */
    ind = wcscmp(dest, L"good");
    assert(ind == 0);

    /*--------------------------------------------------*/
    prc = wcscpy(dest, L"                            ");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str2, L"good");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    /*   strnlen("good") < 5   */
    rc = wcsncpy_s(dest, 5, str2, 8);
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as wcscmp */
    ind = wcscmp(dest, L"good");
    assert(ind == 0);

    /*--------------------------------------------------*/
    prc = wcscpy(str1, L"qq12345weqeqeqeq");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }
    prc = wcscpy(str2, L"it");
    if(prc == NULL)
    {
        assert(1 == EOK);
    }

    nlen = 10;
    rc = wcsncpy_s(str1, 10, str2, nlen);
    assert((rc & 0x7F) == EOK) ;

    /* be sure the results are the same as wcscmp */
    ind = wcscmp(str1, str2);
    assert(ind == 0) ;
}
#endif

#if defined(WITH_PERFORMANCE_ADDONS)
void TestStrcpy_sp()
{
    errno_t rc;
    int32_t  ind;
    char   str1[LEN];
    char   str2[LEN];
    char *temp1=NULL, *temp2=NULL;

    rc = strcpy_sp(temp1, LEN, str2);    /*NULL pointer case*/
    assert( EINVAL == rc);

    /*--------------------------------------------------*/

    strcpy_sp(str1, LEN, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    rc = strcpy_sp(str1, 5, temp2);    /*src NULL pointer case*/
    assert ((rc & 0x7F) == EINVAL);

    assert(str1[0] == '\0') ;

    /*--------------------------------------------------*/

    rc = strcpy_sp(str1, 0, str2);    /*size is 0*/
    assert ((rc & 0x7F) == ERANGE);

    /*--------------------------------------------------*/

    rc = strcpy_sp(str1, (size_t)(SECUREC_STRING_MAX_LEN+1), str2);    /*over maxi limit*/
    assert ((rc & 0x7F) == ERANGE);

    /*--------------------------------------------------*/
    /*--------------------------------------------------*/

    strcpy_sp(str1, LEN, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    str2[0] = '\0';

    rc = strcpy_sp(str1, LEN/2, str2);    /*src is balnk*/
    assert ((rc & 0x7F) == EOK);
    assert(str1[0] == '\0');

    /*--------------------------------------------------*/

    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    rc = strcpy_sp(str1, LEN, str1);    /*full overlap*/
    assert ((rc & 0x7F) == EOK);
    assert(str1[0] == 'a');
    assert (strcmp(str1,  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);

    /*--------------------------------------------------*/
#if defined(__GNUC__)
    strcpy(&str1[0], "keep it simple");

    rc = strcpy_sp(&str1[0], LEN, &str1[5]);    /*part overlap*/

    assert (rc == EOVERLAP_AND_RESET);
#endif

    /*--------------------------------------------------*/

    strcpy(&str1[0], "keep it simple");
    str2[0] = '\0';

    rc = strcpy_sp(str1, LEN, str2);    /*blank src*/
    assert ((rc & 0x7F) == EOK);

    assert (*str1 == '\0');

    /*--------------------------------------------------*/

    str1[0] = '\0';
    strcpy(&str2[0], "keep it simple");

    rc = strcpy_sp(str1, LEN, str2);
    assert ((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(str1, str2);
    assert (ind == 0);

    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "keep it simple");

    rc = strcpy_sp(str1, LEN, str2);    /*different copy*/
    assert ((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(str1, str2);
    assert (ind == 0);

    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "keep it simple");

    rc = strcpy_sp(str1, 1, str2);
    assert ((rc & 0x7F) == ERANGE);

    assert (*str1 == '\0');

    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "keep it simple");

    rc = strcpy_sp(str1, 2, str2);
    assert ((rc & 0x7F) == ERANGE);

    assert (*str1 == '\0');

    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "it");

    rc = strcpy_sp(str1, 3, str2);
    assert ((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(str1, str2);
    assert (ind == 0);

    /*--------------------------------------------------*/

    strcpy(str1, "qq12345weqeqeqeq");
    strcpy(str2, "it");

    rc = strcpy_sp(str1, 10, str2);
    assert ((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcpy */
    ind = strcmp(str1, str2);
    assert (ind == 0);

    /*   for (i=0; i<10; i++) {
    printf("str1[%i] = %d \n", i, str1[i]);
    }
    */
}

void testOverlapp(void)
{
    errno_t rc;
    int32_t  i;
    char   str1[LEN];
    /*char lsdStr[] = "123\0abcdef";*/
    char catStr[20] = "0123456789";

    for(i = 0; i <LEN - 1; ++i) {
        str1[i] = 'a' + (i %26);
    }
    str1[i] = '\0';

    rc = strcpy_sp(str1, LEN, str1);    
    assert( EOK == rc);

#if defined(__GNUC__)
    rc = strcpy_sp(str1, LEN, str1 +10);    
    assert( EOVERLAP_AND_RESET == rc);

    strcpy_sp(str1, LEN, "abcdefghijklmnopqrst");    
    rc = strcpy_sp(str1+ 10, LEN, str1);    
    assert( EOVERLAP_AND_RESET == rc);

    rc = strcat_s(catStr,  sizeof(catStr), catStr + 5);    
    assert( EOVERLAP_AND_RESET == rc);

    strcpy_sp(catStr, sizeof(catStr), "0123456789");    
    rc = strncat_s(catStr+ 4,  sizeof(catStr) -4, catStr, 2);    
    assert( EOK == rc);
    assert(strcmp(catStr, "012345678901") ==0);

    strcpy_sp(catStr, sizeof(catStr), "0123456789");    
    rc = strncat_s(catStr+ 4,  sizeof(catStr) -4, catStr, 3);    
    assert( EOK == rc);
    assert(strcmp(catStr, "0123456789012") ==0);

    rc = strcpy_sp(catStr, sizeof(catStr), "0123456789");    
    assert( EOK == rc);
    rc = strncat_s(catStr+ 4,  sizeof(catStr) -4, catStr, 4);    
    assert( EOVERLAP_AND_RESET == rc);
    assert(strcmp(catStr + 4, "") ==0);


    strcpy_sp(catStr, sizeof(catStr), "0123456789");    
    rc = strncat_s(catStr+ 4,  sizeof(catStr) -4, catStr, 9);    
    assert( EOVERLAP_AND_RESET == rc);
#endif
}

void TestStrncpy_sp()
{
    errno_t rc;
    size_t nlen;
    int32_t ind;
    char   str1[LEN];
    char   str2[LEN];
    char   dest[LEN];
    char *temp1=NULL, *temp2=NULL;

    /*--------------------------------------------------*/

    nlen = 5;
    rc = strncpy_sp(temp1, LEN, str2, nlen);    /*test dest is NULL*/
    assert((rc & 0x7F) == EINVAL);

    /*--------------------------------------------------*/

    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    nlen = 5;
    rc = strncpy_sp(str1, 5, temp2, nlen);
    assert((rc & 0x7F) == EINVAL);

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/

    nlen = 5;
    rc = strncpy_sp(str1, 0, str2, nlen);
    assert((rc & 0x7F) == ERANGE);
    assert(str1[0] == 0);

    /*--------------------------------------------------*/

    rc = strncpy_sp(str1, (size_t)-2, str2, nlen);
    assert((rc & 0x7F) == ERANGE);

    /*--------------------------------------------------*/
    /*--------------------------------------------------*/

    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    str2[0] = '\0';

    rc = strncpy_sp(str1, 5, str2, 0);
    assert((rc & 0x7F) == EOK) ;    /*the return value is different to safeC ESZEROL*/

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/
    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    strcpy(str2, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    rc = strncpy_sp(str1, 5, str2, (size_t)(SECUREC_STRING_MAX_LEN+1));    /*src over range*/
    assert((rc & 0x7F) == ERANGE);


    /*--------------------------------------------------*/

    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    str2[0] = '\0';
    nlen = 5;

    rc = strncpy_sp(&str1[0], LEN/2, &str2[0], nlen);
    assert((rc & 0x7F) == EOK) ;

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/

    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    nlen = 5;

    /* test overlap */
    rc = strncpy_sp(str1, LEN, str1, nlen);
    assert((rc & 0x7F) == EOK);

    assert(str1[0] == 'a');

    /*--------------------------------------------------*/
#if defined(__GNUC__)
    strcpy(str1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    nlen = 18;

    rc = strncpy_sp(&str1[0], LEN, &str1[5], nlen);
    assert(rc == EOVERLAP_AND_RESET);

    assert(str1[0] == '\0');
#endif
    /*--------------------------------------------------*/

    strcpy(str1, "keep it simple");
    str2[0] = '\0';

    nlen = 10;
    rc = strncpy_sp(str1, LEN, str2, nlen);
    assert((rc & 0x7F) == EOK);

    assert(str1[0] == '\0');

    /*--------------------------------------------------*/

    str1[0] = '\0';
    strcpy(str2, "keep it simple");

    nlen = 20;
    rc = strncpy_sp(str1, LEN, str2, nlen);    /*overwrite dest*/
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(str1, str2);
    assert(ind == 0);


    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "keep it simple");

    nlen = 32;
    rc = strncpy_sp(str1, LEN, str2, nlen);
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(str1, str2);
    assert(ind == 0) ;

    /*--------------------------------------------------*/
    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "keep it simple");

    rc = strncpy_sp(str1, 1, str2, nlen);    /*over dest range*/
    assert((rc & 0x7F) == ERANGE);

    assert(*str1 == '\0');

    /*--------------------------------------------------*/

    strcpy(str1, "qqweqeqeqeq");
    strcpy(str2, "keep it simple");

    rc = strncpy_sp(str1, 2, str2, nlen);
    assert((rc & 0x7F) == ERANGE);

    assert(*str1 == '\0');

    /*--------------------------------------------------*/
    /* TR example */

    strcpy(dest, "                            ");
    strcpy(str1, "hello");

    rc = strncpy_sp(dest, 6, str1, 100);
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(dest, str1);
    assert(ind == 0);

    /*--------------------------------------------------*/
    /* TR example */

    strcpy(dest, "                            ");
    strcpy(str2, "goodbye");

    rc = strncpy_sp(dest, 5, str2, 7);
    assert((rc & 0x7F) == ERANGE);
    assert(dest[0] == 0);

    /*--------------------------------------------------*/
    /* TR example */

    strcpy(dest, "                            ");
    strcpy(str2, "goodbye");

    rc = strncpy_sp(dest, 5, str2, 4);
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(dest, "good");
    assert(ind == 0);

    /*--------------------------------------------------*/

    strcpy(dest, "                            ");
    strcpy(str2, "good");

    /*   strnlen("good") < 5   */
    rc = strncpy_sp(dest, 5, str2, 8);
    assert((rc & 0x7F) == EOK);

    /* be sure the results are the same as strcmp */
    ind = strcmp(dest, "good");
    assert(ind == 0);

    /*--------------------------------------------------*/

    strcpy(str1, "qq12345weqeqeqeq");
    strcpy(str2, "it");

    nlen = 10;
    rc = strncpy_sp(str1, 10, str2, nlen);
    assert((rc & 0x7F) == EOK) ;

    /* be sure the results are the same as strcmp */
    ind = strcmp(str1, str2);
    assert(ind == 0) ;
}
#endif
