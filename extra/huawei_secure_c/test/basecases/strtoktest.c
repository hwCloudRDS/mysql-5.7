/*
memcpytest.c

*/
#include "securec.h"
#include "base_funcs.h"
#include "testutil.h"
#include <assert.h>
#include <string.h>

#define LEN   ( 128 )

/*
    this test suite(TestStrtok_s) is for SafeC, NOT for our strtok_s in Huawei secureC 
*/
void TestStrtok_s()
{

    char *p2str;
    char *p2tok;

    size_t len;
    char   str1[LEN] = "";
    char   str2[LEN] = "";


    /*--------------------------------------------------*/


    p2tok = strtok_s(str1,  str2,  &p2str);
    assert(p2tok == NULL);

    /*--------------------------------------------------*/
    p2tok = strtok("",  "abcdef");

    p2tok = strtok_s("",  "abcdef",  &p2str);
    assert(p2tok == NULL);

    /*--------------------------------------------------*/

    len = 0;
    p2tok = strtok_s(str1,  str2,  &p2str);
    assert(p2tok == NULL) ;

    /*--------------------------------------------------*/


 
    len = 0;
    p2tok = strtok_s(str1, NULL,  &p2str);
    assert(p2tok == NULL);

    /*--------------------------------------------------*/


    p2tok = strtok_s(str1, str2,  NULL);
    assert(p2tok == NULL) ;

    /*--------------------------------------------------*/


    /* no token test */
    strcpy(str1, "aaaaaaaa");
    len = strlen(str1);

    strcpy(str2, "fedcba");

    p2tok = strtok_s(str1, str2, &p2str);
    assert(p2tok == NULL);

    /*--------------------------------------------------*/


    strcpy(str1, "jklmnopqrst");

    strcpy(str2, "fedcba");

    p2tok = strtok_s(str1, str2, &p2str);

    assert(p2tok == str1) ;

    /*--------------------------------------------------*/


    strcpy(str1, "aaamnopqrst");

    strcpy(str2, "fedcba");

    p2tok = strtok_s(str1, str2, &p2str);
    assert(p2tok == str1 + 3);

    /*--------------------------------------------------*/
    /** [1] **/


    strcpy(str1, "aaamnopqrstfedcba");
    len = strlen(str1);

    strcpy(str2, "fedcba");

    p2tok = strtok_s(str1, str2, &p2str);
    assert(p2tok == str1 +3);

    assert(0 == strcmp(p2tok, "mnopqrst"));

    /*printf("token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );*/

    /*--------------------------------------------------*/
    /** [2] **/

    p2tok = strtok_s(p2str, str2, &p2str);
    assert(p2tok == NULL);

    /*printf("token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );*/

    /*--------------------------------------------------*/
    /*--------------------------------------------------*/
    /** [1] **/


    strcpy(str1, "?a???b,,,#c");
    len = strlen(str1);

    strcpy(str2, "?");

    p2tok = strtok_s(str1, str2, &p2str);

    assert(0 == strcmp(p2tok, "a") );

    /*printf("token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );*/

    /*--------------------------------------------------*/
    /** [2] **/
    strcpy(str1, "?a???b,,,#c");
    strcpy(str2, ",");   /* change the tokenizer string */

    /** p2tok = strtok_s(p2str, str2, &p2str); **/
    p2tok = strtok_s(NULL, str2, &p2str);

    assert(strcmp(p2tok, "??b") ) ;

    /*printf("token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );*/

    /*--------------------------------------------------*/

    strcpy(str1, ",,0,1,23,456,789,a,b,");
    len = strlen(str1);

    strcpy(str2, ",");   /* change the tokenizer string */

    printf("\n");
    printf("String to tokenize str1 = \"%s\"  len = %u\n", str1, (unsigned)len);
    printf("String of delimiters str2 = \"%s\" \n", str2);

    p2str = str1;
    p2tok = str1;

    while (p2tok && len) {

        printf("  p2tok = strtok_s(p2str, str2, &p2str); \n");

        p2tok = strtok_s(p2str, str2, &p2str);

        printf("  token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );
    }

    /*--------------------------------------------------*/

    strcpy(str1, ",.*;one,two;three,;four*.*.five-six***");

    len = strlen(str1);

    strcpy(str2, ",.;*");

    printf("\n");
    printf("String to tokenize str1 = \"%s\"  len = %u\n", str1, (unsigned)len);
    printf("String of delimiters str2 = \"%s\" \n", str2);

    printf("  p2tok = strtok_s(str1, str2, &p2str); \n");
    p2tok = strtok_s(str1, str2, &p2str);
    printf("  token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );

    printf("  p2tok = strtok_s(NULL, str2, &p2str); \n");
    p2tok = strtok_s(NULL, str2, &p2str);
    printf("  token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );

    printf("  p2tok = strtok_s(NULL, str2, &p2str); \n");
    p2tok = strtok_s(NULL, str2, &p2str);
    printf("  token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );

    printf("  p2tok = strtok_s(NULL, str2, &p2str); \n");
    p2tok = strtok_s(NULL, str2, &p2str);
    printf("  token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );

    printf("  p2tok = strtok_s(NULL, str2, &p2str); \n");
    p2tok = strtok_s(NULL, str2, &p2str);
    printf("  token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );

    printf("  p2tok = strtok_s(NULL, str2, &p2str); \n");
    p2tok = strtok_s(NULL, str2, &p2str);
    printf("  token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );

    /* len is zero at this point */
    printf("  p2tok = strtok_s(NULL, str2, &p2str); \n");
    p2tok = strtok_s(NULL, str2, &p2str);
    printf("  token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );

    printf("\n");

    /*--------------------------------------------------*/

    strcpy(str1, ",.*;one,two;three,;four*.*.five-six***");

    len = strlen(str1);

    strcpy(str2, ",.;*");

    printf("\n");
    printf("String to tokenize str1 = \"%s\"  len = %u\n", str1, (unsigned)len);
    printf("String of delimiters str2 = \"%s\" \n", str2);

    p2str = str1;
    p2tok = str1;

    while (p2tok && len) {
        printf("  p2tok = strtok_s(p2str, str2, &p2str); \n");

        p2tok = strtok_s(p2str, str2, &p2str);

        printf("  token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );
    }

    /*--------------------------------------------------*/

    strcpy(str1, ",.*;one,two;three,;four*.*.five-six***");

    len = strlen(str1) - 1;     /** back off the null **/

    strcpy(str2, ",.;*");

    printf("\n");
    printf("String to tokenize str1 = \"%s\"  len = %u\n", str1, (unsigned)len);
    printf("String of delimiters str2 = \"%s\" \n", str2);

    p2str = str1;
    p2tok = str1;

    while (p2tok && len) {
        printf("  p2tok = strtok_s(p2str, str2, &p2str); \n");

        p2tok = strtok_s(p2str, str2, &p2str);

        printf("  token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );
    }

    /*--------------------------------------------------*/

    strcpy(str1, ",.*;one,two;three,;four*.*.five-six***");

    len = strlen(str1) - 15;     /** back off a few! **/

    strcpy(str2, ",.;*");

    printf("\n");
    printf("String to tokenize str1 = \"%s\"  len = %u\n", str1, (unsigned)len);
    printf("String of delimiters str2 = \"%s\" \n", str2);

    p2str = str1;
    p2tok = str1;

    while (p2tok && len) {
        printf("  p2tok = strtok_s(p2str, str2, &p2str); \n");

        /*        p2tok = strtok_s(p2str, str2, &p2str);*/
        p2tok = strtok_s(NULL, str2, &p2str);

        printf("  token -%s-  -%s- len=%d \n", p2tok, p2str, (int)len );
    }

}

void test_strtok(void)
{
    char string1[] ="A string\tof ,,tokens\nand some  more tokens";
    char string2[] = "Another string\n\tparsed at the same time.";
    char seps[]   = " ,\t\n";
    
    char *token1,
        *token2,
        *next_token1,
        *next_token2;
    
    token1 = strtok_s( string1, seps, &next_token1);
    token2 = strtok_s ( string2, seps, &next_token2);
    
    assert(token1 != NULL);
    assert(token2 != NULL);


    assert( strcmp(token1, "A")== 0);
    assert( strcmp(token2, "Another")== 0);

    token1 = strtok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && strcmp(token1, "string")== 0);

    token1 = strtok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && strcmp(token1, "of")== 0);

    token1 = strtok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && strcmp(token1, "tokens")== 0);

    token1 = strtok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && strcmp(token1, "and")== 0);

    token1 = strtok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && strcmp(token1, "some")== 0);

    token1 = strtok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && strcmp(token1, "more")== 0);

    token1 = strtok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && strcmp(token1, "tokens")== 0);

    token1 = strtok_s( NULL, seps, &next_token1);
    assert(token1 == NULL );


    token2 = strtok_s (NULL, seps, &next_token2); 
    assert(token2 != NULL && strcmp(token2, "string")== 0);

    token2 = strtok_s (NULL, seps, &next_token2); 
    assert(token2 != NULL && strcmp(token2, "parsed")== 0);

    token2 = strtok_s (NULL, seps, &next_token2); 
    assert(token2 != NULL && strcmp(token2, "at")== 0);

    token2 = strtok_s (NULL, seps, &next_token2); 
    assert(token2 != NULL && strcmp(token2, "the")== 0);

    token2 = strtok_s (NULL, seps, &next_token2); 
    assert(token2 != NULL && strcmp(token2, "same")== 0);

    token2 = strtok_s (NULL, seps, &next_token2); 
    assert(token2 != NULL && strcmp(token2, "time.")== 0);

    token2 = strtok_s (NULL, seps, &next_token2); 
    assert(token2 == NULL );


}
#ifndef SECUREC_VXWORKS_PLATFORM
void test_wcstok(void)
{
    wchar_t string1[] = L"A string\tof ,,tokens\nand some  more tokens";
    wchar_t string2[] = L"Another string\n\tparsed at the same time.";
    wchar_t seps[]   = L" ,\t\n";
    
    wchar_t *token1,
        *token2,
        *next_token1,
        *next_token2;
    
    token1 = wcstok_s( string1, seps, &next_token1);
    token2 = wcstok_s ( string2, seps, &next_token2);
    
    assert(token1 != NULL);
    assert(token2 != NULL);


    assert( my_wcscmp(token1, L"A")== 0);
    assert( my_wcscmp(token2, L"Another")== 0);

    token1 = wcstok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && my_wcscmp(token1, L"string")== 0);

    token1 = wcstok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && my_wcscmp(token1, L"of")== 0);

    token1 = wcstok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && my_wcscmp(token1, L"tokens")== 0);

    token1 = wcstok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && my_wcscmp(token1, L"and")== 0);

    token1 = wcstok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && my_wcscmp(token1, L"some")== 0);

    token1 = wcstok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && my_wcscmp(token1, L"more")== 0);

    token1 = wcstok_s( NULL, seps, &next_token1);
    assert(token1 != NULL && my_wcscmp(token1, L"tokens")== 0);

    token1 = wcstok_s( NULL, seps, &next_token1);
    assert(token1 == NULL );


    token2 = wcstok_s (NULL, seps, &next_token2); 
    assert(token2 != NULL && my_wcscmp(token2, L"string")== 0);

    token2 = wcstok_s (NULL, seps, &next_token2); 
    assert(token2 != NULL && my_wcscmp(token2, L"parsed")== 0);

    token2 = wcstok_s (NULL, seps, &next_token2); 
    assert(token2 != NULL && my_wcscmp(token2, L"at")== 0);

    token2 = wcstok_s (NULL, seps, &next_token2); 
    assert(token2 != NULL && my_wcscmp(token2, L"the")== 0);

    token2 = wcstok_s (NULL, seps, &next_token2); 
    assert(token2 != NULL && my_wcscmp(token2, L"same")== 0);

    token2 = wcstok_s (NULL, seps, &next_token2); 
    assert(token2 != NULL && my_wcscmp(token2, L"time.")== 0);

    token2 = wcstok_s (NULL, seps, &next_token2); 
    assert(token2 == NULL );


}
#endif
