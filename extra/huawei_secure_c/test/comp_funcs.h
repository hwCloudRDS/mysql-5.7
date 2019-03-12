/*
comp_funcs.h
*/

#ifndef __UNITTEST_H__B918_45ed_AECF_676FA_COMP
#define __UNITTEST_H__B918_45ed_AECF_676FA_COMP


//lint -esym(526, test_sscanf_format_*)
//lint -esym(526, test_printf_format_*)
//lint -esym(526, test_sprintf_format_*)
/* float */
void test_sscanf_format_e(FILE* fStd,FILE* fSec);
void  test_sscanf_format_e_add(FILE* fStd,FILE* fSec);
void  test_sscanf_format_E_add(FILE* fStd,FILE* fSec);
void  test_sscanf_format_f_add(FILE* fStd,FILE* fSec);
void  test_sscanf_format_g_add(FILE* fStd,FILE* fSec);
void test_sscanf_format_g(FILE* fStd,FILE* fSec);
void test_sscanf_format_f(FILE* fStd,FILE* fSec);
void test_sscanf_format_a(FILE* fStd,FILE* fSec);
void test_sscanf_format_a_add(FILE* fStd,FILE* fSec);

/* int_d */
void test_sscanf_format_d(FILE* fStd,FILE* fSec);
void test_sscanf_format_d_add(FILE* fStd,FILE* fSec);
void test_sscanf_format_D_add(FILE* fStd,FILE* fSec);

/* int_i */
void test_sscanf_format_i(FILE* fStd,FILE* fSec);
void test_sscanf_format_i_add(FILE* fStd,FILE* fSec);

void test_sscanf_format_o(FILE* fStd,FILE* fSec);
void test_sscanf_format_o_add(FILE* fStd,FILE* fSec);
void test_sscanf_format_u(FILE* fStd,FILE* fSec);
void test_sscanf_format_u_add(FILE* fStd,FILE* fSec);
void test_sscanf_format_x(FILE* fStd,FILE* fSec);
void test_sscanf_format_x_add(FILE* fStd,FILE* fSec);
void test_sscanf_format_X_add(FILE* fStd,FILE* fSec);

/* str-c */
void test_sscanf_format_c(FILE* fStd,FILE* fSec);
void test_sscanf_format_c_add(FILE* fStd,FILE* fSec);
void test_sscanf_format_C(FILE* fStd,FILE* fSec);

/* str-s */
void test_sscanf_format_s(FILE* fStd,FILE* fSec);
void test_sscanf_format_s_add(FILE* fStd,FILE* fSec);
#if !(defined(SECUREC_VXWORKS_PLATFORM))
void test_swscanf_format_s(FILE* fStd,FILE* fSec);
void test_swprintf_format_s(FILE *fstd, FILE *fsec);
#endif
/*void test_sscanf_format_S(FILE* fStd,FILE* fSec);*/

/* other */
void test_sscanf_format_n(FILE* fStd,FILE* fSec);
void test_sscanf_format_p(FILE* fStd,FILE* fSec);
void test_sscanf_format_p_add(FILE* fStd,FILE* fSec);
/* % */
void test_sscanf_format_percent(FILE* fStd,FILE* fSec);
void test_sscanf_format_percent_add(FILE* fStd,FILE* fSec);
/* [] */
void test_sscanf_format_regular(FILE* fStd,FILE* fSec);
void test_sscanf_format_regular_add(FILE *fstd, FILE *fsec);
void  test_sscanf_format_n_add(FILE* fStd,FILE* fSec);
void  test_sscanf_format_combin(FILE* fStd,FILE* fSec);
/******/
void test_printf_format_o(FILE* fStd,FILE* fSec);                     
void test_printf_format_u(FILE* fStd,FILE* fSec);                     
void test_printf_format_x(FILE* fStd,FILE* fSec);                     
void test_printf_format_c(FILE* fStd,FILE* fSec);                     
void test_printf_format_C(FILE* fStd,FILE* fSec);                     

void test_printf_format_e(FILE* fStd,FILE* fSec);                     
void test_printf_format_g(FILE* fStd,FILE* fSec);                     
void test_printf_format_f(FILE* fStd,FILE* fSec);                     
void test_printf_format_a(FILE* fStd,FILE* fSec);                     

void test_printf_format_d(FILE* fStd,FILE* fSec); 
void test_sprintf_format_i(FILE* fStd,FILE* fSec);

void test_sprintf_format_s(FILE* fStd,FILE* fSec);
void test_sprintf_format_s_NULL(FILE* fStd,FILE* fSec);

void test_printf_format_n(FILE* fStd,FILE* fSec);
void test_printf_format_p(FILE* fStd,FILE* fSec);
void test_printf_format_percent(FILE* fStd,FILE* fSec);
void test_printf_format_regular(FILE* fStd,FILE* fSec);


#endif
