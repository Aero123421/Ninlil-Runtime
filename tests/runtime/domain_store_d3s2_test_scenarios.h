#ifndef NINLIL_DOMAIN_STORE_D3S2_TEST_SCENARIOS_H
#define NINLIL_DOMAIN_STORE_D3S2_TEST_SCENARIOS_H

#ifdef __cplusplus
extern "C" {
#endif

int test_d3s2_mode23_cancel_first_empty_success(void);
int test_d3s2_mode23_nonempty_success(void);
int test_d3s2_p0_7_mode24_reply_count0_empty_success(void);
int test_d3s2_mode24_reply_one_success(void);
int test_d3s2_p0_7_mode24_declared_missing_reply_fail(void);
int test_d3s2_mode25_retry_zero_success(void);
int test_d3s2_mode25_retry_one_success(void);
int test_d3s2_mode25_recent_without_cumulative_fail(void);
int test_d3s2_mode26_management_zero_success(void);
int test_d3s2_mode26_management_one_success(void);
int test_d3s2_mode26_management_without_spool_fail(void);
int test_d3s2_empty_carrier_empty_secondary_success(void);
int test_d3s2_p1_mode21_bind_carrier_absent(void);
int test_d3s2_port_failure_no_note(void);

int ninlil_d3s2_run_all_tests(void);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_DOMAIN_STORE_D3S2_TEST_SCENARIOS_H */
