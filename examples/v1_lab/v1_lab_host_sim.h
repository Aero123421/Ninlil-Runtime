#ifndef V1_LAB_HOST_SIM_H
#define V1_LAB_HOST_SIM_H

/*
 * V1-LAB item 10b host simulation example harness (build-tree only).
 * Not part of the public installable ABI.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Controller downlink submit→delivery on full C4/C5 integration topology. */
int v1_lab_host_sim_run_controller(const char *workdir);

/* Cell Agent custody leg on the same topology (USB custody + radio TX). */
int v1_lab_host_sim_run_cell(const char *workdir);

#ifdef __cplusplus
}
#endif

#endif /* V1_LAB_HOST_SIM_H */
