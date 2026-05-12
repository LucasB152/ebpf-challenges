#ifndef OPERATING_SYSTEMS_PROJECT_2_MONITOR_H
#define OPERATING_SYSTEMS_PROJECT_2_MONITOR_H

#define EVENT_TOO_HIGH 0
#define EVENT_SCHEDULE_CHECK 1

#define MAX_FAULTS 10000

struct pff_config {
    __u32 upper_bound_freq_ms;      // max page faults per ms
    __u32 lower_bound_freq_ms;      // min page faults per ms
    __u32 time_window_ms;           // sliding window duration in ms
};

struct pff_state {
    __u64 write_idx;                // next slot to write in circular buffer
    __u64 first_fault_timestamp;    // timestamp of first observed fault
};

struct pff_event {
    __u32 type;                     // type of event (EVENT_TOO_HIGH / EVENT_SCHEDULE_CHECK)
    __u32 pid;                      // process id
    __u64 deadline_ns;              // for SCHEDULE_CHECK: when to check lower bound
    __u64 first_fault_timestamp;    // so user-space knows when monitoring started
    __u64 window_ns;                // window size in ns
    __u64 write_idx;                // write index at the schedule
};

#endif //OPERATING_SYSTEMS_PROJECT_2_MONITOR_H