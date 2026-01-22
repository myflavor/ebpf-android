#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, uint32_t);
    __type(value, uint32_t);
} cpu_pid_map SEC(".maps");

struct switch_args {
    unsigned long long ignore;
    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    long long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int tp_sched_switch(struct switch_args *args) {
    uint32_t key;
    uint32_t val;

    key = bpf_get_smp_processor_id(); 
    val = args->next_pid;             

    bpf_map_update_elem(&cpu_pid_map, &key, &val, BPF_ANY);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";