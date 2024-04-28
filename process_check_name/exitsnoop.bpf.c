#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "exitsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define PROC_NAME "dotnet"
#define NAME_LEN sizeof(PROC_NAME) - 1 // Length of the process name string


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, tid;
    u64 id, ts, *start_ts, start_time = 0;

    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task();
    start_time = BPF_CORE_READ(task, start_time);

    e->duration_ns = bpf_ktime_get_ns() - start_time;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    //check if current process name has same actual length to search keyword.
    if((e->comm[NAME_LEN+1]=='\0')){
                //check if current process name has same name as search keyword.
            int check_process_name = __builtin_memcmp(e->comm, PROC_NAME, NAME_LEN);
            char fmt[] = "memcmp result: %s\n";
            bpf_trace_printk(fmt, sizeof(fmt), e->comm);
            if(check_process_name == 0 ) {
                    /* send data to user-space for post-processing */
                    bpf_ringbuf_submit(e, 0);
                    return 0;
            }
    }

    bpf_ringbuf_discard(e,0);


    return 0;
}
