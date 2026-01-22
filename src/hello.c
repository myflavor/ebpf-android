#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int running = 1;
void sig_handler(int sig) { running = 0; }

int main()
{
    struct bpf_object *obj;
    struct bpf_link *link = NULL;
    const char *obj_path = "hello.bpf.o";
    int map_fd;

    signal(SIGINT, sig_handler);

    obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "[-] Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj))
    {
        fprintf(stderr, "[-] Failed to load BPF object\n");
        goto cleanup;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "tp_sched_switch");
    if (!prog)
    {
        fprintf(stderr, "[-] Failed to find program 'tp_sched_switch'\n");
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link))
    {
        fprintf(stderr, "[-] Failed to attach BPF program\n");
        goto cleanup;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "cpu_pid_map");

    printf("[+] Press Ctrl+C to exit...\n");

    while (running)
    {
        uint32_t key = 0, next_key;
        uint32_t value;
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
        {
            bpf_map_lookup_elem(map_fd, &next_key, &value);
            printf("Key: %d, Value: %d\n", next_key, value);
            key = next_key;
        }
        usleep(500000);
    }

    printf("\n[-] Cleaning up...\n");

cleanup:
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}