#include "tot.skel.h"
#include <assert.h>
#include <fcntl.h>
#include <fstream>
#include <signal.h>
#include <sstream>
#include <string>
#include <unistd.h>

static volatile bool running = true;

static void handle_signal(int sig)
{
	running = false;
}

int main()
{
	struct tot_bpf *skel = NULL;
	int cgroup_fd;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	skel = tot_bpf__open_and_load();
	assert(skel);

	assert(!tot_bpf__attach(skel));

	cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
	assert(cgroup_fd);
	skel->links.sockops_write_tcp_options =
		bpf_program__attach_cgroup(skel->progs.sockops_write_tcp_options, cgroup_fd);
	assert(skel->links.sockops_write_tcp_options);
	close(cgroup_fd);

	while (running) {
		sleep(1);
	}

	bpf_link__detach(skel->links.sockops_write_tcp_options);
	tot_bpf__detach(skel);
	tot_bpf__destroy(skel);
}
