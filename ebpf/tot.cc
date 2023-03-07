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

static std::string current_cgroup_mount_path()
{
	std::ifstream ifs;
	std::string line;
	std::string type, path;

	ifs.open("/proc/self/mounts");
	while (std::getline(ifs, line)) {
		std::istringstream iss(line);
		if (!(iss >> type >> path))
			break;

		if (type == "cgroup2")
			break;
	}
	ifs.close();

	return path;
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

	std::string cgroup_mount_path = current_cgroup_mount_path();
	cgroup_fd = open(cgroup_mount_path.data(), O_RDONLY);
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
