/* Copyright (C) 2024 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <elf.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps5/kernel.h>

#include "elfldr.h"
#include "log.h"
#include <ptrace.h>


#ifndef IPV6_2292PKTOPTIONS
#define IPV6_2292PKTOPTIONS 25
#endif


/**
 * Convenient macros.
 **/
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))


/**
 * Absolute path to the SceSpZeroConf eboot.
 **/
static const char* SceSpZeroConf = "/system/vsh/app/NPXS40112/eboot.bin";


/**
 * Load an ELF into the address space of a process with the given pid.
 **/
intptr_t
elfldr_load(pid_t pid, const uint8_t *elf) {
  const Elf64_Ehdr *ehdr = (const Elf64_Ehdr*)elf;
  const Elf64_Phdr *phdr = (const Elf64_Phdr*)(elf + ehdr->e_phoff);
  const Elf64_Shdr *shdr = (const Elf64_Shdr*)(elf + ehdr->e_shoff);

  elfldr_ctx_t ctx = {.elf = elf, .pid=pid};

  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  int error = 0;

  // Compute size of virtual memory region.
  for(int i=0; i<ehdr->e_phnum; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }

    if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }

  if(min_vaddr == (size_t)-1) {
    LOG_PUTS("elfldr_load: ELF has no loadable segments");
    return 0;
  }

  min_vaddr = TRUNC_PG(min_vaddr);
  max_vaddr = ROUND_PG(max_vaddr);
  ctx.base_size = max_vaddr - min_vaddr;
  ctx.min_vaddr = min_vaddr;

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  int prot = PROT_READ | PROT_WRITE;
  if(ehdr->e_type == ET_DYN) {
    ctx.base_addr = 0;
  } else if(ehdr->e_type == ET_EXEC) {
    ctx.base_addr = min_vaddr;
    flags |= MAP_FIXED;
  } else {
    LOG_PUTS("elfldr_load: ELF type not supported");
    return 0;
  }

  if(!(ctx.base_mirror=malloc(ctx.base_size))) {
    LOG_PERROR("malloc");
    return 0;
  }

  // Reserve an address space of sufficient size.
  if((ctx.base_addr=pt_mmap(pid, ctx.base_addr, ctx.base_size, prot,
			    flags, -1, 0)) == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    free(ctx.base_mirror);
    return 0;
  }

  // Parse program headers.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    switch(phdr[i].p_type) {
    case PT_LOAD:
      error = data_load(&ctx, &phdr[i]);
      break;
    }
  }

  // Apply relocations.
  for(int i=0; i<ehdr->e_shnum && !error; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    const Elf64_Rela* rela = (const Elf64_Rela*)(elf + shdr[i].sh_offset);
    for(int j=0; j<shdr[i].sh_size/sizeof(Elf64_Rela) && !error; j++) {
      switch(rela[j].r_info & 0xffffffffl) {
      case R_X86_64_RELATIVE:
	error = r_relative(&ctx, &rela[j]);
	break;
      }
    }
  }

  if(pt_copyin(ctx.pid, ctx.base_mirror, ctx.base_addr, ctx.base_size)) {
    LOG_PERROR("pt_copyin");
    error = 1;
  }

  // Set protection bits on mapped pages, once for each run of equal pages.
  for(size_t page=min_vaddr; page<max_vaddr && !error;) {
    int pbits = elfldr_page_protection(phdr, ehdr->e_phnum, page);
    size_t end = page + PAGE_SIZE;

    while(end < max_vaddr &&
          elfldr_page_protection(phdr, ehdr->e_phnum, end) == pbits) {
      end += PAGE_SIZE;
    }

    if(pbits & PROT_EXEC) {
      if(kernel_mprotect(pid, ctx.base_addr + page - min_vaddr,
                         end - page, pbits)) {
	LOG_PERROR("kernel_mprotect");
	error = 1;
      }
    } else {
      if(pt_mprotect(pid, ctx.base_addr + page - min_vaddr,
		     end - page, pbits)) {
	LOG_PT_PERROR(pid, "pt_mprotect");
	error = 1;
      }
    }

    page = end;
  }

  if(pt_msync(pid, ctx.base_addr, ctx.base_size, MS_SYNC)) {
    LOG_PT_PERROR(pid, "pt_msync");
    error = 1;
  }

  free(ctx.base_mirror);

  if(error) {
    pt_munmap(pid, ctx.base_addr, ctx.base_size);
    return 0;
  }

  return ctx.base_addr + ehdr->e_entry - min_vaddr;
}


/**
 * Create payload args in the address space of the process with the given pid.
 **/
intptr_t
elfldr_payload_args(pid_t pid) {
  int victim_sock;
  int master_sock;
  intptr_t buf;
  int pipe0;
  int pipe1;

  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    return 0;
  }

  if((master_sock=pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    LOG_PT_PERROR(pid, "pt_socket");
    return 0;
  }

  pt_setint(pid, buf+0x00, 20);
  pt_setint(pid, buf+0x04, IPPROTO_IPV6);
  pt_setint(pid, buf+0x08, IPV6_TCLASS);
  pt_setint(pid, buf+0x0c, 0);
  pt_setint(pid, buf+0x10, 0);
  pt_setint(pid, buf+0x14, 0);
  if(pt_setsockopt(pid, master_sock, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, 24)) {
    LOG_PT_PERROR(pid, "pt_setsockopt");
    return 0;
  }

  if((victim_sock=pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    LOG_PT_PERROR(pid, "pt_socket");
    return 0;
  }

  pt_setint(pid, buf+0x00, 0);
  pt_setint(pid, buf+0x04, 0);
  pt_setint(pid, buf+0x08, 0);
  pt_setint(pid, buf+0x0c, 0);
  pt_setint(pid, buf+0x10, 0);
  if(pt_setsockopt(pid, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20)) {
    LOG_PT_PERROR(pid, "pt_setsockopt");
    return 0;
  }

  if(kernel_overlap_sockets(pid, master_sock, victim_sock)) {
    LOG_PUTS("kernel_overlap_sockets failed");
    return 0;
  }

  if(pt_pipe(pid, buf)) {
    LOG_PT_PERROR(pid, "pt_pipe");
    return 0;
  }
  pipe0 = pt_getint(pid, buf);
  pipe1 = pt_getint(pid, buf+4);

  intptr_t args       = buf;
  intptr_t rwpipe     = buf + 0x100;
  intptr_t rwpair     = buf + 0x200;
  intptr_t kpipe_addr = kernel_get_proc_file(pid, pipe0);
  intptr_t payloadout = buf + 0x300;
  intptr_t getpid      = pt_resolve(pid, "HoLVWNanBBc");

  pt_setlong(pid, args + 0x00, getpid);
  pt_setlong(pid, args + 0x08, rwpipe);
  pt_setlong(pid, args + 0x10, rwpair);
  pt_setlong(pid, args + 0x18, kpipe_addr);
  pt_setlong(pid, args + 0x20, KERNEL_ADDRESS_DATA_BASE);
  pt_setlong(pid, args + 0x28, payloadout);
  pt_setint(pid, rwpipe + 0, pipe0);
  pt_setint(pid, rwpipe + 4, pipe1);
  pt_setint(pid, rwpair + 0, master_sock);
  pt_setint(pid, rwpair + 4, victim_sock);
  pt_setint(pid, payloadout, 0);

  return args;
}


/**
 * Prepare registers of a process for execution of an ELF.
 **/
static int
elfldr_prepare_exec(pid_t pid, const uint8_t *elf) {
  intptr_t entry;
  intptr_t args;
  struct reg r;

  if(pt_getregs(pid, &r)) {
    LOG_PERROR("pt_getregs");
    return -1;
  }

  if(!(entry=elfldr_load(pid, elf))) {
    LOG_PUTS("elfldr_load failed");
    return -1;
  }

  if(!(args=elfldr_payload_args(pid))) {
    LOG_PUTS("elfldr_payload_args failed");
    return -1;
  }

  pt_setlong(pid, r.r_rsp-8, r.r_rip);
  r.r_rsp -= 8;
  r.r_rip = entry;
  r.r_rdi = args;

  if(pt_setregs(pid, &r)) {
    LOG_PERROR("pt_setregs");
    return -1;
  }

  return 0;
}


/**
 * Escape jail and raise privileges.
 **/
int
elfldr_raise_privileges(pid_t pid) {
  static const uint8_t caps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
				   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  intptr_t vnode;

  if(!(vnode=kernel_get_root_vnode())) {
    return -1;
  }
  if(kernel_set_proc_rootdir(pid, vnode)) {
    return -1;
  }
  if(kernel_set_proc_jaildir(pid, 0)) {
    return -1;
  }
  if(kernel_set_ucred_uid(pid, 0)) {
    return -1;
  }
  if(kernel_set_ucred_caps(pid, caps)) {
    return -1;
  }

  return 0;
}


/**
 * Execute an ELF inside the process with the given pid.
 **/
int
elfldr_exec(pid_t pid, int stdio, const uint8_t* elf) {
  uint8_t caps[16];
  intptr_t jaildir;
  intptr_t rootdir;
  uint64_t authid;
  int error = 0;

  // backup privileges
  jaildir = kernel_get_proc_jaildir(pid);
  if(!(rootdir=kernel_get_proc_rootdir(pid))) {
    LOG_PUTS("kernel_get_proc_rootdir failed");
    pt_detach(pid, 0);
    return -1;
  }
  if(kernel_get_ucred_caps(pid, caps)) {
    LOG_PUTS("kernel_get_ucred_caps failed");
    pt_detach(pid, 0);
    return -1;
  }
  if(!(authid=kernel_get_ucred_authid(pid))) {
    LOG_PUTS("kernel_get_ucred_authid failed");
    pt_detach(pid, 0);
    return -1;
  }

  if(elfldr_raise_privileges(pid)) {
    LOG_PUTS("Unable to raise privileges");
    pt_detach(pid, 0);
    return -1;
  }

  if(stdio > 0) {
    stdio = pt_rdup(pid, getpid(), stdio);

    pt_close(pid, STDERR_FILENO);
    pt_close(pid, STDOUT_FILENO);
    pt_close(pid, STDIN_FILENO);

    pt_dup2(pid, stdio, STDIN_FILENO);
    pt_dup2(pid, stdio, STDOUT_FILENO);
    pt_dup2(pid, stdio, STDERR_FILENO);

    pt_close(pid, stdio);
  }

  if(elfldr_prepare_exec(pid, elf)) {
    error = -1;
  }

  // restore privileges
  if(kernel_set_proc_jaildir(pid, jaildir)) {
    LOG_PUTS("kernel_set_proc_jaildir failed");
    error = -1;
  }
  if(kernel_set_proc_rootdir(pid, rootdir)) {
    LOG_PUTS("kernel_set_proc_rootdir failed");
    error = -1;
  }

  if(kernel_set_ucred_caps(pid, caps)) {
    LOG_PUTS("kernel_set_ucred_caps failed");
    error = -1;
  }
  if(kernel_set_ucred_authid(pid, authid)) {
    LOG_PUTS("kernel_set_ucred_authid failed");
    error = -1;
  }

  if(pt_detach(pid, 0)) {
    LOG_PERROR("pt_detach");
    error = -1;
  }

  return error;
}


/**
 * Set the heap size for libc.
 **/
static int
elfldr_set_heap_size(pid_t pid, ssize_t size) {
  intptr_t sceLibcHeapSize;
  intptr_t sceLibcParam;
  intptr_t sceProcParam;
  intptr_t Need_sceLibc;

  if(!(sceProcParam=pt_sceKernelGetProcParam(pid))) {
    LOG_PT_PERROR(pid, "pt_sceKernelGetProcParam");
    return -1;
  }

  if(pt_copyout(pid, sceProcParam+56, &sceLibcParam,
		sizeof(sceLibcParam))) {
    LOG_PERROR("pt_copyout");
    return -1;
  }

  if(pt_copyout(pid, sceLibcParam+16, &sceLibcHeapSize,
		sizeof(sceLibcHeapSize))) {
    LOG_PERROR("pt_copyout");
    return -1;
  }

  if(pt_setlong(pid, sceLibcHeapSize, size)) {
    LOG_PERROR("pt_setlong");
    return -1;
  }

  if(size != -1) {
    return 0;
  }

  if(pt_copyout(pid, sceLibcParam+72, &Need_sceLibc,
		sizeof(Need_sceLibc))) {
    LOG_PERROR("pt_copyout");
    return -1;
  }

  return pt_setlong(pid, sceLibcParam+32, Need_sceLibc);
}


static int
sys_budget_set(long budget) {
  return __syscall(0x23b, budget);
}


static int
elfldr_rfork_entry(void* argv) {
  if(sys_budget_set(0)) {
    klog_perror("sys_budget_set");
    return -1;
  }
  if(open("/dev/deci_stdin", O_RDONLY) < 0) {
    klog_perror("open");
    return -1;
  }
  if(open("/dev/deci_stdout", O_WRONLY) < 0) {
    klog_perror("open");
    return -1;
  }
  if(open("/dev/deci_stderr", O_WRONLY) < 0) {
    klog_perror("open");
    return -1;
  }

  if(syscall(SYS_ptrace, PT_TRACE_ME, 0, 0, 0) < 0) {
    klog_perror("syscall(SYS_ptrace)");
    return -1;
  }

  execve(SceSpZeroConf, argv, 0);
  klog_perror("execve");
  return -1;
}


/**
 * Execute an ELF inside a new process.
 **/
pid_t
elfldr_spawn(int stdio, char* const argv[], const uint8_t* elf, size_t payload_size) {
  intptr_t libkernel_entry;
  off_t need_reloc_offset;
  intptr_t eboot_entry;
  off_t main_offset;
  struct kevent evt;
  void *stack;
  pid_t pid;
  pid_t self;
  intptr_t authid;
  int kq;

  if((kq=kqueue()) < 0) {
    LOG_PERROR("kqueue");
    return -1;
  }

  if(!(stack=malloc(PAGE_SIZE))) {
    LOG_PERROR("malloc");
    close(kq);
    return -1;
  }

  self = getpid();
  if(!(authid=kernel_get_ucred_authid(self))) {
    LOG_PUTS("kernel_get_ucred_authid failed");
    free(stack);
    close(kq);
    return -1;
  }

  if(kernel_set_ucred_authid(self, 0x4800000000010003l)) {
    LOG_PUTS("kernel_set_ucred_authid failed");
    free(stack);
    close(kq);
    return -1;
  }

  if((pid=rfork_thread(RFPROC | RFCFDG | RFMEM, stack+PAGE_SIZE-8,
		       elfldr_rfork_entry, (void*)argv)) < 0) {
    LOG_PERROR("rfork_thread");
    if(kernel_set_ucred_authid(self, authid)) {
      LOG_PUTS("kernel_set_ucred_authid restore failed");
    }
    free(stack);
    close(kq);
    return -1;
  }

  if(kernel_set_ucred_authid(self, authid)) {
    LOG_PUTS("kernel_set_ucred_authid restore failed");
    kill(pid, SIGKILL);
    waitpid(pid, 0, 0);
    free(stack);
    close(kq);
    return -1;
  }

  EV_SET(&evt, pid, EVFILT_PROC, EV_ADD, NOTE_EXEC, 0, 0);
  if(kevent(kq, &evt, 1, &evt, 1, 0) < 0) {
    LOG_PERROR("kevent");
    kill(pid, SIGKILL);
    free(stack);
    close(kq);
    return -1;
  }

  if(waitpid(pid, 0, 0) < 0) {
    LOG_PERROR("waitpid");
    kill(pid, SIGKILL);
    free(stack);
    close(kq);
    return -1;
  }

  free(stack);
  close(kq);

  // The proc is now in the STOP state, with the instruction pointer pointing
  // at the libkernel entry.

  if(!(libkernel_entry=kernel_dynlib_entry_addr(pid, 1))) {
    LOG_PUTS("kernel_dynlib_entry_addr failed");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  if(!(eboot_entry=kernel_dynlib_entry_addr(pid, 0))) {
    LOG_PUTS("kernel_dynlib_entry_addr failed");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  if(kernel_get_fw_version() < 0x14000000) {
    need_reloc_offset = 15;
    main_offset = 58;
  } else {
    need_reloc_offset = 15;
    main_offset = 63;
  }

  // Continue execution until just after libkernel makes the syscall
  // sys_dynlib_process_needed_and_relocate.
  if(pt_breakat(pid, libkernel_entry + need_reloc_offset)) {
    LOG_PERROR("pt_breakat");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  // Allow libc to allocate arbitrary amount of memory.
  if(elfldr_set_heap_size(pid, -1)) {
    LOG_PUTS("elfldr_set_heap_size failed");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  // continue execution until just before main() is invoked.
  if(pt_breakat(pid, eboot_entry + main_offset)) {
    LOG_PERROR("pt_breakat");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  // Execute the ELF
  elfldr_set_procname(pid, argv[0]);
  if(elfldr_exec(pid, stdio, elf)) {
    kill(pid, SIGKILL);
    return -1;
  }

  return pid;
}


/**
 * Read an ELF from a given socket.
 **/
int
elfldr_read(int fd, uint8_t** elf, size_t* elf_size) {
  Elf64_Shdr *shdr;
  Elf64_Ehdr ehdr;
  uint8_t* buf;
  uint8_t* bak;
  size_t size;
  off_t shend;
  size_t rem;

  if(recv(fd, &ehdr, sizeof(ehdr), MSG_WAITALL) != sizeof(ehdr)) {
    return -1;
  }

  if(ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' ||
     ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
    errno = ENOEXEC;
    return -1;
  }

  if(ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
     ehdr.e_shentsize != sizeof(Elf64_Shdr) || !ehdr.e_shnum ||
     ehdr.e_shoff < sizeof(ehdr) ||
     ehdr.e_shoff > SIZE_MAX - ehdr.e_shnum * sizeof(Elf64_Shdr)) {
    errno = ENOEXEC;
    return -1;
  }

  size = ehdr.e_shoff + ehdr.e_shnum * sizeof(Elf64_Shdr);
  if(!(buf=malloc(size))) {
    return -1;
  }

  memcpy(buf, &ehdr, sizeof(ehdr));
  rem = size - sizeof(ehdr);
  if(recv(fd, buf + sizeof(ehdr), rem, MSG_WAITALL) != rem) {
    free(buf);
    return -1;
  }

  shend = 0;
  shdr = (Elf64_Shdr*)(buf + ehdr.e_shoff);
  for(int i=0; i<ehdr.e_shnum; i++) {
    if(shdr[i].sh_type == SHT_NOBITS) {
      continue;
    }
    if(shdr[i].sh_size > SIZE_MAX - shdr[i].sh_offset) {
      free(buf);
      errno = ENOEXEC;
      return -1;
    }
    size_t end = shdr[i].sh_offset + shdr[i].sh_size;
    if(end > shend) {
      shend = end;
    }
  }

  // sections appear before section headers
  if(shend <= size) {
    *elf = buf;
    *elf_size = size;
    return 0;
  }

  bak = buf;
  if(!(buf=realloc(buf, shend))) {
    free(bak);
    return -1;
  }

  rem = shend - size;
  if(recv(fd, buf + size, rem, MSG_WAITALL) != rem) {
    free(buf);
    return -1;
  }

  *elf = buf;
  *elf_size = shend;

  return 0;
}
