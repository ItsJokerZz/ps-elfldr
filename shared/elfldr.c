/* Copyright (C) 2025 John Törnblom
   Copyright (C) 2026 ItsJokerZz

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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <ptrace.h>

#include "elfldr.h"
#include "log.h"

#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)                                                             \
  ((((x) & PF_R) ? PROT_READ : 0) | (((x) & PF_W) ? PROT_WRITE : 0)           \
   | (((x) & PF_X) ? PROT_EXEC : 0))

/**
 * Parse a R_X86_64_RELATIVE relocatable.
 **/
int
r_relative(elfldr_ctx_t *ctx, const Elf64_Rela *rela) {
  intptr_t *loc;
  intptr_t val;

  if(rela->r_offset < ctx->min_vaddr || ctx->base_size < sizeof(*loc)
     || rela->r_offset - ctx->min_vaddr > ctx->base_size - sizeof(*loc)) {
    return -1;
  }

  loc = (intptr_t *)((uint8_t *)ctx->base_mirror
                     + rela->r_offset - ctx->min_vaddr);
  val = ctx->base_addr - ctx->min_vaddr + rela->r_addend;
  *loc = val;

  return 0;
}

/**
 * Parse a PT_LOAD program header.
 **/
int
data_load(elfldr_ctx_t *ctx, const Elf64_Phdr *phdr) {
  uint64_t offset;

  if(!phdr->p_memsz || !phdr->p_filesz) {
    return 0;
  }

  if(phdr->p_filesz > phdr->p_memsz || phdr->p_vaddr < ctx->min_vaddr) {
    return -1;
  }

  offset = phdr->p_vaddr - ctx->min_vaddr;
  if(offset > ctx->base_size || phdr->p_filesz > ctx->base_size - offset) {
    return -1;
  }

  memcpy((uint8_t *)ctx->base_mirror + offset, ctx->elf + phdr->p_offset,
         phdr->p_filesz);
  return 0;
}

static int
elfldr_in_bounds(uint64_t off, uint64_t len, size_t size) {
  return off <= size && len <= size - off;
}

/**
 * Ensure the data is a well-formed ELF, so that the program and section
 * headers, the segments, and the relocation tables can be read without
 * leaving the buffer.
 **/
int
elfldr_sanity_check(const uint8_t *elf, size_t elf_size) {
  const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf;
  const Elf64_Phdr *phdr;
  const Elf64_Shdr *shdr;

  if(elf_size < sizeof(Elf64_Ehdr)) {
    return -1;
  }

  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E'
     || ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F'
     || ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
    return -1;
  }

  if(ehdr->e_phnum) {
    if(ehdr->e_phentsize != sizeof(Elf64_Phdr)
       || !elfldr_in_bounds(ehdr->e_phoff,
                            (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr),
                            elf_size)) {
      return -1;
    }

    phdr = (const Elf64_Phdr *)(elf + ehdr->e_phoff);
    for(int i = 0; i < ehdr->e_phnum; i++) {
      if(!elfldr_in_bounds(phdr[i].p_offset, phdr[i].p_filesz, elf_size)) {
        return -1;
      }

      if(phdr[i].p_type == PT_LOAD
         && (phdr[i].p_filesz > phdr[i].p_memsz
             || phdr[i].p_memsz > UINT64_MAX - phdr[i].p_vaddr)) {
        return -1;
      }
    }
  }

  if(ehdr->e_shnum) {
    if(ehdr->e_shentsize != sizeof(Elf64_Shdr)
       || !elfldr_in_bounds(ehdr->e_shoff,
                            (uint64_t)ehdr->e_shnum * sizeof(Elf64_Shdr),
                            elf_size)) {
      return -1;
    }

    shdr = (const Elf64_Shdr *)(elf + ehdr->e_shoff);
    for(int i = 0; i < ehdr->e_shnum; i++) {
      if(shdr[i].sh_type == SHT_RELA
         && !elfldr_in_bounds(shdr[i].sh_offset, shdr[i].sh_size, elf_size)) {
        return -1;
      }
    }
  }

  return 0;
}

/**
 * Get the protection bits of a page, combining every segment that covers it.
 **/
int
elfldr_page_protection(const Elf64_Phdr *phdr, unsigned count, uintptr_t page) {
  int prot = 0;

  for(unsigned i = 0; i < count; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    uintptr_t start = TRUNC_PG(phdr[i].p_vaddr);
    uintptr_t end = ROUND_PG(phdr[i].p_vaddr + phdr[i].p_memsz);

    if(page >= start && page < end) {
      prot |= PFLAGS(phdr[i].p_flags);
    }
  }

  return prot;
}

/**
 * Set the name of a process.
 **/
int
elfldr_set_procname(pid_t pid, const char *name) {
  char comm[MAXCOMLEN + 1];
  intptr_t buf;

  if((buf = pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0))
     == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    return -1;
  }

  strncpy(comm, name, sizeof(comm) - 1);
  comm[sizeof(comm) - 1] = 0;

  pt_copyin(pid, comm, buf, strlen(comm) + 1);

  pt_syscall(pid, SYS_thr_set_name, -1, buf);
  pt_msync(pid, buf, PAGE_SIZE, MS_SYNC);
  pt_munmap(pid, buf, PAGE_SIZE);

  return 0;
}

/**
 * Find the pid of a process with the given name.
 **/
pid_t
elfldr_find_pid(const char *name) {
  int mib[4] = { 1, 14, 8, 0 };
  pid_t mypid = getpid();
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    LOG_PERROR("sysctl");
    return -1;
  }

  if(!(buf = malloc(buf_size))) {
    LOG_PERROR("malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    LOG_PERROR("sysctl");
    free(buf);
    return -1;
  }

  for(uint8_t *ptr = buf; ptr < (buf + buf_size);) {
    int ki_structsize = *(int *)ptr;
    pid_t ki_pid = *(pid_t *)&ptr[72];
    char *ki_tdname = (char *)&ptr[447];

    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname) && ki_pid != mypid) {
      pid = ki_pid;
    }
  }

  free(buf);

  return pid;
}
