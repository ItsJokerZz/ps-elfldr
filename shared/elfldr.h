/* Copyright (C) 2024 John Törnblom
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

#pragma once

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

/**
 * Shared state used while loading an ELF image.
 **/
typedef struct elfldr_ctx {
  const uint8_t *elf;
  pid_t pid;

  intptr_t base_addr;
  size_t base_size;
  uintptr_t min_vaddr;
  void *base_mirror;
} elfldr_ctx_t;

int r_relative(elfldr_ctx_t *ctx, const Elf64_Rela *rela);
int data_load(elfldr_ctx_t *ctx, const Elf64_Phdr *phdr);
int elfldr_page_protection(const Elf64_Phdr *phdr, unsigned count,
                           uintptr_t page);
int elfldr_set_procname(pid_t pid, const char *name);

/**
 * Find the id of a process with the given name.
 **/
pid_t elfldr_find_pid(const char *name);

/**
 * Map an ELF into the address space of a process and return its entry point,
 * or 0 on failure. Only R_X86_64_RELATIVE relocations are applied.
 **/
intptr_t elfldr_load(pid_t pid, const uint8_t *elf);

/**
 * Spawn a new process that executes the given ELF file.
 **/
pid_t elfldr_spawn(int stdio, char *const argv[], const uint8_t *elf,
                   size_t elf_size);

/**
 * Execute an ELF file in a given process.
 **/
int elfldr_exec(pid_t pid, int stdio, const uint8_t *elf);

/**
 * Read an ELF from the given socket.
 **/
int elfldr_read(int fd, uint8_t **elf, size_t *elf_size);

/**
 * Ensure the data is in the ELF format.
 **/
int elfldr_sanity_check(const uint8_t *elf, size_t elf_size);

#ifdef __PROSPERO__
/**
 * Create payload args in the address space of the process with the given pid.
 **/
intptr_t elfldr_payload_args(pid_t pid);
#endif

/**
 * Raise privileges for the process with the given pid.
 **/
int elfldr_raise_privileges(pid_t pid);
