#   Copyright (C) 2025 John Törnblom
#   Copyright (C) 2026 ItsJokerZz
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

ifndef PLATFORM
include platforms.mk
else

BUILD := build/$(PLATFORM)

PTRACE_REPO ?= https://github.com/ItsJokerZz/lib-ps-ptrace.git
PTRACE_DIR  ?= .deps/lib-ps-ptrace
PTRACE      := $(PTRACE_DIR)/build/$(PLATFORM)/libptrace.a

# its headers are needed by the first object that gets compiled
all test: $(PTRACE_DIR)/include/ptrace.h

include make.$(PLATFORM)

CFLAGS += -Ishared -I$(PLATFORM) -I$(BUILD) -I$(PTRACE_DIR)/include

vpath %.c shared $(PLATFORM)

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(PTRACE_DIR)/include/ptrace.h:
	git clone --depth 1 $(PTRACE_REPO) $(PTRACE_DIR)

$(PTRACE): $(PTRACE_DIR)/include/ptrace.h $(wildcard $(PTRACE_DIR)/src/*)
	$(MAKE) -C $(PTRACE_DIR) PLATFORM=$(PLATFORM) all

clean:
	rm -rf $(BUILD)

format:
	clang-format -i $(wildcard shared/*.c shared/*.h ps4/*.c ps4/*.h ps5/*.c ps5/*.h)

endif
