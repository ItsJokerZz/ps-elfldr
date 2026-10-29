#   Copyright (C) 2026 ItsJokerZz
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

# Without PLATFORM the Makefile runs its goals once per console. "make" and
# "make all" build ps4 and ps5, "make ps4" or "make ps5" only that one, and a
# console can be combined with a goal, as in "make ps5 clean". "all" can be
# the console too, "make all clean" cleans both.
#
# "make test" sends the loader to a console, so it needs one: "make ps5 test".

MAIN     := $(firstword $(MAKEFILE_LIST))
CONSOLES := $(filter ps4 ps5,$(MAKECMDGOALS))
GOALS    := $(filter-out ps4 ps5,$(MAKECMDGOALS))

# in front of other goals "all" only names both consoles, as in "make all clean"
ifeq ($(word 1,$(GOALS)),all)
    ifneq ($(word 2,$(GOALS)),)
        GOALS := $(wordlist 2,$(words $(GOALS)),$(GOALS))
    endif
endif

ifeq ($(CONSOLES),)
    ifneq ($(filter test,$(GOALS)),)
        $(error make test needs a console, e.g., make ps5 test)
    endif
    CONSOLES := ps4 ps5
endif

.DEFAULT_GOAL := all
.PHONY: all ps4 ps5 $(GOALS) run

all ps4 ps5 $(GOALS): run

run:
	@for c in $(CONSOLES); do $(MAKE) -f $(MAIN) PLATFORM=$$c $(or $(GOALS),all) || exit 1; done
