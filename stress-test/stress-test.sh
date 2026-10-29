#!/usr/bin/env bash
#   Copyright (C) 2024 John Törnblom
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

SCRIPTDIR="${BASH_SOURCE[0]}"
SCRIPTDIR="$(dirname "${SCRIPTDIR}")"

cd $SCRIPTDIR || exit 1

CONSOLE="$1"
case "$CONSOLE" in
    ps4|ps5) ;;
    *) echo "usage: $0 <ps4 | ps5>"; exit 1 ;;
esac

echo "Deploying getpid_test.elf 5000 times..."
sleep 3

for i in {1..5000}
do
    make $CONSOLE test || exit 1
done
