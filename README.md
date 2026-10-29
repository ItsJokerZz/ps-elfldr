# ps-elfldr
An ELF loader for jailbroken PS4 and PS5 systems, one source tree for both
consoles. Payloads run in separate processes, so the loader keeps running if one
crashes. It supports dynamic linking with SPRX files and resolves symbols at
runtime.

It is modified from the work of [John Törnblom][john]: the
[ps4-payload-elfldr][ps4-elfldr] and the [ps5-payload-elfldr][ps5-elfldr]. It is
built with the my modified and unified [ps-payload-sdk][sdk].

## Choosing a console
Commands take the console as a word, `<ps4 | ps5 | all>`. Leave it out and you
get `all`, so `make` builds both consoles. The word works with any goal and can
go anywhere, e.g., `make ps5 clean`. `make test` sends the loader to a console,
so it needs one: `make ps5 test`.

## Quick-start
**PS5.** Start a kernel exploit that provides a basic ELF loader on port 9020,
e.g., [BD-J ps5-payload-loader][bdj] or the [webkit approach from Specter][webkit],
then run:
```console
$ export PS5_HOST=ps5
$ export PS5_PORT=9020
$ wget -q -O - https://github.com/ps5-payload-dev/elfldr/releases/latest/download/elfldr-ps5.elf | nc -q0 $PS5_HOST $PS5_PORT
```

**PS4.** Start a kernel exploit for your firmware and send over `bin_loader.lua`
(it also accepts basic ELF files). This script does it with the lapse exploit:
```bash
#!/usr/bin/env bash

PS4_HOST=ps4

SEND_LUA=https://raw.githubusercontent.com/shahrilnet/remote_lua_loader/refs/heads/main/payloads/send_lua.py
LAPSE=https://raw.githubusercontent.com/shahrilnet/remote_lua_loader/refs/heads/main/payloads/lapse.lua
BIN_LOADER=https://raw.githubusercontent.com/shahrilnet/remote_lua_loader/refs/heads/main/payloads/bin_loader.lua

wget -qO- $LAPSE      | python3 <(wget -qO- $SEND_LUA) $PS4_HOST 9026 /dev/stdin
wget -qO- $BIN_LOADER | python3 <(wget -qO- $SEND_LUA) $PS4_HOST 9026 /dev/stdin
```
Then deploy the loader you built (see [Building](#building)):
```console
$ export PS4_HOST=ps4 PS4_PORT=9020
$ make ps4 test
```

## Usage examples
The loader listens on port 9021. The examples use the PS5, set `PS4_HOST` and
`PS4_PORT` for the PS4.
```console
$ export PS5_HOST=ps5
$ export PS5_PORT=9021
$ export PS5_PAYLOAD=payload.elf # from local storage
$ nc -q0 $PS5_HOST $PS5_PORT < $PS5_PAYLOAD
$
$ export PS5_PAYLOAD=file:/data/payload.elf # from console storage
$ echo "$PS5_PAYLOAD" | nc -q0 $PS5_HOST $PS5_PORT
$
$ export PS5_PAYLOAD=https://github.com/ps5-payload-dev/ftpsrv/releases/latest/download/ftpsrv-ps5.elf
$ echo "$PS5_PAYLOAD" | nc -q0 $PS5_HOST $PS5_PORT
$
$ curl "http://$PS5_HOST:$PS5_PORT?uri=$PS5_PAYLOAD"
$
$ export PS5_PAYLOAD=payload.elf # from local storage, via http post
$ curl --data-binary "@$PS5_PAYLOAD" "http://$PS5_HOST:$PS5_PORT/$PS5_PAYLOAD?args=-v&pipe=0"
```

A payload URI takes query parameters, e.g., `file:/data/payload.elf?args=-v&pipe=0`:
- `args`: command line arguments for the payload, separated by spaces (escape a
  space that belongs to an argument with a backslash).
- `pipe`: `0`, `false` or `no` keeps the payload's standard output from being
  redirected to the connection.

The loader itself takes `-p PORT` to listen on another port and `-q` to skip the
on-screen notification at start-up.

## Building
With the [ps-payload-sdk][sdk] installed for the console(s) you build for, on a
Debian-based system:
```console
$ sudo apt-get install git
$ export PS4_PAYLOAD_SDK=/opt/ps-payload-sdk/ps4
$ export PS5_PAYLOAD_SDK=/opt/ps-payload-sdk/ps5
$ make <ps4 | ps5 | all>
$ make <ps4 | ps5 | all> clean
```
Each console builds into its own `build/ps4` or `build/ps5` folder, and `clean`
only removes the console you name. Only the variable of the console you build for
has to be set. The result is `build/ps4/elfldr-ps4.elf` (plus `elfldr-ps4.bin`)
and `build/ps5/elfldr-ps5.elf`. CI builds the SDK first, then the loader with it.

## Dependencies
The ptrace helpers come from [lib-ps-ptrace][ptrace]. The Makefile clones it into
`.deps/lib-ps-ptrace` the first time it is needed and builds `libptrace.a` for the
console. To use your own checkout or another source:
```console
$ make ps5 PTRACE_DIR=~/src/lib-ps-ptrace
$ make ps5 PTRACE_REPO=https://example.com/lib-ps-ptrace.git
```

## Source layout
`shared` has the sources used by both consoles, `ps4` and `ps5` the rest, and
`make.ps4` and `make.ps5` the build rules of each console.

## Reporting bugs
[File a GitHub issue](../../issues/new/choose) for problems with ps-elfldr.
For a pull request that changes more than a few lines, file an issue first so the
solution can be discussed before you spend time on it.

## License
ps-elfldr is licensed under the GPLv3+.

[john]: https://github.com/john-tornblom
[ps4-elfldr]: https://github.com/ps4-payload-dev/elfldr
[ps5-elfldr]: https://github.com/ps5-payload-dev/elfldr
[bdj]: https://github.com/john-tornblom/bdj-sdk/tree/master/samples/ps5-payload-loader
[webkit]: https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit
[sdk]: https://github.com/ItsJokerZz/ps-payload-sdk
[ptrace]: https://github.com/ItsJokerZz/lib-ps-ptrace
