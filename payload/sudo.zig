const std = @import("std");
const l = std.os.linux;

pub const std_options: std.Options = .{
    // We don't need a stack, with this we safe 1 syscall and some codegen of the entrypoint.
    .signal_stack_size = null,
};

pub fn main(init: std.process.Init.Minimal) void {
    _ = l.setuid(0);
    const args: [:null]const ?[*:0]const u8 = @ptrCast(init.args.vector);
    const env: std.process.Environ.PosixBlock = init.environ.block;
    _ = l.execve(@ptrCast(args[1]), args.ptr[1..], env.slice.ptr);
}
