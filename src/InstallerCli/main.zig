const std = @import("std");
const builtin = @import("builtin");
const Args = @import("Args");
const Backend = @import("Backend");

pub fn main() !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const raw = try std.process.argsAlloc(alloc);
    const argv = if (raw.len > 0) raw[1..] else raw[0..0];
    const action = Args.parse(argv) catch |err| {
        std.debug.print("usage: InstallerCli [-l|-i [-s] [-o]|-u [-k]|-r|-w] ({s})\n", .{@errorName(err)});
        std.process.exit(2);
    };

    if (builtin.os.tag != .windows) {
        std.debug.print("dry-run (non-Windows host): action={s}\n", .{@tagName(action)});
        return;
    }

    switch (action) {
        .list, .health => {
            const h = Backend.healthCheck() catch |err| fatal(err);
            std.debug.print("hook={} present={} running={}\n", .{
                h.service_dll_points_at_hook,
                h.hook_file_present,
                h.service_running,
            });
        },
        .install => |o| Backend.install(o.system32_layout, o.overwrite) catch |err| fatal(err),
        .uninstall => |o| Backend.uninstall(o.keep_config) catch |err| fatal(err),
        .restart => Backend.restartServices() catch |err| fatal(err),
    }
    std.debug.print("ok\n", .{});
}

fn fatal(err: Backend.BackendError) noreturn {
    const msg: []const u8 = switch (err) {
        Backend.BackendError.AccessDenied => "access denied: run as Administrator",
        Backend.BackendError.NotFound => "not found: TermService or registry key missing",
        Backend.BackendError.RegistryFailed => "registry operation failed",
        Backend.BackendError.ServiceFailed => "service operation failed",
        Backend.BackendError.FileFailed => "file operation failed",
        Backend.BackendError.BadConfig => "refusing: third-party ServiceDll (retry with -o to overwrite)",
        Backend.BackendError.UnsupportedOs => "windows only",
        Backend.BackendError.OutOfMemory => "out of memory",
    };
    std.debug.print("error: {s}\n", .{msg});
    std.process.exit(1);
}
