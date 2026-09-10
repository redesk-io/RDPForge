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
            const h = try Backend.healthCheck();
            std.debug.print("hook={} present={} running={}\n", .{
                h.service_dll_points_at_hook,
                h.hook_file_present,
                h.service_running,
            });
        },
        .install => |o| try Backend.install(o.system32_layout, o.overwrite),
        .uninstall => |o| try Backend.uninstall(o.keep_config),
        .restart => try Backend.restartServices(),
    }
}
