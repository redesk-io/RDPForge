const std = @import("std");
const Args = @import("Args");
const Plan = @import("Plan");

test "args: defaults to list, parses all flags" {
    try std.testing.expect((try Args.parse(&.{})) == .list);
    try std.testing.expect((try Args.parse(&.{"-l"})) == .list);
    try std.testing.expect((try Args.parse(&.{"-r"})) == .restart);
    try std.testing.expect((try Args.parse(&.{"-w"})) == .health);
    const i = try Args.parse(&.{ "-i", "-s", "-o" });
    try std.testing.expect(i.install.system32_layout and i.install.overwrite);
    const u = try Args.parse(&.{"-u"});
    try std.testing.expect(!u.uninstall.keep_config);
    const uk = try Args.parse(&.{ "-u", "-k" });
    try std.testing.expect(uk.uninstall.keep_config);
    try std.testing.expectError(error.UnknownFlag, Args.parse(&.{"-bogus"}));
    try std.testing.expectError(error.UnknownFlag, Args.parse(&.{ "-i", "-k" }));
}

test "plan: install dir + hook path join" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const dir = try Plan.defaultInstallDir(arena.allocator(), "C:\\Program Files");
    try std.testing.expect(std.mem.endsWith(u8, dir, Plan.install_subdir));
    const dll = try Plan.hookDllPath(arena.allocator(), dir);
    try std.testing.expect(std.mem.endsWith(u8, dll, Plan.hook_dll_name));
}

test "plan: rollback reverses completed prefix" {
    const done = [_]Plan.Step{ .stop_services, .copy_files, .set_acls };
    var out: [8]Plan.Step = undefined;
    const rb = Plan.rollbackFor(&done, &out);
    try std.testing.expect(rb.len == 3);
    try std.testing.expect(rb[0] == .set_acls);
    try std.testing.expect(rb[1] == .copy_files);
    try std.testing.expect(rb[2] == .stop_services);
    try std.testing.expect(Plan.install_order[0] == .stop_services);
    try std.testing.expect(Plan.install_order[Plan.install_order.len - 1] == .create_task);
}
