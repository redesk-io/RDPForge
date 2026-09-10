const std = @import("std");

pub fn main() !void {
    var args = std.process.args();
    _ = args.skip();
    const stdout = std.io.getStdOut().writer();
    const flag = args.next() orelse "-l";
    if (std.mem.eql(u8, flag, "-l")) {
        try stdout.print("RDPForge InstallerCli M0 skeleton (no changes made)\n", .{});
    } else {
        try stdout.print("flag {s} not yet implemented (M0)\n", .{flag});
    }
}
