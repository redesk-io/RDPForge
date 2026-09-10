const std = @import("std");

pub const Action = union(enum) {
    list,
    install: InstallOpts,
    uninstall: UninstallOpts,
    restart,
    health,

    pub const InstallOpts = struct { system32_layout: bool = false, overwrite: bool = false };
    pub const UninstallOpts = struct { keep_config: bool = false };
};

pub const ParseError = error{ UnknownFlag, MissingValue };

pub fn parse(argv: []const []const u8) ParseError!Action {
    if (argv.len == 0) return .list;
    const flag = argv[0];
    if (std.mem.eql(u8, flag, "-l")) return .list;
    if (std.mem.eql(u8, flag, "-r")) return .restart;
    if (std.mem.eql(u8, flag, "-w")) return .health;
    if (std.mem.eql(u8, flag, "-i")) {
        var opts: Action.InstallOpts = .{};
        for (argv[1..]) |a| {
            if (std.mem.eql(u8, a, "-s")) {
                opts.system32_layout = true;
            } else if (std.mem.eql(u8, a, "-o")) {
                opts.overwrite = true;
            } else return ParseError.UnknownFlag;
        }
        return .{ .install = opts };
    }
    if (std.mem.eql(u8, flag, "-u")) {
        var opts: Action.UninstallOpts = .{};
        for (argv[1..]) |a| {
            if (std.mem.eql(u8, a, "-k")) {
                opts.keep_config = true;
            } else return ParseError.UnknownFlag;
        }
        return .{ .uninstall = opts };
    }
    return ParseError.UnknownFlag;
}
