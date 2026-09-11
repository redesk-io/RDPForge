const std = @import("std");
const windows = std.os.windows;
const Patch = @import("Patch");

var already_hooked: windows.LONG = 0;

export fn DllMain(hinst: windows.HINSTANCE, reason: u32, _: ?*anyopaque) callconv(.winapi) i32 {
    _ = hinst;
    if (reason == 1) {
        if (@cmpxchgStrong(windows.LONG, &already_hooked, 0, 1, .seq_cst, .seq_cst) != null) return 1;
        hookInit();
    }
    return 1;
}

fn hookInit() void {
    Patch.trace("event=HOOK_INIT");
    if (Patch.hookInit()) |rep| {
        const full = rep.def_policy != null and rep.single_user != null and rep.local_only != null;
        Patch.trace(if (full) "event=BOOT result=patched" else "event=BOOT result=partial");
    } else |_| {
        Patch.trace("event=BOOT result=failed");
    }
}

export fn ServiceMain(argc: u32, argv: ?*anyopaque) callconv(.winapi) void {
    _ = argc;
    _ = argv;
}

export fn SvchostPushServiceGlobals(_: ?*anyopaque) callconv(.winapi) void {}
