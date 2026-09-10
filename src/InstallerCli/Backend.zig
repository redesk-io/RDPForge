const std = @import("std");
const builtin = @import("builtin");
const Plan = @import("Plan");

pub const BackendError = error{ UnsupportedOs } || std.mem.Allocator.Error;

pub const Health = struct {
    service_dll_points_at_hook: bool,
    hook_file_present: bool,
    service_running: bool,
};

pub fn healthCheck() BackendError!Health {
    if (builtin.os.tag != .windows) return BackendError.UnsupportedOs;
    @panic("TODO(M3): SCM + registry health check");
}

pub fn install(system32_layout: bool, overwrite: bool) BackendError!void {
    _ = system32_layout;
    _ = overwrite;
    if (builtin.os.tag != .windows) return BackendError.UnsupportedOs;
    @panic("TODO(M3): transactional install per Plan.install_order");
}

pub fn uninstall(keep_config: bool) BackendError!void {
    _ = keep_config;
    if (builtin.os.tag != .windows) return BackendError.UnsupportedOs;
    @panic("TODO(M3): restore ServiceDll + restart + cleanup");
}

pub fn restartServices() BackendError!void {
    if (builtin.os.tag != .windows) return BackendError.UnsupportedOs;
    @panic("TODO(M3): restart TermService");
}
