const std = @import("std");

pub const termservice_params = "SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters";
pub const service_dll_value = "ServiceDll";
pub const ts_key = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server";

pub const hook_dll_name = "ForgeHook.dll";
pub const termsrv_dll_name = "termsrv.dll";
pub const install_subdir = "RDP Wrapper";
pub const health_task_name = "RDPForgeHealth";

pub fn defaultInstallDir(allocator: std.mem.Allocator, program_files: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &[_][]const u8{ program_files, install_subdir });
}

pub fn hookDllPath(allocator: std.mem.Allocator, install_dir: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &[_][]const u8{ install_dir, hook_dll_name });
}

pub const Step = enum {
    stop_services,
    copy_files,
    set_acls,
    set_service_dll,
    write_registry,
    write_firewall,
    start_services,
    create_task,
};

pub const install_order = [_]Step{
    .stop_services,
    .copy_files,
    .set_acls,
    .set_service_dll,
    .write_registry,
    .write_firewall,
    .start_services,
    .create_task,
};

pub fn rollbackFor(completed: []const Step, out: []Step) []Step {
    var n: usize = 0;
    var i: usize = completed.len;
    while (i > 0 and n < out.len) {
        i -= 1;
        out[n] = completed[i];
        n += 1;
    }
    return out[0..n];
}
