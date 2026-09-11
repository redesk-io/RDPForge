const std = @import("std");
const builtin = @import("builtin");
const Plan = @import("Plan");

pub const BackendError = error{
    UnsupportedOs,
    AccessDenied,
    NotFound,
    RegistryFailed,
    ServiceFailed,
    FileFailed,
    BadConfig,
} || std.mem.Allocator.Error;

pub const Health = struct {
    service_dll_points_at_hook: bool,
    hook_file_present: bool,
    service_running: bool,
};

const windows_only = builtin.os.tag == .windows;

const HANDLE = ?*anyopaque;
const HKEY = ?*anyopaque;
const BOOL = i32;
const DWORD = u32;
const LSTATUS = i32;
const LPCWSTR = [*:0]const u16;

const HKEY_LOCAL_MACHINE: HKEY = @ptrFromInt(0x80000002);
const KEY_READ: DWORD = 0x20019;
const KEY_WRITE: DWORD = 0x20006;
const REG_EXPAND_SZ: DWORD = 2;
const REG_DWORD: DWORD = 4;
const INVALID_FILE_ATTRIBUTES: DWORD = 0xFFFFFFFF;

const SC_MANAGER_ALL_ACCESS: DWORD = 0xF003F;
const SERVICE_QUERY_STATUS: DWORD = 0x4;
const SERVICE_STOP: DWORD = 0x20;
const SERVICE_START: DWORD = 0x10;
const SERVICE_CONTROL_STOP: DWORD = 1;
const SERVICE_RUNNING: DWORD = 4;
const SERVICE_STOPPED: DWORD = 1;
const CREATE_NO_WINDOW: DWORD = 0x08000000;
const INFINITE: DWORD = 0xFFFFFFFF;
const WAIT_OBJECT_0: DWORD = 0;

const SERVICE_STATUS_PROCESS = extern struct {
    service_type: DWORD,
    current_state: DWORD,
    controls_accepted: DWORD,
    win32_exit_code: DWORD,
    service_exit_code: DWORD,
    check_point: DWORD,
    wait_hint: DWORD,
    process_id: DWORD,
    service_flags: DWORD,
};

const STARTUPINFOW = extern struct {
    cb: DWORD,
    reserved: ?*anyopaque,
    desktop: ?*anyopaque,
    title: ?*anyopaque,
    x: DWORD,
    y: DWORD,
    x_size: DWORD,
    y_size: DWORD,
    x_count_chars: DWORD,
    y_count_chars: DWORD,
    fill_attribute: DWORD,
    flags: DWORD,
    show_window: u16,
    reserved2: u16,
    reserved2_ptr: ?*u8,
    std_input: HANDLE,
    std_output: HANDLE,
    std_error: HANDLE,
};

const PROCESS_INFORMATION = extern struct {
    process: HANDLE,
    thread: HANDLE,
    process_id: DWORD,
    thread_id: DWORD,
};

extern "advapi32" fn RegOpenKeyExW(hKey: HKEY, lpSubKey: LPCWSTR, ulOptions: DWORD, samDesired: DWORD, phkResult: *HKEY) callconv(.winapi) LSTATUS;
extern "advapi32" fn RegQueryValueExW(hKey: HKEY, lpValueName: LPCWSTR, lpReserved: ?*DWORD, lpType: ?*DWORD, lpData: ?[*]u8, lpcbData: *DWORD) callconv(.winapi) LSTATUS;
extern "advapi32" fn RegSetValueExW(hKey: HKEY, lpValueName: LPCWSTR, Reserved: DWORD, dwType: DWORD, lpData: [*]const u8, cbData: DWORD) callconv(.winapi) LSTATUS;
extern "advapi32" fn RegCreateKeyExW(hKey: HKEY, lpSubKey: LPCWSTR, Reserved: DWORD, lpClass: ?*anyopaque, dwOptions: DWORD, samDesired: DWORD, lpSecurityAttributes: ?*anyopaque, phkResult: *HKEY, lpdwDisposition: ?*DWORD) callconv(.winapi) LSTATUS;
extern "advapi32" fn RegCloseKey(hKey: HKEY) callconv(.winapi) LSTATUS;
extern "advapi32" fn OpenSCManagerW(lpMachineName: ?*anyopaque, lpDatabaseName: ?*anyopaque, dwDesiredAccess: DWORD) callconv(.winapi) HANDLE;
extern "advapi32" fn OpenServiceW(hSCManager: HANDLE, lpServiceName: LPCWSTR, dwDesiredAccess: DWORD) callconv(.winapi) HANDLE;
extern "advapi32" fn QueryServiceStatusEx(hService: HANDLE, InfoLevel: i32, lpBuffer: [*]u8, cbBufSize: DWORD, pcbBytesNeeded: *DWORD) callconv(.winapi) BOOL;
extern "advapi32" fn ControlService(hService: HANDLE, dwControl: DWORD, lpServiceStatus: [*]u8) callconv(.winapi) BOOL;
extern "advapi32" fn StartServiceW(hService: HANDLE, dwNumServiceArgs: DWORD, lpServiceArgVectors: ?*anyopaque) callconv(.winapi) BOOL;
extern "advapi32" fn CloseServiceHandle(hSCObject: HANDLE) callconv(.winapi) BOOL;
extern "kernel32" fn GetFileAttributesW(lpFileName: LPCWSTR) callconv(.winapi) DWORD;
extern "kernel32" fn CopyFileW(lpExistingFileName: LPCWSTR, lpNewFileName: LPCWSTR, bFailIfExists: BOOL) callconv(.winapi) BOOL;
extern "kernel32" fn DeleteFileW(lpFileName: LPCWSTR) callconv(.winapi) BOOL;
extern "kernel32" fn CreateDirectoryW(lpPathName: LPCWSTR, lpSecurityAttributes: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn RemoveDirectoryW(lpPathName: LPCWSTR) callconv(.winapi) BOOL;
extern "kernel32" fn GetModuleFileNameW(hModule: HANDLE, lpFilename: [*]u16, nSize: DWORD) callconv(.winapi) DWORD;
extern "kernel32" fn GetEnvironmentVariableW(lpName: LPCWSTR, lpBuffer: [*]u16, nSize: DWORD) callconv(.winapi) DWORD;
extern "kernel32" fn GetSystemDirectoryW(lpBuffer: [*]u16, uSize: DWORD) callconv(.winapi) DWORD;
extern "kernel32" fn CreateProcessW(lpApplicationName: ?*anyopaque, lpCommandLine: [*:0]u16, lpProcessAttributes: ?*anyopaque, lpThreadAttributes: ?*anyopaque, bInheritHandles: BOOL, dwCreationFlags: DWORD, lpEnvironment: ?*anyopaque, lpCurrentDirectory: ?*anyopaque, lpStartupInfo: *STARTUPINFOW, lpProcessInformation: *PROCESS_INFORMATION) callconv(.winapi) BOOL;
extern "kernel32" fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) callconv(.winapi) DWORD;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) BOOL;
extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;
extern "kernel32" fn Sleep(dwMilliseconds: DWORD) callconv(.winapi) void;
extern "shell32" fn IsUserAnAdmin() callconv(.winapi) BOOL;

fn wbuf(buf: []u16, s: []const u8) [:0]u16 {
    const n = std.unicode.utf8ToUtf16Le(buf[0 .. buf.len - 1], s) catch return buf[0..0 :0];
    buf[n] = 0;
    return buf[0..n :0];
}

fn traceLog(msg: []const u8) void {
    if (comptime !windows_only) return;
    std.fs.cwd().makePath("C:\\ProgramData\\RDPForge") catch {};
    const f = std.fs.cwd().createFile("C:\\ProgramData\\RDPForge\\install.log", .{ .mode = .write_only }) catch return;
    defer f.close();
    f.seekFromEnd(0) catch return;
    f.writeAll(msg) catch {};
    f.writeAll("\n") catch {};
}

fn errFromLast(default: BackendError) BackendError {
    return switch (GetLastError()) {
        5 => BackendError.AccessDenied,
        2, 3 => BackendError.NotFound,
        else => default,
    };
}

fn openParams(access: DWORD) BackendError!HKEY {
    var sub: [128]u16 = [_]u16{0} ** 128;
    var key: HKEY = null;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wbuf(&sub, Plan.termservice_params).ptr, 0, access, &key) != 0 or key == null)
        return BackendError.RegistryFailed;
    return key;
}

fn readServiceDll(alloc: std.mem.Allocator) BackendError![]u8 {
    const key = try openParams(KEY_READ);
    defer _ = RegCloseKey(key);
    var name: [32]u16 = [_]u16{0} ** 32;
    var data: [520]u8 = [_]u8{0} ** 520;
    var dtype: DWORD = 0;
    var size: DWORD = @as(u32, @intCast(data.len));
    if (RegQueryValueExW(key, wbuf(&name, Plan.service_dll_value).ptr, null, &dtype, data[0..].ptr, &size) != 0)
        return BackendError.RegistryFailed;
    const wlen = size / 2;
    var tmp: [260]u16 = [_]u16{0} ** 260;
    const n = @min(wlen, tmp.len);
    var i: usize = 0;
    while (i < n) : (i += 1) tmp[i] = std.mem.readInt(u16, data[i * 2 ..][0..2], .little);
    return std.unicode.utf16LeToUtf8Alloc(alloc, tmp[0..n]) catch return BackendError.RegistryFailed;
}

fn writeServiceDll(path: []const u8) BackendError!void {
    const key = try openParams(KEY_WRITE);
    defer _ = RegCloseKey(key);
    var name: [32]u16 = [_]u16{0} ** 32;
    var val: [520]u16 = [_]u16{0} ** 520;
    const w = wbuf(&val, path);
    const bytes: [*]const u8 = @ptrCast(w.ptr);
    if (RegSetValueExW(key, wbuf(&name, Plan.service_dll_value).ptr, 0, REG_EXPAND_SZ, bytes, (@as(u32, @intCast(w.len)) + 1) * 2) != 0)
        return BackendError.RegistryFailed;
}

fn writeDword(subkey: []const u8, value: []const u8, data: DWORD) BackendError!void {
    var sub: [256]u16 = [_]u16{0} ** 256;
    var key: HKEY = null;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, wbuf(&sub, subkey).ptr, 0, null, 0, KEY_WRITE, null, &key, null) != 0 or key == null)
        return BackendError.RegistryFailed;
    defer _ = RegCloseKey(key);
    var name: [64]u16 = [_]u16{0} ** 64;
    var raw: [4]u8 = [_]u8{0} ** 4;
    std.mem.writeInt(u32, &raw, data, .little);
    if (RegSetValueExW(key, wbuf(&name, value).ptr, 0, REG_DWORD, raw[0..].ptr, 4) != 0)
        return BackendError.RegistryFailed;
}

fn fileExists(path: []const u8) bool {
    var buf: [520]u16 = [_]u16{0} ** 520;
    return GetFileAttributesW(wbuf(&buf, path).ptr) != INVALID_FILE_ATTRIBUTES;
}

fn serviceState() BackendError!DWORD {
    const scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
    if (scm == null) return errFromLast(BackendError.ServiceFailed);
    defer _ = CloseServiceHandle(scm);
    var name: [32]u16 = [_]u16{0} ** 32;
    const svc = OpenServiceW(scm, wbuf(&name, "TermService").ptr, SERVICE_QUERY_STATUS);
    if (svc == null) return errFromLast(BackendError.ServiceFailed);
    defer _ = CloseServiceHandle(svc);
    var st: SERVICE_STATUS_PROCESS = std.mem.zeroes(SERVICE_STATUS_PROCESS);
    var needed: DWORD = 0;
    if (QueryServiceStatusEx(svc, 0, @ptrCast(&st), @sizeOf(SERVICE_STATUS_PROCESS), &needed) == 0)
        return BackendError.ServiceFailed;
    return st.current_state;
}

fn stopServiceByName(name_u8: []const u8) void {
    const scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
    if (scm == null) return;
    defer _ = CloseServiceHandle(scm);
    var name: [64]u16 = [_]u16{0} ** 64;
    const svc = OpenServiceW(scm, wbuf(&name, name_u8).ptr, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (svc == null) return;
    defer _ = CloseServiceHandle(svc);
    var st: SERVICE_STATUS_PROCESS = std.mem.zeroes(SERVICE_STATUS_PROCESS);
    var needed: DWORD = 0;
    if (QueryServiceStatusEx(svc, 0, @ptrCast(&st), @sizeOf(SERVICE_STATUS_PROCESS), &needed) == 0) return;
    if (st.current_state == SERVICE_STOPPED) return;
    var dummy: [28]u8 = [_]u8{0} ** 28;
    _ = ControlService(svc, SERVICE_CONTROL_STOP, dummy[0..].ptr);
    var waits: u32 = 0;
    while (waits < 30) : (waits += 1) {
        Sleep(1000);
        if (QueryServiceStatusEx(svc, 0, @ptrCast(&st), @sizeOf(SERVICE_STATUS_PROCESS), &needed) == 0) return;
        if (st.current_state == SERVICE_STOPPED) return;
    }
}

fn startServiceByName(name_u8: []const u8) BackendError!void {
    const scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
    if (scm == null) return errFromLast(BackendError.ServiceFailed);
    defer _ = CloseServiceHandle(scm);
    var name: [64]u16 = [_]u16{0} ** 64;
    const svc = OpenServiceW(scm, wbuf(&name, name_u8).ptr, SERVICE_START);
    if (svc == null) return errFromLast(BackendError.ServiceFailed);
    defer _ = CloseServiceHandle(svc);
    if (StartServiceW(svc, 0, null) == 0 and GetLastError() != 1056)
        return BackendError.ServiceFailed;
}

fn runHidden(cmd: []const u8) void {
    var buf: [1024]u16 = [_]u16{0} ** 1024;
    const w = wbuf(&buf, cmd);
    var mut: [1024]u16 = [_]u16{0} ** 1024;
    @memcpy(mut[0..w.len], w);
    mut[w.len] = 0;
    var si: STARTUPINFOW = std.mem.zeroes(STARTUPINFOW);
    si.cb = @sizeOf(STARTUPINFOW);
    var pi: PROCESS_INFORMATION = std.mem.zeroes(PROCESS_INFORMATION);
    if (CreateProcessW(null, mut[0 .. w.len + 1 :0].ptr, null, null, 0, CREATE_NO_WINDOW, null, null, &si, &pi) == 0) return;
    defer _ = CloseHandle(pi.process);
    defer _ = CloseHandle(pi.thread);
    if (WaitForSingleObject(pi.process, 60000) != WAIT_OBJECT_0) return;
}

fn basenameLower(path: []const u8, out: []u8) []const u8 {
    var start: usize = 0;
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        if (path[i] == '\\' or path[i] == '/') start = i + 1;
    }
    const name = path[start..];
    const n = @min(name.len, out.len);
    var k: usize = 0;
    while (k < n) : (k += 1) out[k] = std.ascii.toLower(name[k]);
    return out[0..n];
}

fn installDir(alloc: std.mem.Allocator, system32_layout: bool) BackendError![]u8 {
    if (system32_layout) {
        var sysdir: [260]u16 = [_]u16{0} ** 260;
        const n = GetSystemDirectoryW(&sysdir, sysdir.len);
        if (n == 0 or n >= sysdir.len) return BackendError.FileFailed;
        const s = std.unicode.utf16LeToUtf8Alloc(alloc, sysdir[0..n]) catch return BackendError.FileFailed;
        return s;
    }
    var pf: [260]u16 = [_]u16{0} ** 260;
    var pfname: [32]u16 = [_]u16{0} ** 32;
    const n = GetEnvironmentVariableW(wbuf(&pfname, "ProgramFiles").ptr, &pf, pf.len);
    if (n == 0 or n >= pf.len) return BackendError.FileFailed;
    const pfs = std.unicode.utf16LeToUtf8Alloc(alloc, pf[0..n]) catch return BackendError.FileFailed;
    defer alloc.free(pfs);
    return Plan.defaultInstallDir(alloc, pfs) catch return BackendError.FileFailed;
}

fn exeDir(alloc: std.mem.Allocator) BackendError![]u8 {
    var buf: [520]u16 = [_]u16{0} ** 520;
    const n = GetModuleFileNameW(null, &buf, buf.len);
    if (n == 0 or n >= buf.len) return BackendError.FileFailed;
    const s = std.unicode.utf16LeToUtf8Alloc(alloc, buf[0..n]) catch return BackendError.FileFailed;
    defer alloc.free(s);
    const dir = std.fs.path.dirname(s) orelse return BackendError.FileFailed;
    return alloc.dupe(u8, dir) catch return BackendError.FileFailed;
}

fn requireAdmin() BackendError!void {
    if (IsUserAnAdmin() == 0) return BackendError.AccessDenied;
}

pub fn healthCheck() BackendError!Health {
    if (comptime !windows_only) return BackendError.UnsupportedOs;
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const dll = readServiceDll(alloc) catch return Health{
        .service_dll_points_at_hook = false,
        .hook_file_present = false,
        .service_running = false,
    };
    var lower: [260]u8 = [_]u8{0} ** 260;
    const base = basenameLower(dll, &lower);
    const st = serviceState() catch SERVICE_STOPPED;
    return Health{
        .service_dll_points_at_hook = std.mem.eql(u8, base, "forgehook.dll"),
        .hook_file_present = fileExists(dll),
        .service_running = st == SERVICE_RUNNING,
    };
}

pub fn install(system32_layout: bool, overwrite: bool) BackendError!void {
    if (comptime !windows_only) return BackendError.UnsupportedOs;
    try requireAdmin();
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    traceLog("install: read ServiceDll");
    const current = try readServiceDll(alloc);
    var lower: [260]u8 = [_]u8{0} ** 260;
    const base = basenameLower(current, &lower);
    const is_termsrv = std.mem.eql(u8, base, "termsrv.dll");
    const is_hook = std.mem.eql(u8, base, "forgehook.dll");
    if (!is_termsrv and !is_hook and !overwrite) return BackendError.BadConfig;

    const dir = try installDir(alloc, system32_layout);
    const src_dir = try exeDir(alloc);
    const src = try std.fs.path.join(alloc, &[_][]const u8{ src_dir, Plan.hook_dll_name });
    const dst = try Plan.hookDllPath(alloc, dir);

    stopServiceByName("UmRdpService");
    stopServiceByName("TermService");
    traceLog("install: services stopped");

    var wdir: [520]u16 = [_]u16{0} ** 520;
    _ = CreateDirectoryW(wbuf(&wdir, dir).ptr, null);
    var wsrc: [520]u16 = [_]u16{0} ** 520;
    var wdst: [520]u16 = [_]u16{0} ** 520;
    if (CopyFileW(wbuf(&wsrc, src).ptr, wbuf(&wdst, dst).ptr, 0) == 0)
        return errFromLast(BackendError.FileFailed);

    traceLog("install: files copied");
    try writeServiceDll(dst);
    traceLog("install: ServiceDll set");
    try writeDword(Plan.ts_key, "fDenyTSConnections", 0);
    try writeDword(Plan.ts_key, "EnableConcurrentSessions", 1);
    try writeDword(Plan.ts_key, "AllowMultipleTSSessions", 1);

    runHidden("netsh advfirewall firewall add rule name=\"Remote Desktop\" protocol=TCP dir=in localport=3389 action=allow");

    try startServiceByName("TermService");
    try startServiceByName("UmRdpService");
    traceLog("install: services restarted");
    runHidden("schtasks /Create /SC ONSTART /TN RDPForgeHealth /TR \"'C:\\Program Files\\RDP Wrapper\\InstallerCli.exe' -w\" /RL HIGHEST /RU SYSTEM /F");
}

pub fn uninstall(keep_config: bool) BackendError!void {
    if (comptime !windows_only) return BackendError.UnsupportedOs;
    try requireAdmin();
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var sysdir: [260]u16 = [_]u16{0} ** 260;
    const n = GetSystemDirectoryW(&sysdir, sysdir.len);
    if (n == 0 or n >= sysdir.len) return BackendError.FileFailed;
    const sys = std.unicode.utf16LeToUtf8Alloc(alloc, sysdir[0..n]) catch return BackendError.FileFailed;
    const termsrv = std.fs.path.join(alloc, &[_][]const u8{ sys, Plan.termsrv_dll_name }) catch return BackendError.FileFailed;

    traceLog("install: read ServiceDll");
    const current = try readServiceDll(alloc);
    const dir = try installDir(alloc, false);
    const hook = try Plan.hookDllPath(alloc, dir);

    stopServiceByName("UmRdpService");
    stopServiceByName("TermService");
    try writeServiceDll(termsrv);
    try startServiceByName("TermService");
    try startServiceByName("UmRdpService");

    var whook: [520]u16 = [_]u16{0} ** 520;
    _ = DeleteFileW(wbuf(&whook, hook).ptr);
    var wdir: [520]u16 = [_]u16{0} ** 520;
    _ = RemoveDirectoryW(wbuf(&wdir, dir).ptr);
    runHidden("schtasks /Delete /TN RDPForgeHealth /F");
    _ = keep_config;
    _ = current;
}

pub fn restartServices() BackendError!void {
    if (comptime !windows_only) return BackendError.UnsupportedOs;
    traceLog("restart: begin");
    try requireAdmin();
    stopServiceByName("UmRdpService");
    stopServiceByName("TermService");
    try startServiceByName("TermService");
    try startServiceByName("UmRdpService");
}
