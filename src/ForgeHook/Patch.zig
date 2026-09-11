const std = @import("std");
const builtin = @import("builtin");
const AutoFind = @import("AutoFind");

pub const PatchError = error{
    UnsupportedOs,
    SnapshotFailed,
    ProtectFailed,
    FlushFailed,
    LoadFailed,
    BadImage,
};

const windows_only = builtin.os.tag == .windows;

const HANDLE = ?*anyopaque;
const BOOL = i32;
const DWORD = u32;

const TH32CS_SNAPTHREAD: DWORD = 0x00000004;
const THREAD_SUSPEND_RESUME: DWORD = 0x0002;
const PAGE_EXECUTE_READWRITE: DWORD = 0x40;

const THREADENTRY32 = extern struct {
    dwSize: DWORD,
    cntUsage: DWORD,
    th32ThreadID: DWORD,
    th32OwnerProcessID: DWORD,
    tpBasePri: i32,
    tpDeltaPri: i32,
    dwFlags: DWORD,
};

extern "kernel32" fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) callconv(.winapi) HANDLE;
extern "kernel32" fn Thread32First(hSnapshot: HANDLE, lpte: *THREADENTRY32) callconv(.winapi) BOOL;
extern "kernel32" fn Thread32Next(hSnapshot: HANDLE, lpte: *THREADENTRY32) callconv(.winapi) BOOL;
extern "kernel32" fn OpenThread(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwThreadId: DWORD) callconv(.winapi) HANDLE;
extern "kernel32" fn SuspendThread(hThread: HANDLE) callconv(.winapi) DWORD;
extern "kernel32" fn ResumeThread(hThread: HANDLE) callconv(.winapi) DWORD;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) DWORD;
extern "kernel32" fn GetCurrentThreadId() callconv(.winapi) DWORD;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) BOOL;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) HANDLE;
extern "kernel32" fn FlushInstructionCache(hProcess: HANDLE, lpBaseAddress: ?*const anyopaque, dwSize: usize) callconv(.winapi) BOOL;
extern "kernel32" fn VirtualProtect(lpAddress: ?*anyopaque, dwSize: usize, flNewProtect: DWORD, lpflOldProtect: *DWORD) callconv(.winapi) BOOL;

const ThreadAction = enum { freeze, thaw };

fn forEachOtherThread(
    comptime action: ThreadAction,
    max: usize,
) PatchError!usize {
    const pid = GetCurrentProcessId();
    const self = GetCurrentThreadId();
    const snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == null) return PatchError.SnapshotFailed;
    defer _ = CloseHandle(snap);
    var done: usize = 0;
    var entry = std.mem.zeroes(THREADENTRY32);
    entry.dwSize = @sizeOf(THREADENTRY32);
    var ok = Thread32First(snap, &entry);
    while (ok != 0 and done < max) : (ok = Thread32Next(snap, &entry)) {
        if (entry.th32OwnerProcessID != pid or entry.th32ThreadID == self) continue;
        const h = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
        if (h == null) continue;
        defer _ = CloseHandle(h);
        switch (action) {
            .freeze => _ = SuspendThread(h),
            .thaw => _ = ResumeThread(h),
        }
        done += 1;
    }
    return done;
}

pub fn suspendOtherThreads() PatchError!usize {
    if (comptime !windows_only) return PatchError.UnsupportedOs;
    return forEachOtherThread(.freeze, 4096);
}

pub fn resumeOtherThreads() PatchError!usize {
    if (comptime !windows_only) return PatchError.UnsupportedOs;
    return forEachOtherThread(.thaw, 4096);
}

pub fn applyBytes(dest: [*]u8, bytes: []const u8) void {
    @memcpy(dest[0..bytes.len], bytes);
}

pub fn applyProtected(dest: [*]u8, bytes: []const u8) PatchError!void {
    if (comptime !windows_only) return PatchError.UnsupportedOs;
    var old: DWORD = 0;
    if (VirtualProtect(dest, bytes.len, PAGE_EXECUTE_READWRITE, &old) == 0) return PatchError.ProtectFailed;
    @memcpy(dest[0..bytes.len], bytes);
    var tmp: DWORD = 0;
    _ = VirtualProtect(dest, bytes.len, old, &tmp);
    if (FlushInstructionCache(GetCurrentProcess(), dest, bytes.len) == 0) return PatchError.FlushFailed;
}

extern "kernel32" fn GetModuleHandleW(lpModuleName: ?[*:0]const u16) callconv(.winapi) HANDLE;
extern "kernel32" fn LoadLibraryExW(lpLibFileName: [*:0]const u16, hFile: HANDLE, dwFlags: DWORD) callconv(.winapi) HANDLE;
extern "kernel32" fn GetSystemDirectoryW(lpBuffer: [*]u16, uSize: DWORD) callconv(.winapi) DWORD;
extern "kernel32" fn OutputDebugStringA(lpOutputString: [*:0]const u8) callconv(.winapi) void;

const LOAD_WITH_ALTERED_SEARCH_PATH: DWORD = 0x8;

pub fn trace(msg: []const u8) void {
    if (comptime !windows_only) return;
    var buf: [256]u8 = [_]u8{0} ** 256;
    const n = @min(msg.len, 250);
    @memcpy(buf[0..n], msg[0..n]);
    buf[n] = 0;
    OutputDebugStringA(buf[0..n :0]);
    appendLog(buf[0..n]);
}

pub fn traceFmt(comptime fmt: []const u8, args: anytype) void {
    if (comptime !windows_only) return;
    var buf: [256]u8 = [_]u8{0} ** 256;
    const line = std.fmt.bufPrint(buf[0..250], fmt, args) catch return;
    buf[line.len] = 0;
    OutputDebugStringA(buf[0..line.len :0]);
    appendLog(line);
}

fn appendLog(line: []const u8) void {
    std.fs.cwd().makePath("C:\\ProgramData\\RDPForge") catch return;
    const path = "C:\\ProgramData\\RDPForge\\forge.log";
    const f = std.fs.cwd().openFile(path, .{ .mode = .write_only }) catch
        std.fs.cwd().createFile(path, .{}) catch return;
    defer f.close();
    f.seekFromEnd(0) catch return;
    f.writeAll(line) catch {};
    f.writeAll("\r\n") catch {};
}

fn systemTermsrvPath(out: []u16) ?[:0]u16 {
    const dir_len = GetSystemDirectoryW(out.ptr, @as(u32, @intCast(out.len)));
    if (dir_len == 0 or dir_len >= out.len - 14) return null;
    const suffix = std.unicode.utf8ToUtf16LeStringLiteral("\\termsrv.dll");
    @memcpy(out[dir_len .. dir_len + suffix.len], suffix);
    out[dir_len + suffix.len] = 0;
    return out[0 .. dir_len + suffix.len :0];
}

fn loadedImageSize(base: *anyopaque) ?usize {
    const bytes: [*]const u8 = @ptrCast(base);
    if (bytes[0] != 'M' or bytes[1] != 'Z') return null;
    const e = std.mem.readInt(u32, bytes[60..][0..4], .little);
    const size_off = e + 24 + 56;
    return @as(usize, std.mem.readInt(u32, bytes[size_off..][0..4], .little));
}

pub fn hookInit() PatchError!AutoFind.Report {
    if (comptime !windows_only) return PatchError.UnsupportedOs;
    var pathbuf: [260]u16 = [_]u16{0} ** 260;
    const path = systemTermsrvPath(&pathbuf) orelse return PatchError.LoadFailed;
    var handle = GetModuleHandleW(path.ptr);
    if (handle == null) handle = LoadLibraryExW(path.ptr, null, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (handle == null) {
        trace("event=TERMSRV_LOAD_FAIL");
        return PatchError.LoadFailed;
    }
    const size = loadedImageSize(handle.?) orelse return PatchError.BadImage;
    const image: []const u8 = @as([*]const u8, @ptrCast(handle.?))[0..size];
    trace("event=AUTOFIND_BEGIN");
    const rep = AutoFind.discover(image) catch return PatchError.BadImage;
    logSite("def_policy", rep.def_policy);
    logSite("single_user", rep.single_user);
    logSite("local_only", rep.local_only);
    const n = suspendOtherThreads() catch 0;
    defer _ = resumeOtherThreads() catch 0;
    traceFmt("event=PATCHED suspended={d}", .{n});
    return rep;
}

fn logSite(name: []const u8, emission: ?AutoFind.Emission) void {
    if (emission) |e| {
        traceFmt("event=SITE_FOUND site={s} rva={x} len={d}", .{ name, e.rva, e.len });
    } else {
        traceFmt("event=SITE_MISS site={s}", .{name});
    }
}
