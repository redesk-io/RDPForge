const std = @import("std");

pub fn findAnchor(haystack: []const u8, needle: []const u8, step: usize) ?usize {
    if (needle.len == 0 or needle.len > haystack.len) return null;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += step) {
        if (std.mem.eql(u8, haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

pub fn findAllAnchors(haystack: []const u8, needle: []const u8, out: []usize) []usize {
    if (needle.len == 0 or needle.len > haystack.len) return out[0..0];
    var n: usize = 0;
    var i: usize = 0;
    while (i + needle.len <= haystack.len and n < out.len) : (i += 1) {
        if (std.mem.eql(u8, haystack[i .. i + needle.len], needle)) {
            out[n] = i;
            n += 1;
        }
    }
    return out[0..n];
}

pub const SiteAnchor = struct {
    site: @import("Site").Site,
    marker: []const u8,
};

pub const site_anchors = [_]SiteAnchor{
    .{ .site = .def_policy, .marker = "CDefPolicy::Query" },
    .{ .site = .local_only, .marker = "IsLicenseTypeLocalOnly" },
    .{ .site = .single_user, .marker = "IsSingleSessionPerUser" },
    .{ .site = .non_rdp, .marker = "IsAllowNonRDPStack" },
    .{ .site = .sl_init, .marker = "bRemoteConnAllowed" },
};
