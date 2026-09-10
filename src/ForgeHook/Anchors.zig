const std = @import("std");

pub fn findAnchor(haystack: []const u8, needle: []const u8, step: usize) ?usize {
    if (needle.len == 0 or needle.len > haystack.len) return null;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += step) {
        if (std.mem.eql(u8, haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

pub const SiteAnchor = struct {
    site: @import("AutoFind").Site,
    marker: []const u8,
};

pub const site_anchors = [_]SiteAnchor{
    .{ .site = .def_policy, .marker = "CDefPolicy::Query" },
    .{ .site = .local_only, .marker = "IsLicenseTypeLocalOnly" },
    .{ .site = .single_user, .marker = "IsSingleSessionPerUser" },
    .{ .site = .non_rdp, .marker = "IsAllowNonRDPStack" },
    .{ .site = .sl_init, .marker = "bRemoteConnAllowed" },
};
