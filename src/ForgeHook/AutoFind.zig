const Pe = @import("Pe");
const Anchors = @import("Anchors");
const Decode = @import("Decode");
const Pdata = @import("Pdata");
const Xref = @import("Xref");
const Validate = @import("Validate");

const S = @import("Site");
pub const Site = S.Site;
pub const Emission = S.Emission;

pub const DiscoveryResult = enum { found, miss, validation_fail };

pub const Report = struct {
    def_policy: ?Emission = null,
    single_user: ?Emission = null,
    local_only: ?Emission = null,
    def_policy_candidates: usize = 0,
    single_user_candidates: usize = 0,
    local_only_candidates: usize = 0,
};

pub const DiscoverError = error{ BadImage, NoText };

pub fn run() void {}

pub fn validateEmission(e: Emission) bool {
    return e.len <= 16;
}

pub fn classify(found_anchor: bool, valid_shape: bool) DiscoveryResult {
    if (!found_anchor) return .miss;
    if (!valid_shape) return .validation_fail;
    return .found;
}

fn textBytes(image: []const u8, sections: []const Pe.Section) DiscoverError!struct { bytes: []const u8, rva: u32 } {
    var name: [8]u8 = [_]u8{0} ** 8;
    name[0] = '.';
    name[1] = 't';
    name[2] = 'e';
    name[3] = 'x';
    name[4] = 't';
    const text = Pe.findSection(sections, &name) orelse return DiscoverError.NoText;
    if (@as(usize, text.raw_ptr) + text.raw_size > image.len) return DiscoverError.BadImage;
    return .{
        .bytes = image[text.raw_ptr .. text.raw_ptr + text.raw_size],
        .rva = text.virtual_address,
    };
}

pub fn discover(image: []const u8) DiscoverError!Report {
    var rep = Report{};
    var secbuf: [16]Pe.Section = undefined;
    const sections = Pe.parseSections(image, &secbuf) catch return DiscoverError.BadImage;
    const text = try textBytes(image, sections);

    var cmps: [8192]Validate.CmpSite = undefined;
    const all_cmps = Validate.listCmpMemDisps(text.bytes, text.rva, &cmps);
    for (all_cmps) |c| {
        if (c.disp != 0x63C) continue;
        rep.def_policy_candidates += 1;
        if (rep.def_policy != null) continue;
        const func = Pdata.containingFunctionForRva(image, sections, c.at_rva) catch continue;
        const f_off = Pe.rvaToOffset(sections, func.begin) orelse continue;
        const f_end = Pe.rvaToOffset(sections, func.end) orelse continue;
        if (f_end <= f_off or f_end > image.len) continue;
        if (Validate.findDefPolicySite(image[f_off..f_end], func.begin)) |s| {
            if (!validateEmission(.{ .site = .def_policy, .rva = s.jcc_rva, .len = s.jcc_len })) continue;
            rep.def_policy = .{ .site = .def_policy, .rva = s.jcc_rva, .len = s.jcc_len };
        }
    }

    var occ: [16]usize = undefined;
    const su_occ = Anchors.findAllAnchors(image, "IsSingleSessionPerUser", &occ);
    for (su_occ) |off| {
        const anchor_rva = Pe.offsetToRva(sections, off) orelse continue;
        var refs: [256]Xref.Xref = undefined;
        const found = Xref.scanRipXrefs(text.bytes, text.rva, anchor_rva, &refs);
        for (found) |x| {
            const func = Pdata.containingFunctionForRva(image, sections, x.at_rva) catch continue;
            const f_off = Pe.rvaToOffset(sections, func.begin) orelse continue;
            const f_end = Pe.rvaToOffset(sections, func.end) orelse continue;
            if (f_end <= f_off or f_end > image.len) continue;
            rep.single_user_candidates += 1;
            if (rep.single_user != null) continue;
            if (Validate.findCallTestJz(image[f_off..f_end], func.begin)) |s| {
                if (!validateEmission(.{ .site = .single_user, .rva = s.jz_rva, .len = s.jz_len })) continue;
                rep.single_user = .{ .site = .single_user, .rva = s.jz_rva, .len = s.jz_len };
            }
        }
    }

    var lo_occ: [16]usize = undefined;
    const lo_all = Anchors.findAllAnchors(image, "IsLicenseTypeLocalOnly", &lo_occ);
    var lea_rvas: [16]u32 = undefined;
    var n_lea: usize = 0;
    var host_begin: u32 = 0;
    var host_end: u32 = 0;
    for (lo_all) |off| {
        const anchor_rva = Pe.offsetToRva(sections, off) orelse continue;
        var refs: [256]Xref.Xref = undefined;
        const found = Xref.scanRipXrefs(text.bytes, text.rva, anchor_rva, &refs);
        for (found) |x| {
            const func = Pdata.containingFunctionForRva(image, sections, x.at_rva) catch continue;
            if (n_lea < lea_rvas.len) {
                lea_rvas[n_lea] = x.at_rva;
                n_lea += 1;
            }
            if (host_begin == 0 or func.begin < host_begin) host_begin = func.begin;
            if (func.end > host_end) host_end = func.end;
        }
    }
    if (n_lea > 0 and host_end > host_begin) {
        const h_off = Pe.rvaToOffset(sections, host_begin) orelse return rep;
        const h_end = Pe.rvaToOffset(sections, host_end) orelse return rep;
        if (h_end > h_off and h_end <= image.len) {
            var shapes: [256]Validate.VersionCheckSite = undefined;
            const all = Validate.findAllCallTestJz(image[h_off..h_end], host_begin, &shapes);
            rep.local_only_candidates = all.len;
            var ranked: [256]Validate.RankedSite = undefined;
            const ordered = Validate.rankByLeaProximity(all, lea_rvas[0..n_lea], &ranked);
            if (ordered.len > 0) {
                const top = ordered[0].site;
                if (validateEmission(.{ .site = .local_only, .rva = top.jz_rva, .len = top.jz_len })) {
                    rep.local_only = .{ .site = .local_only, .rva = top.jz_rva, .len = top.jz_len };
                }
            }
        }
    }
    return rep;
}
