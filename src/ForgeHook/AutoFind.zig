pub const Site = enum { local_only, def_policy, single_user, non_rdp, sl_init };

pub const Emission = struct {
    site: Site,
    rva: u32,
    len: u8,
};

pub const DiscoveryResult = enum { found, miss, validation_fail };

pub fn run() void {}

pub fn validateEmission(e: Emission) bool {
    return e.len <= 16;
}

pub fn classify(found_anchor: bool, valid_shape: bool) DiscoveryResult {
    if (!found_anchor) return .miss;
    if (!valid_shape) return .validation_fail;
    return .found;
}
