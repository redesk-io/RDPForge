pub const Site = enum { local_only, def_policy, single_user, non_rdp, sl_init };

pub const Emission = struct {
    site: Site,
    rva: u32,
    len: u8,
};

pub fn run() void {}

pub fn validateEmission(e: Emission) bool {
    return e.len <= 16;
}
