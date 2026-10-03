const std = @import("std");

pub const FakeIpEngine = struct {
    next_ip: u32 = 0xC6120002,
    domain_to_ip: std.StringHashMap(u32),
    ip_to_domain: std.AutoHashMap(u32, []const u8),

    pub fn init(allocator: std.mem.Allocator) FakeIpEngine {
        return .{
            .domain_to_ip = std.StringHashMap(u32).init(allocator),
            .ip_to_domain = std.AutoHashMap(u32, []const u8).init(allocator),
        };
    }

    pub fn deinit(self: *FakeIpEngine) void {
        self.domain_to_ip.deinit();
        self.ip_to_domain.deinit();
    }

    pub fn allocate(self: *FakeIpEngine, domain: []const u8) !u32 {
        if (self.domain_to_ip.get(domain)) |ip| return ip;
        const ip = self.next_ip;
        self.next_ip += 1;
        try self.domain_to_ip.put(domain, ip);
        try self.ip_to_domain.put(ip, domain);
        return ip;
    }

    pub fn lookup(self: *const FakeIpEngine, ip: u32) ?[]const u8 {
        return self.ip_to_domain.get(ip);
    }
};
