const std = @import("std");

pub const FakeIpEngine = struct {
    allocator: std.mem.Allocator,
    next_ip: u32 = 0xC6120002,
    domain_to_ip: std.StringHashMap(u32),
    ip_to_domain: std.AutoHashMap(u32, []const u8),

    pub fn init(allocator: std.mem.Allocator) FakeIpEngine {
        return .{
            .allocator = allocator,
            .domain_to_ip = std.StringHashMap(u32).init(allocator),
            .ip_to_domain = std.AutoHashMap(u32, []const u8).init(allocator),
        };
    }

    pub fn deinit(self: *FakeIpEngine) void {
        var it = self.ip_to_domain.valueIterator();
        while (it.next()) |val| {
            self.allocator.free(val.*);
        }
        self.domain_to_ip.deinit();
        self.ip_to_domain.deinit();
    }

    pub fn allocate(self: *FakeIpEngine, domain: []const u8) !u32 {
        if (self.domain_to_ip.get(domain)) |ip| return ip;
        const ip = self.next_ip;
        self.next_ip += 1;
        const duped = try self.allocator.dupe(u8, domain);
        try self.domain_to_ip.put(duped, ip);
        try self.ip_to_domain.put(ip, duped);
        return ip;
    }

    pub fn lookup(self: *const FakeIpEngine, ip: u32) ?[]const u8 {
        return self.ip_to_domain.get(ip);
    }
};
