const std = @import("std");

pub const FlowKey = struct {
    client_ip: [4]u8,
    fake_ip: [4]u8,
    client_port: u16,
    target_port: u16,

    pub fn eql(a: FlowKey, b: FlowKey) bool {
        return std.mem.eql(u8, &a.client_ip, &b.client_ip) and
            std.mem.eql(u8, &a.fake_ip, &b.fake_ip) and
            a.client_port == b.client_port and
            a.target_port == b.target_port;
    }
};

pub const Flow = struct {
    stream_id: u32,
    client_ip: [4]u8,
    fake_ip: [4]u8,
    client_port: u16,
    target_port: u16,
    domain: [256]u8,
    domain_len: usize,
    client_seq: u32,
    server_seq: u32,
    established: bool = false,
    closed: bool = false,

    pub fn getDomain(self: *const Flow) []const u8 {
        return self.domain[0..self.domain_len];
    }
};

pub const FlowTable = struct {
    flows: std.AutoHashMap(u32, Flow),
    key_to_stream: std.AutoHashMap(FlowKey, u32),
    next_stream_id: u32 = 1,
    mutex: std.Thread.Mutex = .{},
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) FlowTable {
        return .{
            .flows = std.AutoHashMap(u32, Flow).init(allocator),
            .key_to_stream = std.AutoHashMap(FlowKey, u32).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *FlowTable) void {
        self.flows.deinit();
        self.key_to_stream.deinit();
    }

    pub fn getOrCreate(
        self: *FlowTable,
        client_ip: [4]u8,
        fake_ip: [4]u8,
        client_port: u16,
        target_port: u16,
        domain: []const u8,
        initial_client_seq: u32,
    ) !*Flow {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = FlowKey{
            .client_ip = client_ip,
            .fake_ip = fake_ip,
            .client_port = client_port,
            .target_port = target_port,
        };

        if (self.key_to_stream.get(key)) |stream_id| {
            if (self.flows.getPtr(stream_id)) |existing| {
                return existing;
            }
        }

        const stream_id = self.next_stream_id;
        self.next_stream_id += 1;

        var flow = Flow{
            .stream_id = stream_id,
            .client_ip = client_ip,
            .fake_ip = fake_ip,
            .client_port = client_port,
            .target_port = target_port,
            .domain = undefined,
            .domain_len = @min(domain.len, 255),
            .client_seq = initial_client_seq + 1,
            .server_seq = 0x10000001,
            .established = false,
            .closed = false,
        };
        @memcpy(flow.domain[0..flow.domain_len], domain[0..flow.domain_len]);

        try self.flows.put(stream_id, flow);
        try self.key_to_stream.put(key, stream_id);
        return self.flows.getPtr(stream_id).?;
    }

    pub fn lookupByKey(self: *FlowTable, client_ip: [4]u8, fake_ip: [4]u8, client_port: u16, target_port: u16) ?*Flow {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = FlowKey{
            .client_ip = client_ip,
            .fake_ip = fake_ip,
            .client_port = client_port,
            .target_port = target_port,
        };
        if (self.key_to_stream.get(key)) |stream_id| {
            return self.flows.getPtr(stream_id);
        }
        return null;
    }

    pub fn lookupByStream(self: *FlowTable, stream_id: u32) ?*Flow {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.flows.getPtr(stream_id);
    }

    pub fn remove(self: *FlowTable, stream_id: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.flows.get(stream_id)) |flow| {
            const key = FlowKey{
                .client_ip = flow.client_ip,
                .fake_ip = flow.fake_ip,
                .client_port = flow.client_port,
                .target_port = flow.target_port,
            };
            _ = self.key_to_stream.remove(key);
            _ = self.flows.remove(stream_id);
        }
    }
};
