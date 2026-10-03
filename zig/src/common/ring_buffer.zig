const std = @import("std");

pub fn RingBuffer(comptime Capacity: usize) type {
    return struct {
        data: [Capacity]u8 = undefined,
        head: usize = 0,
        tail: usize = 0,
        size: usize = 0,

        const Self = @This();

        pub fn init() Self {
            return .{};
        }

        pub fn write(self: *Self, slice: []const u8) usize {
            const available = Capacity - self.size;
            const to_write = @min(slice.len, available);
            var i: usize = 0;
            while (i < to_write) : (i += 1) {
                self.data[self.tail] = slice[i];
                self.tail = (self.tail + 1) % Capacity;
            }
            self.size += to_write;
            return to_write;
        }

        pub fn read(self: *Self, dest: []u8) usize {
            const to_read = @min(dest.len, self.size);
            var i: usize = 0;
            while (i < to_read) : (i += 1) {
                dest[i] = self.data[self.head];
                self.head = (self.head + 1) % Capacity;
            }
            self.size -= to_read;
            return to_read;
        }

        pub fn isFull(self: *const Self) bool {
            return self.size == Capacity;
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.size == 0;
        }
    };
}
