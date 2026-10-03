const std = @import("std");

pub const StreamState = struct {
    stream_id: u32,
    sent_offset: u64 = 0,
    ack_offset: u64 = 0,

    pub fn recordAck(self: *StreamState, offset: u64) void {
        self.ack_offset = @max(self.ack_offset, offset);
    }
};
