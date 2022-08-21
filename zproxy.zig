const std = @import("std");
const mem = std.mem;
const thread = std.Thread;
const network = @import("zig-network/network.zig");

const DATAGRAM_FLAG: u8 = 0x80;
const FRAGMENT_FLAG: u8 = 0x10;
pub const HandleFn = fn () bool;

// Packets ID
const LoginPacket: u8 = 0x1;

pub fn startup(bind_address: network.EndPoint, target_address: network.EndPoint, client_handler: HandleFn, server_handler: HandleFn) !void {
    // Initialize listener
    const listener_address_family = switch (bind_address.address) {
        .ipv4 => network.AddressFamily.ipv4,
        .ipv6 => network.AddressFamily.ipv6,
    };
    var listener = Listener{ .socket = try network.Socket.create(listener_address_family, .udp), .client = null };
    defer listener.socket.close();
    try listener.socket.bind(bind_address);

    // Initialize dialer
    const dialer_bind_address = .{
        .address = .{ .ipv4 = network.Address.IPv4.loopback },
        .port = 0,
    };
    var dialer = Dialer{ .socket = try network.Socket.create(.ipv4, .udp), .target = target_address };
    defer dialer.socket.close();
    try dialer.socket.bind(dialer_bind_address);

    // Initialize allocator.
    const allocator = std.heap.page_allocator;

    // Create threads.
    var thr1 = try thread.spawn(.{}, listener_loop, .{ &listener, &dialer, server_handler, &allocator });
    var thr2 = try thread.spawn(.{}, dialer_loop, .{ &dialer, &listener, client_handler });

    // Start threads.
    thr1.join();
    thr2.join();
}

fn listener_loop(
    listener: *Listener,
    dialer: *Dialer,
    handler: HandleFn,
    allocator: *const mem.Allocator,
) !void {
    var fragment_stock = Fragment.init(allocator);
    while (true) {
        // Allocate memory for incoming packet.
        var data: []u8 = try allocator.alloc(u8, 4096);
        defer allocator.free(data);

        const size = try listener.recv(data);

        // Handle only framed packets.
        if (data[0] & DATAGRAM_FLAG != 0) {
            const flags = data[4];
            const data_len = read_big_u16(data[5..7]) / 8;
            const start_index = size - data_len;

            if (flags & FRAGMENT_FLAG != 0) {
                const info = FragmentInfo.from_bytes(data[start_index - 10 .. start_index]);
                const packet = try fragment_stock.receive_fragment(info, data[start_index..size]);

                if (packet != null) {
                    // Received all split packet.
                    if (packet.?[0] == 0xfe) {
                        try handle_mcpe(packet.?[1..]);
                    } else unreachable;
                }
            } else {
                // Handle only mcbe packets.
                if (data[size - data_len] == 0xfe) {
                    try handle_mcpe(data[size - data_len + 1 ..]);
                }
            }
        }

        // Call user handle function.
        if (!handler()) _ = try dialer.send(data[0..size]);
    }
}

fn handle_mcpe(data: []u8) !void {
    const allocator = std.heap.page_allocator;
    var fib = std.io.fixedBufferStream(data);
    const reader = fib.reader();
    var decompressor = try std.compress.deflate.decompressor(allocator, reader, null);
    defer decompressor.deinit();

    while (true) {
        const len = read_var_u32(decompressor.reader()) catch |err| switch(err) {
            error.EndOfStream => break,
            else => return err
        };

        var packet = try decompressor.reader().readAllAlloc(allocator, len);
        defer allocator.free(packet);

        var fixed_buffer = std.io.fixedBufferStream(packet);
        const cursor = fixed_buffer.reader();

        switch (try cursor.readByte()) {
            LoginPacket => {
                const protocol_version = try cursor.readIntBig(u32);
                const data_len = try read_var_u32(cursor);
                std.debug.print("protocol version : {!}\ndata length {!}", .{protocol_version, data_len});
            },
            else => unreachable,
        }
    }
}

fn dialer_loop(dialer: *Dialer, listener: *Listener, handler: HandleFn) !void {
    //var dialer_seq = 0;
    while (true) {
        var data: [4096]u8 = undefined;
        const size = try dialer.recv(data[0..4096]);

        // Call user handle function.
        if (!handler()) _ = try listener.send(data[0..size]);
    }
}

pub const Dialer = struct {
    mutex: thread.Mutex = .{},
    socket: network.Socket,
    target: network.EndPoint,

    const Self = @This();

    pub fn recv(self: *Self, data: []u8) !usize {
        while (true) {
            const recv_from = try self.socket.receiveFrom(data);
            if (!recv_from.sender.address.eql(self.target.address) and recv_from.sender.port == self.target.port) continue;
            return recv_from.numberOfBytes;
        }
    }

    pub fn send(self: *Self, data: []const u8) !usize {
        return try self.socket.sendTo(self.target, data);
    }
};

pub const Listener = struct {
    mutex: thread.Mutex = .{},
    socket: network.Socket,
    client: ?network.EndPoint = null,

    const Self = @This();

    pub fn recv(self: *Self, data: []u8) !usize {
        while (true) {
            const recv_from = try self.socket.receiveFrom(data);

            self.client = recv_from.sender;
            return recv_from.numberOfBytes;
        }
    }

    pub fn send(self: *Self, data: []const u8) !usize {
        if (self.client == null) return error.NotConnected;
        return try self.socket.sendTo(self.client.?, data);
    }
};

pub const FragmentInfo = struct {
    compound_size: u32,
    compound_id: u16,
    index: u32,

    const Self = @This();

    pub fn from_bytes(b: []u8) Self {
        return Self{ .compound_size = read_big_u32(b[0..4]), .compound_id = read_big_u16(b[4..6]), .index = read_big_u32(b[6..10]) };
    }
};

pub const Fragment = struct {
    allocator: *const mem.Allocator,
    fragment: ?[]?[]u8,

    id: ?u16,
    size: ?u32,

    const Self = @This();

    pub fn init(allocator: *const mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .fragment = null,
            .id = null,
            .size = null,
        };
    }

    pub fn receive_fragment(self: *Self, info: FragmentInfo, payload: []u8) !?[]u8 {
        // Return error if the split size is biggger than maximum split size.
        if (info.compound_size > 256) {
            //TODO : return error
        }

        if (self.fragment == null) {
            self.fragment = try self.allocator.alloc(?[]u8, info.compound_size);
            self.size = info.compound_size;
            self.id = info.compound_id;
        }

        if (info.compound_id != self.id.? or info.index > self.size.? - 1) {
            //TODO : return error
        }

        self.fragment.?[info.index] = try self.allocator.alloc(u8, payload.len);
        mem.copy(u8, self.fragment.?[info.index].?, @as([]const u8, payload));

        // Check if all packets have been received
        var total_len: usize = 0;
        for (self.fragment.?) |data| {
            if (data != null) {
                total_len += data.?.len;
            } else return null;
        }

        // Concat all packets
        var packet = try self.allocator.alloc(u8, total_len);
        var pos: usize = 0;
        for (self.fragment.?) |data| {
            mem.copy(u8, packet[pos..], @as([]const u8, data.?));
            self.allocator.free(data.?);
            pos += data.?.len;
        }

        // free memory and reset values.
        self.allocator.free(self.fragment.?);
        self.fragment = null;
        self.id = null;
        self.size = null;

        return packet;
    }
};

fn read_big_u16(b: *[2]u8) u16 {
    return @as(u16, b[1]) | (@as(u16, b[0]) << 8);
}

pub fn read_big_u32(b: *[4]u8) u32 {
    return @as(u32, b[3]) | @as(u32, b[2]) << 8 | @as(u32, b[1]) << 16 | @as(u32, b[0]) << 24;
}

// Varint functions

fn zigzag_encode_32(src: i32) u32 {
    if (src >= 0) return @intCast(u32, src) << 1 else return (@intCast(u32, (-src)) << 1) - 1;
}

fn zigzag_decode_32(src: u32) i32 {
    if (src & 1 != 0) return -@intCast(i32, (src >> 1)) - 1 else return @intCast(i32, (src >> 1));
}

fn zigzag_encode_64(src: i64) u64 {
    if (src >= 0) return @intCast(u64, src) << 1 else return (@intCast(u64, (-src)) << 1) - 1;
}

fn zigzag_decode_64(src: u64) i64 {
    if (src & 1 != 0) return -@intCast(i64, (src >> 1)) - 1 else return @intCast(i64, (src >> 1));
}

fn read_var_i64(reader : anytype) !i64 {
    var i : u32 = 0;
    var ans : i64 = 0;
    while (i < 8) : (i+=1) {
        const byte = try reader.readByte();
        ans |= @intCast(i64,(byte & 0b0111_1111)) << 7 * i;
        if (byte & 0b1000_0000 == 0) {
            break;
        }
    }
    return ans;
}

fn read_var_i32(reader : anytype) !i32 {
    var i : u5 = 0;
    var ans : i32 = 0;
    while (i < 4) : (i+=1) {
        const byte = try reader.readByte();
        ans |= @intCast(i32,(byte & 0b0111_1111)) << 7 * i;
        if (byte & 0b1000_0000 == 0) {
            break;
        }
    }
    return ans;
}

fn read_var_u64(reader : anytype) !u64 {
    return zigzag_encode_64(try read_var_i64(reader));
}

fn read_var_u32(reader : anytype) !u32 {
    return zigzag_encode_32(try read_var_i32(reader));
}