const std = @import("std");
const mem = std.mem;
const json = std.json;
const P384 = std.crypto.ecc.P384;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const thread = std.Thread;
const network = @import("zig-network/network.zig");

const DATAGRAM_FLAG: u8 = 0x80;
const FRAGMENT_FLAG: u8 = 0x10;
pub const HandleFn = fn () bool;

const Mojang_pubkey: []const u8 = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8ELkixyLcwlZryUQcu1TvPOmI2B7vX83ndnWRUaXm74wFfa5f/lwQNTfrLVHa2PmenpGI6JhIMUJaWZrjmMj90NoKNFSNBuKdm8rYiXsfaz3K36x/1U26HpG0ZxK/V1V";

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
        const len = read_var_u32(decompressor.reader()) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };

        var packet = try decompressor.reader().readAllAlloc(allocator, len);
        defer allocator.free(packet);
        std.debug.print("packet length : {!}\n", .{packet.len});

        var fixed_buffer = std.io.fixedBufferStream(packet);
        const cursor = fixed_buffer.reader();

        switch (try cursor.readByte()) {
            LoginPacket => {
                const protocol_version = try cursor.readIntBig(u32);
                const data_len = try read_var_u32(cursor);
                std.debug.print("protocol version : {!}\ndata lengrh : {!}\n", .{ protocol_version, data_len });

                const jwt_chain_len = try cursor.readIntLittle(u32);
                std.debug.print("jwt chain length : {!}\n", .{jwt_chain_len});

                const jwt_chain = try allocator.alloc(u8, jwt_chain_len);
                defer allocator.free(jwt_chain);
                std.debug.assert((try cursor.read(jwt_chain)) == jwt_chain_len);

                const player_data_len = try cursor.readIntLittle(u32);
                std.debug.print("player data jwt len : {!}\n", .{player_data_len});

                const player_data_jwt = try allocator.alloc(u8, player_data_len);
                defer allocator.free(player_data_jwt);
                std.debug.assert((try cursor.read(player_data_jwt)) == player_data_len);

                const claims_start = mem.indexOfScalar(u8, player_data_jwt, '.').? + 1;
                const claims_end = mem.indexOfScalar(u8, player_data_jwt[claims_start..], '.').?;
                const claims = player_data_jwt[claims_start..claims_end];

                const JwtChain = struct { chain: [][]u8 };

                var jwts_ts = json.TokenStream.init(jwt_chain);
                const jwts = try json.parse(JwtChain, &jwts_ts, .{ .allocator = allocator });

                for (jwts.chain) |jwt_str| {
                    var jwt = try Jwt.init(jwt_str, allocator);
                    defer jwt.deinit();

                    if (jwt.extra_data != null) {
                        std.debug.print("{s} logged in!\n", .{jwt.extra_data.?.display_name});
                        std.debug.print("pubkey : {s}\n", .{jwt.identity_public_key});

                        const pubkey = try parse_pkix_key(jwt.identity_public_key);

                        // Generate key
                        const secret = P384.scalar.random(.Big);
                        const our_pubkey = try P384.basePoint.mul(secret, .Big);

                        // Exchange key
                        const shared_secret = try pubkey.mul(secret, .Big);
                        const shared_bytes = shared_secret.x.toBytes(.Big);

                        std.debug.print("secret key : {any}\n", .{shared_bytes});

                        const our_pubkey_der = encode_pkix_key(our_pubkey);
                        var our_pubkey_pem: [160]u8 = [_]u8{0} ** 160;
                        _ = std.base64.standard.Encoder.encode(our_pubkey_pem[0..160], &our_pubkey_der);

                        std.debug.print("our public key : {s}\n", .{our_pubkey_pem});

                        const pem = our_pubkey_pem[0..160];

                        // Now we send our token to target server.
                        // We use the same key for listener and dialer.
                        const xuid = jwt.extra_data.?.xuid;
                        const display_name = jwt.extra_data.?.display_name;
                        const identity = jwt.extra_data.?.identity;

                        const urlsafe_nopad = std.base64.url_safe_no_pad;
                        const header_json = try json.stringifyAlloc(allocator, .{
                            .alg = "ES384",
                            .x5u = pem,
                        }, .{});

                        const header_b64_len = urlsafe_nopad.Encoder.calcSize(header_json.len);
                        defer allocator.free(header_json);

                        const extra_data = .{ .XUID = xuid, .displayName = display_name, .identity = identity };

                        const claims_json = try json.stringifyAlloc(allocator, .{
                            .exp = jwt.exp,
                            .extraData = extra_data,
                            .identityPublicKey = pem,
                            .nbf = jwt.nbf,
                        }, .{});
                        const claims_b64_len = urlsafe_nopad.Encoder.calcSize(claims_json.len);
                        defer allocator.free(claims_json);

                        var jwt_dst = try allocator.alloc(u8, header_b64_len + claims_b64_len + urlsafe_nopad.Encoder.calcSize(96) + 2);
                        defer allocator.free(jwt_dst);

                        _ = urlsafe_nopad.Encoder.encode(jwt_dst, header_json);
                        jwt_dst[header_b64_len] = '.';
                        _ = urlsafe_nopad.Encoder.encode(jwt_dst[header_b64_len + 1 ..], claims_json);
                        jwt_dst[header_b64_len + claims_b64_len + 1] = '.';

                        const skey = try EcdsaP384Sha384.SecretKey.fromBytes(secret);
                        const key_pair = try EcdsaP384Sha384.KeyPair.fromSecretKey(skey);
                        const sign = try key_pair.sign(jwt_dst[0..header_b64_len + claims_b64_len + 1], null);

                        _ = urlsafe_nopad.Encoder.encode(jwt_dst[header_b64_len + claims_b64_len + 2 ..], sign.toBytes()[0..96]);

                        //std.debug.print("{s}\n", .{jwt_dst});

                        const player_data_claims_dst = try allocator.alloc(u8, header_b64_len + claims.len + urlsafe_nopad.Encoder.calcSize(96) + 2);
                        defer allocator.free(player_data_claims_dst);

                        _ = urlsafe_nopad.Encoder.encode(player_data_claims_dst, header_json);
                        player_data_claims_dst[header_b64_len] = '.';
                        mem.copy(u8, player_data_claims_dst[header_b64_len + 1..], claims);
                        player_data_claims_dst[header_b64_len + claims.len + 1] = '.';

                        const player_data_sign = try key_pair.sign(player_data_claims_dst[0..header_b64_len + claims.len + 1], null);

                        _ = urlsafe_nopad.Encoder.encode(player_data_claims_dst[header_b64_len + claims.len + 2 ..], player_data_sign.toBytes()[0..96]);
                        //std.debug.print("{s}\n", .{player_data_claims_dst});
                    }
                }
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

    pub fn recv(self: Self, data: []u8) !usize {
        while (true) {
            const recv_from = try self.socket.receiveFrom(data);
            if (!recv_from.sender.address.eql(self.target.address) and recv_from.sender.port == self.target.port) continue;
            return recv_from.numberOfBytes;
        }
    }

    pub fn send(self: Self, data: []const u8) !usize {
        return try self.socket.sendTo(self.target, data);
    }

    pub fn login(protocol_version : u32, jwt : []const u8, player_data : []const u8, allocator : mem.Allocator) void {
        const chain = try json.stringifyAlloc(.{.chain=[_][]const u8{jwt}},null);
        defer allocator.free(chain);

        const strings_len = chain.len + player_data.len + @sizeOf(u32) * 2;

        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        // MCPE packet identifier
        buffer.writer().writeByte(0xfe);
        
        var compressor = try std.compress.deflate.compressor(allocator, buffer.writer(), .{.level = .level_7});
        defer compressor.deinit();

        try compressor.writer().writeByte(LoginPacket);
        try compressor.writer().writeIntBig(u32, protocol_version);
        try write_var_u32(compressor.writer(), strings_len);
        try compressor.writer().writeIntLittle(u32, chain.len);
        try compressor.writer().writeAll(chain);
        try compressor.writer().writeIntLittle(u32, player_data);
        try compressor.writer().writeAll(player_data);
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

    pub fn send(self: Self, data: []const u8) !usize {
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
            @panic("TODO : return error");
        }

        if (self.fragment == null) {
            self.fragment = try self.allocator.alloc(?[]u8, info.compound_size);
            self.size = info.compound_size;
            self.id = info.compound_id;
        }

        if (info.compound_id != self.id.? or info.index > self.size.? - 1) {
            @panic("TODO : return error");
        }

        self.fragment.?[info.index] = try self.allocator.alloc(u8, payload.len);
        mem.copy(u8, self.fragment.?[info.index].?, payload);

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
            mem.copy(u8, packet[pos..], data.?);
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

// No verification. Because it's annoying.
// We trust the clients we connect with.
// TODO : verify
const Jwt = struct {
    pub const ExtraData = struct {
        xuid: []const u8,
        identity: []const u8,
        display_name: []const u8,
        title_id: []const u8,
    };

    allocator: mem.Allocator,
    x5u: []const u8,
    identity_public_key: []const u8,
    extra_data: ?ExtraData,

    nbf: i64,
    exp: i64,

    const Self = @This();

    pub fn init(str: []u8, allocator: std.mem.Allocator) !Self {
        // Split token with '.'.
        const header_end = mem.indexOfScalar(u8, str, '.').?;
        const claims_end = mem.indexOfScalarPos(u8, str, header_end + 1, '.').?;

        const header_b64 = str[0..header_end];
        const claims_b64 = str[header_end + 1 .. claims_end];

        // Decode token.
        var header_json_str = try allocator.alloc(u8, try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(header_b64));
        defer allocator.free(header_json_str);
        try std.base64.url_safe_no_pad.Decoder.decode(header_json_str, header_b64);

        var claims_json_str = try allocator.alloc(u8, try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(claims_b64));
        defer allocator.free(claims_json_str);
        try std.base64.url_safe_no_pad.Decoder.decode(claims_json_str, claims_b64);

        // Parse strings to json.
        var parser = json.Parser.init(allocator, false);
        parser.deinit();

        var parser2 = json.Parser.init(allocator, false);
        parser2.deinit();

        var header = try parser.parse(header_json_str);
        defer header.deinit();
        var claims = try parser2.parse(claims_json_str);
        defer claims.deinit();

        // Allocate memory and copy.
        var x5u = try copy_string(header.root.Object.get("x5u").?.String, allocator);
        var identity_public_key = try copy_string(claims.root.Object.get("identityPublicKey").?.String, allocator);

        const extra = claims.root.Object.get("extraData");
        const extra_data = if (extra != null)
            ExtraData{
                .xuid = try copy_string(extra.?.Object.get("XUID").?.String, allocator),
                .identity = try copy_string(extra.?.Object.get("identity").?.String, allocator),
                .display_name = try copy_string(extra.?.Object.get("displayName").?.String, allocator),
                .title_id = try copy_string(extra.?.Object.get("titleId").?.String, allocator),
            }
        else
            null;

        const nbf = claims.root.Object.get("nbf").?.Integer;
        const exp = claims.root.Object.get("exp").?.Integer;
        return Self{ .allocator = allocator, .x5u = x5u, .identity_public_key = identity_public_key, .extra_data = extra_data, .nbf = nbf, .exp = exp };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.x5u);
        self.allocator.free(self.identity_public_key);
        if (self.extra_data != null) {
            self.allocator.free(self.extra_data.?.xuid);
            self.allocator.free(self.extra_data.?.identity);
            self.allocator.free(self.extra_data.?.display_name);
            self.allocator.free(self.extra_data.?.title_id);
        }
    }
};

// I don't know how to copy `[]const u8` with allocating memory.
fn copy_string(src: []const u8, allocator: mem.Allocator) ![]u8 {
    var dest = try allocator.alloc(u8, src.len);
    mem.copy(u8, dest, src);
    return dest;
}

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

fn read_var_i64(reader: anytype) !i64 {
    var i: u32 = 0;
    var ans: i64 = 0;
    while (i < 8) : (i += 1) {
        const byte = try reader.readByte();
        ans |= @intCast(i64, (byte & 0b0111_1111)) << 7 * i;
        if (byte & 0b1000_0000 == 0) {
            break;
        }
    }
    return ans;
}

fn read_var_i32(reader: anytype) !i32 {
    var i: u5 = 0;
    var ans: i32 = 0;
    while (i < 4) : (i += 1) {
        const byte = try reader.readByte();
        ans |= @intCast(i32, (byte & 0b0111_1111)) << 7 * i;
        if (byte & 0b1000_0000 == 0) {
            break;
        }
    }
    return ans;
}

fn read_var_u64(reader: anytype) !u64 {
    return zigzag_encode_64(try read_var_i64(reader));
}

fn read_var_u32(reader: anytype) !u32 {
    return zigzag_encode_32(try read_var_i32(reader));
}

fn var_i32_len(v : i32) usize {
    var cnt = 0;
    while (v != 0) {
        v = (v >> 7) & (std.math.maxInt(i32) >> 6);
        cnt += 1;
    }
    return cnt;
}

fn var_i64_len(v : i32) usize {
    var cnt = 0;
    while (v != 0) {
        v = (v >> 7) & (std.math.maxInt(i64) >> 6);
        cnt += 1;
    }
    return cnt;
}

fn var_u32_len(v : u32) usize {
    return var_i32_len(zigzag_decode_32(v));
}

fn var_u64_len(v : u64) usize {
    return var_i64_len(zigzag_decode_64(v));
}

fn write_var_i32(writer: anytype, v: i32) !void {
    var byte = 0;
    while (v != 0) {
        byte = @intCast(u8, v & 0b0111_1111);
        v = (v >> 7) & (std.math.maxInt(i32) >> 6);
        if (v != 0) {
            byte |= 0b1000_0000;
        }
        try writer.writeByte(byte);
    }
}

fn write_var_i64(writer : anytype, v: i64) !void {
    var byte = 0;
    while (v != 0) {
        byte = @intCast(u8, v & 0b0111_1111);
        v = (v >> 7) & (std.math.maxInt(i64) >> 6);
        if (v != 0) {
            byte |= 0b1000_0000;
        }
        try writer.writeByte(byte);
    }
}

fn write_var_u32(writer : anytype, v : u64) !void {
    try write_var_i32(writer, zigzag_decode_32(v));
}

fn writer_var_u64(writer : anytype, v : u64) !void {
    try write_var_i64(writer, zigzag_decode_64(v));
}


// This is a terrible function to parse pkix key.
// But it's fast and simple :).
fn parse_pkix_key(pem: []const u8) !P384 {
    var key: [120]u8 = [_]u8{0x0} ** 120;
    try std.base64.standard.Decoder.decode(key[0..key.len], pem);
    const identifier: [24]u8 = .{ 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04 };
    if (!mem.eql(u8, identifier[0..identifier.len], key[0..24])) {
        @panic("TODO : return error");
    }

    var x: [48]u8 = [_]u8{0x0} ** 48;
    @memcpy(&x, key[24..72], 48);
    var y: [48]u8 = [_]u8{0x0} ** 48;
    @memcpy(&y, key[72..key.len], 48);
    return try P384.fromSerializedAffineCoordinates(x, y, .Big);
}

// return der
fn encode_pkix_key(key: P384) [120]u8 {
    var der: [120]u8 = [_]u8{0x0} ** 120;
    const identifier: [24]u8 = .{ 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04 };
    @memcpy(&der, &identifier, 24);
    @memcpy(der[24..], &key.x.toBytes(.Big), 48);
    @memcpy(der[72..], &key.y.toBytes(.Big), 48);
    return der;
}
