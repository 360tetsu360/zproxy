# ZPROXY
[WIP] A simple proxy for mcbe written in zig.

# Usage
``` zig
const std = @import("std");
const network = @import("network");
const zproxy = @import("zproxy");

fn handle_client() bool {
    return false;
}

fn handle_server() bool {
    return false;
}

pub fn main() !void {
    try network.init();
    defer network.deinit();

    const bind_address = .{
        .address = .{ .ipv4 = network.Address.IPv4.loopback },
        .port = 19130,
    };

    const target_address = .{
        .address = .{ .ipv4 = network.Address.IPv4.loopback },
        .port = 19132,
    };

    try zproxy.startup(bind_address, target_address, handle_client, handle_server);
}
```