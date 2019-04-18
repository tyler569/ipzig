
const std = @import("std");
const warn = std.debug.warn;
const tun = @import("./tun.zig");
const ip = @import("./ip.zig");
const Tun = tun.Tun;

fn pretty_packet(pkt: []const u8) void {
    for (pkt) |byte| {
        warn("{x2} ", byte);
    }
    warn("\n");
}

pub fn main() !void {
    const t1 = try Tun.init("tun0");
    warn("tun0 is {}\n", t1);

    const t2 = try Tun.initWithNs("tun0", "blue");
    warn("blue:tun0 is {}\n", t2);


    while (true) {
        var pkt_buf: [1500]u8 = undefined;
        const pkt = try t1.read(pkt_buf[0..]);
        
        pretty_packet(pkt);
    }
}

