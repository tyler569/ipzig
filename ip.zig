const std = @import("std");
const warn = std.debug.warn;

const BadIpAddress = error.BadIpAddress;

pub fn parse_ip(ip: []const u8) !u32 {
    if (1 == 1) {
        return error.BadIpAddress;
    }
    return 0x0a0a0a0a;
}

pub fn format_ip(buf: []u8, ip: u32) ![]u8 {
    const o1 = (ip & 0xFF000000) >> 24;
    const o2 = (ip & 0x00FF0000) >> 16;
    const o3 = (ip & 0x0000FF00) >>  8;
    const o4 = (ip & 0x000000FF);

    return try std.fmt.bufPrint(buf, "{}.{}.{}.{}", o4, o3, o2, o1);
}

test "ip addresses format correctly" {
    var buf: [64]u8 = undefined;

    var fip = try format_ip(buf[0..], 0x06050403);
    std.testing.expect(std.mem.eql(u8, fip, "3.4.5.6"));
    fip = try format_ip(buf[0..], 0x0a0a0a0a);
    std.testing.expect(std.mem.eql(u8, fip, "10.10.10.10"));
    fip = try format_ip(buf[0..], 0xffffffff);
    std.testing.expect(std.mem.eql(u8, fip, "255.255.255.255"));
}

pub fn print_ip(ip: u32) void {
    var buf: [64]u8 = undefined;
    const fip = format_ip(buf[0..], ip);
    warn("{}", fip);
}

const IpHdr = packed struct {
    ihl: u4,
    version: u4,
    tos: u8,
    len: u16,
    id: u16,
    evil: u1, // RFC 3514
    df: u1,
    mf: u1,
    frag_off: u13,
    ttl: u8,
    proto: u8,
    chksm: u16,
    src: u32,
    dst: u32,

    pub fn calc_chksm(self: *const IpHdr) u16 {
        const words = @ptrCast(*const [10]u16, @alignCast(4, self));

        var i: i32 = 0;
        var sum: u32 = 0;
        for (words) |word| {
            sum += @bswap(u16, word);
        }

        sum = (sum & 0xFFFF) + (sum >> 16);
        var csum: u16 = @intCast(u16, sum);
        return csum;
    }

    pub fn set_chksm(self: *IpHdr) void {
        self.chksm = @bswap(u16, self.calc_chksm());
    }

    pub fn pretty_print(self: *const IpHdr) void {
        const words = @ptrCast(*const [20]u8, @alignCast(4, self));
        for (words) |word| {
            std.debug.warn("{x2} ", word);
        }
        std.debug.warn("\n");
    }
};

test "checksums are correct" {
    var ip align(4) = IpHdr{
        .ihl = 5,
        .version = 4,
        .tos = 0,
        .len = @bswap(u16, 64),
        .id = @bswap(u16, 0x1000),
        .evil = 0,
        .df = 0,
        .mf = 0,
        .frag_off = 0,
        .ttl = 64,
        .proto = 17,
        .chksm = 0,
        .src = @bswap(u32, 0x0a010101),
        .dst = @bswap(u32, 0x0a010102),
    };

    ip.set_chksm();
    // ip.pretty_print();
    // TODO: this may be wrong, python was giving me weird results
    // when I was trying to cross-check
    std.testing.expectEqual(ip.chksm, 0x56ab);
}

