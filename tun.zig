
const std = @import("std");
const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("errno.h");
    @cInclude("stdbool.h");
    @cInclude("stdio.h");
    @cInclude("string.h");
    @cInclude("sys/ioctl.h");
    @cInclude("sys/types.h");
    @cInclude("sys/stat.h");
    @cInclude("sched.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
    @cInclude("linux/if.h");
    @cInclude("linux/if_tun.h");
});

fn zero(comptime T: type) T {
    var v: T = undefined;
    @memset(@ptrCast([*]u8, &v), 0, @sizeOf(T));
    return v;
}

// For some reason cInclude doesn't get this one
const TUNSETIFF: c_ulong = 0x400454ca;

const NetnsError = error.NetnsError;
const TunError = error.TunError;

// Once you change to a namespace, you can't change back to the default!!!
// (currently)
var changed_netns: bool = false;
var current_netns: []const u8 = "<default>";

pub fn set_netns(netns_name: []const u8) !void {
    if (changed_netns) {
        return NetnsError;
    }
    current_netns = netns_name;

    var netns_file_buf: [256]u8 = undefined;
    const netns_file = try std.fmt.bufPrint(netns_file_buf[0..],
                                    "/var/run/netns/{s}\x00", netns_name);

    // std.debug.warn("file: {s}\n", netns_file);

    const nsfd: c_int = c.open(netns_file.ptr, c.O_RDONLY);
    if (nsfd < 0) {
        return NetnsError;
    }

    var err: c_int = c.setns(nsfd, c.CLONE_NEWNET);
    if (err != 0) {
        return NetnsError;
    }
    
    err = c.close(nsfd);
    if (err != 0) {
        return NetnsError;
    }
}

pub fn tun_alloc(tun_name: []const u8) !c_int {
    // std.debug.warn("allocating {}\n", tun_name);

    const tunfd: c_int = c.open(c"/dev/net/tun", c.O_RDWR);
    if (tunfd < 0) {
        return TunError;
    }

    var ifr: c.ifreq = zero(c.ifreq);

    ifr.ifr_ifru.ifru_flags = c.IFF_TUN | c.IFF_NO_PI;
    var name = ifr.ifr_ifrn.ifrn_name;
    for (tun_name) |v, i| {
        name[i] = v;
    }
    name[tun_name.len] = 0;

    const err = c.ioctl(tunfd, TUNSETIFF, &ifr);
    if (err != 0) {
        return TunError;
    }

    return tunfd;
}

test "setting namespaces" {
    // the "blue" namespace needs to be set up before this
    // I have no interest in making this happen during the test
    //
    // This test also has to run as root
    try set_netns("blue");
}

test "openning tunnel" {
    // ditto above, interface needs to exist and the test (probably)
    // needs to run as root
    _ = try tun_alloc("tun0");
}

const RWErrors = error {
    ReadError,
    WriteError,
};

pub const Tun = struct {
    name: []const u8,
    netns: []const u8,
    fd: c_int,

    pub fn init(name: []const u8) !Tun {
        const fd = try tun_alloc(name);
        return Tun{ .name = name, .netns = current_netns, .fd = fd };
    }

    pub fn initWithNs(name: []const u8, namespace: []const u8) !Tun {
        try set_netns(namespace);
        const fd = try tun_alloc(name);

        return Tun{ .name = name, .netns = current_netns, .fd = fd };
    }

    pub fn read(self: *const Tun, buf: []u8) ![]u8 {
        const rl = c.read(self.fd, buf.ptr, buf.len);
        if (rl <= 0) {
            return error.ReadError;
        }
        return buf[0..@intCast(usize, rl)];
    }

    pub fn write(self: *const Tun, buf: []const u8) !void {
        const wl = c.write(self.fd, buf.ptr, buf.len);
        if (wl != @intCast(c_int, buf.len)) {
            return error.WriteError;
        }
    }
};

pub fn read_any([]const Tun, buf: []u8) Tun {
    // notimplemented - should do the c.select() call
}

