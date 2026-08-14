//! The socket layer, and only that.
//!
//! std.net is gone in 0.16, so every leg of the client — BNCS, MCP, the game — ends up calling
//! libc directly. Having each of them carry its own copy of connect/read/write is how two legs
//! end up with different timeout behaviour and nobody notices until one of them hangs.

const std = @import("std");

pub const Socket = c_int;

pub extern "c" fn socket(domain: c_int, sock_type: c_int, protocol: c_int) c_int;
pub extern "c" fn connect(fd: c_int, addr: *const anyopaque, len: c_uint) c_int;
pub extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
pub extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
pub extern "c" fn close(fd: c_int) c_int;
extern "c" fn setsockopt(fd: c_int, level: c_int, optname: c_int, optval: *const anyopaque, optlen: c_uint) c_int;
extern "c" fn gettimeofday(tv: *std.posix.timeval, tz: ?*anyopaque) c_int;

const SOCK_STREAM: c_int = 1;

pub const POLLIN: i16 = 0x0001;
pub const pollfd = extern struct { fd: c_int, events: i16, revents: i16 };
pub extern "c" fn poll(fds: *pollfd, nfds: c_uint, timeout: c_int) c_int;

pub fn setRecvTimeout(fd: Socket, ms: u32) void {
    const tv = std.posix.timeval{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
    _ = setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, &tv, @sizeOf(std.posix.timeval));
}

pub fn nowMs() i64 {
    var tv: std.posix.timeval = undefined;
    _ = gettimeofday(&tv, null);
    return @as(i64, @intCast(tv.sec)) * 1000 + @divTrunc(@as(i64, @intCast(tv.usec)), 1000);
}

pub fn writeAll(fd: Socket, buf: []const u8) !void {
    var sent: usize = 0;
    while (sent < buf.len) {
        const n = write(fd, buf.ptr + sent, buf.len - sent);
        if (n <= 0) return error.WriteFailed;
        sent += @intCast(n);
    }
}

/// Connect to the first address that answers. Hostname or dotted quad, v4 or v6.
pub fn connectResolved(gpa: std.mem.Allocator, host: []const u8, port: u16) !Socket {
    const chost = try gpa.dupeZ(u8, host);
    defer gpa.free(chost);
    var pbuf: [8]u8 = undefined;
    const cserv = std.fmt.bufPrintZ(&pbuf, "{d}", .{port}) catch unreachable;
    var hints = std.mem.zeroes(std.c.addrinfo);
    hints.family = 0; // AF_UNSPEC
    hints.socktype = SOCK_STREAM;
    var res: ?*std.c.addrinfo = null;
    if (@intFromEnum(std.c.getaddrinfo(chost.ptr, cserv.ptr, &hints, &res)) != 0) return error.ResolveFailed;
    defer if (res) |r| std.c.freeaddrinfo(r);
    var ai = res;
    while (ai) |a| : (ai = a.next) {
        const sa = a.addr orelse continue;
        const fd = socket(a.family, SOCK_STREAM, 0);
        if (fd < 0) continue;
        if (connect(fd, sa, a.addrlen) == 0) {
            setRecvTimeout(fd, 20000);
            return fd;
        }
        _ = close(fd);
    }
    return error.ConnectFailed;
}
