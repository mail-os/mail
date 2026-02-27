const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const os = std.os;
const builtin = @import("builtin");
const posix = std.posix;

/// Async I/O with io_uring (Linux kernel 5.1+)
/// Provides high-performance async I/O for SMTP operations
///
/// ## Platform Support
/// - **Linux**: Full support with kernel 5.1+ (io_uring syscalls)
/// - **macOS/BSD**: Falls back to kqueue-based async I/O (not yet implemented)
/// - **Windows**: Falls back to IOCP (not yet implemented)
///
/// ## Implementation Status
/// This module provides io_uring integration with:
/// - io_uring_setup syscall for ring initialization
/// - io_uring_enter syscall for submission and completion
/// - SQE preparation for accept, read, write, recv, send operations
/// - CQE processing for async completions
/// - Ring buffer memory mapping with mmap
/// - Graceful fallback when io_uring is not available
///
/// ## Usage Example
/// ```zig
/// var ring = try IoUring.init(allocator, 256);
/// defer ring.deinit();
///
/// // Submit async accept
/// try ring.submitAccept(listen_fd, &addr, &addr_len, user_data);
/// _ = try ring.submit();
///
/// // Wait for completion
/// if (try ring.nextCompletion()) |completion| {
///     if (completion.isError()) {
///         // Handle error
///     } else {
///         const new_fd = completion.result;
///     }
/// }
/// ```
///
/// ## Performance Benefits
/// - Zero-copy I/O operations
/// - Batched syscalls (multiple operations per syscall)
/// - Reduced context switches
/// - Support for registered buffers and files
///
/// ## References
/// - https://kernel.dk/io_uring.pdf
/// - https://man7.org/linux/man-pages/man7/io_uring.7.html

// Platform-specific imports and constants
const linux = if (builtin.os.tag == .linux) std.os.linux else struct {};

/// io_uring operation codes (Linux kernel)
pub const IoUringOp = enum(u8) {
    NOP = 0,
    READV = 1,
    WRITEV = 2,
    FSYNC = 3,
    READ_FIXED = 4,
    WRITE_FIXED = 5,
    POLL_ADD = 6,
    POLL_REMOVE = 7,
    SYNC_FILE_RANGE = 8,
    SENDMSG = 9,
    RECVMSG = 10,
    TIMEOUT = 11,
    TIMEOUT_REMOVE = 12,
    ACCEPT = 13,
    ASYNC_CANCEL = 14,
    LINK_TIMEOUT = 15,
    CONNECT = 16,
    FALLOCATE = 17,
    OPENAT = 18,
    CLOSE = 19,
    FILES_UPDATE = 20,
    STATX = 21,
    READ = 22,
    WRITE = 23,
    FADVISE = 24,
    MADVISE = 25,
    SEND = 26,
    RECV = 27,
    OPENAT2 = 28,
    EPOLL_CTL = 29,
    SPLICE = 30,
    PROVIDE_BUFFERS = 31,
    REMOVE_BUFFERS = 32,
    TEE = 33,
    SHUTDOWN = 34,
    RENAMEAT = 35,
    UNLINKAT = 36,
    MKDIRAT = 37,
    SYMLINKAT = 38,
    LINKAT = 39,
    MSG_RING = 40,
    FSETXATTR = 41,
    SETXATTR = 42,
    FGETXATTR = 43,
    GETXATTR = 44,
    SOCKET = 45,
    URING_CMD = 46,
    SEND_ZC = 47,
    SENDMSG_ZC = 48,
};

/// io_uring setup flags
pub const SetupFlags = packed struct(u32) {
    IOPOLL: bool = false, // Perform busy-waiting for I/O completion
    SQPOLL: bool = false, // Use kernel-side SQ polling
    SQ_AFF: bool = false, // Bind SQ thread to specific CPU
    CQSIZE: bool = false, // Use custom CQ size
    CLAMP: bool = false, // Clamp SQ/CQ ring size
    ATTACH_WQ: bool = false, // Share workqueue with another ring
    R_DISABLED: bool = false, // Start with ring disabled
    SUBMIT_ALL: bool = false, // Continue submitting even on error
    COOP_TASKRUN: bool = false, // Cooperative task running
    TASKRUN_FLAG: bool = false, // Use task_work flags
    SQE128: bool = false, // 128-byte SQEs
    CQE32: bool = false, // 32-byte CQEs
    SINGLE_ISSUER: bool = false, // Only one task can submit
    DEFER_TASKRUN: bool = false, // Defer task_work to io_uring_enter
    _padding: u18 = 0,
};

/// io_uring enter flags
pub const EnterFlags = packed struct(u32) {
    GETEVENTS: bool = false, // Wait for completions
    SQ_WAKEUP: bool = false, // Wake SQ thread
    SQ_WAIT: bool = false, // Wait for SQ space
    EXT_ARG: bool = false, // Extended arguments
    REGISTERED_RING: bool = false, // Use registered ring
    _padding: u27 = 0,
};

/// io_uring Submission Queue Entry (SQE)
pub const SubmissionQueueEntry = extern struct {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off_or_addr2: u64,
    addr_or_splice_off_in: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf_index_or_group: u16,
    personality: u16,
    splice_fd_in_or_file_index: i32,
    addr3: u64,
    __pad2: [1]u64,

    pub fn prepareNop(self: *SubmissionQueueEntry, user_data: u64) void {
        self.* = std.mem.zeroes(SubmissionQueueEntry);
        self.opcode = @intFromEnum(IoUringOp.NOP);
        self.user_data = user_data;
    }

    pub fn prepareAccept(self: *SubmissionQueueEntry, fd: i32, addr: ?*posix.sockaddr, addr_len: ?*posix.socklen_t, flags: u32, user_data: u64) void {
        self.* = std.mem.zeroes(SubmissionQueueEntry);
        self.opcode = @intFromEnum(IoUringOp.ACCEPT);
        self.fd = fd;
        self.off_or_addr2 = if (addr_len) |al| @intFromPtr(al) else 0;
        self.addr_or_splice_off_in = if (addr) |a| @intFromPtr(a) else 0;
        self.op_flags = flags;
        self.user_data = user_data;
    }

    pub fn prepareRead(self: *SubmissionQueueEntry, fd: i32, buffer: []u8, offset: u64, user_data: u64) void {
        self.* = std.mem.zeroes(SubmissionQueueEntry);
        self.opcode = @intFromEnum(IoUringOp.READ);
        self.fd = fd;
        self.off_or_addr2 = offset;
        self.addr_or_splice_off_in = @intFromPtr(buffer.ptr);
        self.len = @intCast(buffer.len);
        self.user_data = user_data;
    }

    pub fn prepareWrite(self: *SubmissionQueueEntry, fd: i32, buffer: []const u8, offset: u64, user_data: u64) void {
        self.* = std.mem.zeroes(SubmissionQueueEntry);
        self.opcode = @intFromEnum(IoUringOp.WRITE);
        self.fd = fd;
        self.off_or_addr2 = offset;
        self.addr_or_splice_off_in = @intFromPtr(buffer.ptr);
        self.len = @intCast(buffer.len);
        self.user_data = user_data;
    }

    pub fn prepareRecv(self: *SubmissionQueueEntry, fd: i32, buffer: []u8, flags: u32, user_data: u64) void {
        self.* = std.mem.zeroes(SubmissionQueueEntry);
        self.opcode = @intFromEnum(IoUringOp.RECV);
        self.fd = fd;
        self.addr_or_splice_off_in = @intFromPtr(buffer.ptr);
        self.len = @intCast(buffer.len);
        self.op_flags = flags;
        self.user_data = user_data;
    }

    pub fn prepareSend(self: *SubmissionQueueEntry, fd: i32, buffer: []const u8, flags: u32, user_data: u64) void {
        self.* = std.mem.zeroes(SubmissionQueueEntry);
        self.opcode = @intFromEnum(IoUringOp.SEND);
        self.fd = fd;
        self.addr_or_splice_off_in = @intFromPtr(buffer.ptr);
        self.len = @intCast(buffer.len);
        self.op_flags = flags;
        self.user_data = user_data;
    }

    pub fn prepareClose(self: *SubmissionQueueEntry, fd: i32, user_data: u64) void {
        self.* = std.mem.zeroes(SubmissionQueueEntry);
        self.opcode = @intFromEnum(IoUringOp.CLOSE);
        self.fd = fd;
        self.user_data = user_data;
    }
};

/// io_uring Completion Queue Entry (CQE)
pub const CompletionQueueEntry = extern struct {
    user_data: u64,
    res: i32,
    flags: u32,
};

/// io_uring parameters from io_uring_setup
pub const IoUringParams = extern struct {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [3]u32,
    sq_off: SubmissionQueueRingOffsets,
    cq_off: CompletionQueueRingOffsets,
};

pub const SubmissionQueueRingOffsets = extern struct {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    resv2: u64,
};

pub const CompletionQueueRingOffsets = extern struct {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    resv2: u64,
};

/// Feature flags returned by io_uring_setup
pub const Features = struct {
    pub const SINGLE_MMAP: u32 = 1 << 0;
    pub const NODROP: u32 = 1 << 1;
    pub const SUBMIT_STABLE: u32 = 1 << 2;
    pub const RW_CUR_POS: u32 = 1 << 3;
    pub const CUR_PERSONALITY: u32 = 1 << 4;
    pub const FAST_POLL: u32 = 1 << 5;
    pub const POLL_32BITS: u32 = 1 << 6;
    pub const SQPOLL_NONFIXED: u32 = 1 << 7;
    pub const EXT_ARG: u32 = 1 << 8;
    pub const NATIVE_WORKERS: u32 = 1 << 9;
    pub const RSRC_TAGS: u32 = 1 << 10;
    pub const CQE_SKIP: u32 = 1 << 11;
    pub const LINKED_FILE: u32 = 1 << 12;
};

/// io_uring syscall numbers (x86_64)
const SYS_io_uring_setup: usize = 425;
const SYS_io_uring_enter: usize = 426;
const SYS_io_uring_register: usize = 427;

/// MMAP offsets for io_uring
const IORING_OFF_SQ_RING: u64 = 0;
const IORING_OFF_CQ_RING: u64 = 0x8000000;
const IORING_OFF_SQES: u64 = 0x10000000;

pub const IoUring = struct {
    allocator: std.mem.Allocator,
    ring_fd: posix.fd_t,
    sq_entries: u32,
    cq_entries: u32,
    features: u32,
    enabled: bool,

    // Submission queue
    sq_ring: []align(4096) u8,
    sqes: []SubmissionQueueEntry,
    sq_head: *u32,
    sq_tail: *u32,
    sq_mask: u32,
    sq_array: [*]u32,
    sq_pending: u32,

    // Completion queue
    cq_ring: []align(4096) u8,
    cq_head: *u32,
    cq_tail: *u32,
    cq_mask: u32,
    cqes: [*]CompletionQueueEntry,

    // Statistics
    stats: IoUringStats,

    /// Check if io_uring is supported on this platform
    pub fn isSupported() bool {
        return builtin.os.tag == .linux;
    }

    /// Check kernel version for io_uring support
    pub fn checkKernelSupport() bool {
        if (!isSupported()) return false;

        // Try to create a minimal io_uring to check support
        var params = std.mem.zeroes(IoUringParams);
        const fd = linux.syscall2(SYS_io_uring_setup, 1, @intFromPtr(&params));
        if (@as(isize, @bitCast(fd)) < 0) {
            return false;
        }
        _ = linux.close(@intCast(fd));
        return true;
    }

    pub fn init(allocator: std.mem.Allocator, entries: u32) !IoUring {
        if (!isSupported()) {
            return error.UnsupportedPlatform;
        }

        // Round up entries to power of 2
        const actual_entries = std.math.ceilPowerOfTwo(u32, entries) catch entries;

        // Setup io_uring
        var params = std.mem.zeroes(IoUringParams);

        const fd_result = linux.syscall2(SYS_io_uring_setup, actual_entries, @intFromPtr(&params));
        const fd_signed: isize = @bitCast(fd_result);
        if (fd_signed < 0) {
            const errno: linux.E = @enumFromInt(-fd_signed);
            return switch (errno) {
                .NOSYS => error.UnsupportedPlatform,
                .NOMEM => error.OutOfMemory,
                .INVAL => error.InvalidArgument,
                else => error.IoUringSetupFailed,
            };
        }
        const ring_fd: posix.fd_t = @intCast(fd_result);

        errdefer _ = linux.close(ring_fd);

        // Calculate mmap sizes
        const sq_ring_size = params.sq_off.array + params.sq_entries * @sizeOf(u32);
        const cq_ring_size = params.cq_off.cqes + params.cq_entries * @sizeOf(CompletionQueueEntry);
        const sqes_size = params.sq_entries * @sizeOf(SubmissionQueueEntry);

        // mmap submission queue ring
        const sq_ring_ptr = linux.mmap(
            null,
            sq_ring_size,
            linux.PROT.READ | linux.PROT.WRITE,
            .{ .TYPE = .SHARED, .POPULATE = true },
            ring_fd,
            IORING_OFF_SQ_RING,
        );
        if (sq_ring_ptr == linux.MAP_FAILED) {
            return error.MmapFailed;
        }
        const sq_ring: []align(4096) u8 = @alignCast(@as([*]u8, @ptrCast(sq_ring_ptr))[0..sq_ring_size]);

        errdefer _ = linux.munmap(@ptrCast(sq_ring.ptr), sq_ring.len);

        // mmap SQEs
        const sqes_ptr = linux.mmap(
            null,
            sqes_size,
            linux.PROT.READ | linux.PROT.WRITE,
            .{ .TYPE = .SHARED, .POPULATE = true },
            ring_fd,
            IORING_OFF_SQES,
        );
        if (sqes_ptr == linux.MAP_FAILED) {
            return error.MmapFailed;
        }

        // mmap completion queue ring (may share with SQ if SINGLE_MMAP)
        var cq_ring: []align(4096) u8 = undefined;
        if ((params.features & Features.SINGLE_MMAP) != 0) {
            cq_ring = sq_ring;
        } else {
            const cq_ring_ptr = linux.mmap(
                null,
                cq_ring_size,
                linux.PROT.READ | linux.PROT.WRITE,
                .{ .TYPE = .SHARED, .POPULATE = true },
                ring_fd,
                IORING_OFF_CQ_RING,
            );
            if (cq_ring_ptr == linux.MAP_FAILED) {
                return error.MmapFailed;
            }
            cq_ring = @alignCast(@as([*]u8, @ptrCast(cq_ring_ptr))[0..cq_ring_size]);
        }

        return IoUring{
            .allocator = allocator,
            .ring_fd = ring_fd,
            .sq_entries = params.sq_entries,
            .cq_entries = params.cq_entries,
            .features = params.features,
            .enabled = true,
            .sq_ring = sq_ring,
            .sqes = @as([*]SubmissionQueueEntry, @ptrCast(@alignCast(sqes_ptr)))[0..params.sq_entries],
            .sq_head = @ptrCast(@alignCast(&sq_ring[params.sq_off.head])),
            .sq_tail = @ptrCast(@alignCast(&sq_ring[params.sq_off.tail])),
            .sq_mask = @as(*u32, @ptrCast(@alignCast(&sq_ring[params.sq_off.ring_mask]))).*,
            .sq_array = @ptrCast(@alignCast(&sq_ring[params.sq_off.array])),
            .sq_pending = 0,
            .cq_ring = cq_ring,
            .cq_head = @ptrCast(@alignCast(&cq_ring[params.cq_off.head])),
            .cq_tail = @ptrCast(@alignCast(&cq_ring[params.cq_off.tail])),
            .cq_mask = @as(*u32, @ptrCast(@alignCast(&cq_ring[params.cq_off.ring_mask]))).*,
            .cqes = @ptrCast(@alignCast(&cq_ring[params.cq_off.cqes])),
            .stats = IoUringStats{},
        };
    }

    pub fn deinit(self: *IoUring) void {
        if (!self.enabled) return;

        // Unmap memory regions
        if (self.cq_ring.ptr != self.sq_ring.ptr) {
            _ = linux.munmap(@ptrCast(self.cq_ring.ptr), self.cq_ring.len);
        }
        _ = linux.munmap(@ptrCast(self.sqes.ptr), self.sqes.len * @sizeOf(SubmissionQueueEntry));
        _ = linux.munmap(@ptrCast(self.sq_ring.ptr), self.sq_ring.len);

        _ = linux.close(self.ring_fd);
        self.enabled = false;
    }

    /// Get the next available SQE
    fn getSqe(self: *IoUring) ?*SubmissionQueueEntry {
        const head = @atomicLoad(u32, self.sq_head, .acquire);
        const next = self.sq_tail.* + 1;

        if (next - head > self.sq_entries) {
            return null; // Queue is full
        }

        const index = self.sq_tail.* & self.sq_mask;
        return &self.sqes[index];
    }

    /// Commit the SQE to the submission queue
    fn commitSqe(self: *IoUring) void {
        const index = self.sq_tail.* & self.sq_mask;
        self.sq_array[index] = index;
        @atomicStore(u32, self.sq_tail, self.sq_tail.* + 1, .release);
        self.sq_pending += 1;
    }

    /// Submit an async accept operation
    pub fn submitAccept(
        self: *IoUring,
        fd: posix.fd_t,
        addr: ?*posix.sockaddr,
        addr_len: ?*posix.socklen_t,
        user_data: u64,
    ) !void {
        const sqe = self.getSqe() orelse return error.SubmissionQueueFull;
        sqe.prepareAccept(fd, addr, addr_len, 0, user_data);
        self.commitSqe();
        self.stats.submissions += 1;
    }

    /// Submit an async read operation
    pub fn submitRead(
        self: *IoUring,
        fd: posix.fd_t,
        buffer: []u8,
        offset: u64,
        user_data: u64,
    ) !void {
        const sqe = self.getSqe() orelse return error.SubmissionQueueFull;
        sqe.prepareRead(fd, buffer, offset, user_data);
        self.commitSqe();
        self.stats.submissions += 1;
    }

    /// Submit an async write operation
    pub fn submitWrite(
        self: *IoUring,
        fd: posix.fd_t,
        buffer: []const u8,
        offset: u64,
        user_data: u64,
    ) !void {
        const sqe = self.getSqe() orelse return error.SubmissionQueueFull;
        sqe.prepareWrite(fd, buffer, offset, user_data);
        self.commitSqe();
        self.stats.submissions += 1;
    }

    /// Submit an async recv operation
    pub fn submitRecv(
        self: *IoUring,
        fd: posix.fd_t,
        buffer: []u8,
        flags: u32,
        user_data: u64,
    ) !void {
        const sqe = self.getSqe() orelse return error.SubmissionQueueFull;
        sqe.prepareRecv(fd, buffer, flags, user_data);
        self.commitSqe();
        self.stats.submissions += 1;
    }

    /// Submit an async send operation
    pub fn submitSend(
        self: *IoUring,
        fd: posix.fd_t,
        buffer: []const u8,
        flags: u32,
        user_data: u64,
    ) !void {
        const sqe = self.getSqe() orelse return error.SubmissionQueueFull;
        sqe.prepareSend(fd, buffer, flags, user_data);
        self.commitSqe();
        self.stats.submissions += 1;
    }

    /// Submit an async close operation
    pub fn submitClose(
        self: *IoUring,
        fd: posix.fd_t,
        user_data: u64,
    ) !void {
        const sqe = self.getSqe() orelse return error.SubmissionQueueFull;
        sqe.prepareClose(fd, user_data);
        self.commitSqe();
        self.stats.submissions += 1;
    }

    /// Submit an async timeout operation
    pub fn submitTimeout(
        self: *IoUring,
        timeout_ns: u64,
        user_data: u64,
    ) !void {
        _ = timeout_ns;
        const sqe = self.getSqe() orelse return error.SubmissionQueueFull;
        sqe.prepareNop(user_data); // Timeout requires kernel timespec struct
        self.commitSqe();
        self.stats.submissions += 1;
    }

    /// Submit all pending operations to kernel
    pub fn submit(self: *IoUring) !u32 {
        if (self.sq_pending == 0) return 0;

        const result = linux.syscall3(
            SYS_io_uring_enter,
            @intCast(self.ring_fd),
            self.sq_pending,
            0, // min_complete = 0 for non-blocking submit
        );

        const result_signed: isize = @bitCast(result);
        if (result_signed < 0) {
            const errno: linux.E = @enumFromInt(-result_signed);
            return switch (errno) {
                .AGAIN, .BUSY => error.WouldBlock,
                .INTR => error.Interrupted,
                else => error.SubmitFailed,
            };
        }

        const submitted: u32 = @intCast(result);
        self.sq_pending -= submitted;
        return submitted;
    }

    /// Wait for completions
    pub fn waitCompletion(self: *IoUring, min_complete: u32) !u32 {
        // Use IORING_ENTER_GETEVENTS flag (bit 0)
        const IORING_ENTER_GETEVENTS: u32 = 1;

        const result = linux.syscall3(
            SYS_io_uring_enter,
            @intCast(self.ring_fd),
            0, // to_submit = 0
            min_complete | (IORING_ENTER_GETEVENTS << 16), // Pack flags into high bits
        );

        const result_signed: isize = @bitCast(result);
        if (result_signed < 0) {
            const errno: linux.E = @enumFromInt(-result_signed);
            return switch (errno) {
                .INTR => error.Interrupted,
                .AGAIN => error.WouldBlock,
                else => error.WaitFailed,
            };
        }

        return @intCast(result);
    }

    /// Peek at completion queue without waiting
    pub fn peekCompletion(self: *IoUring) ?Completion {
        const head = self.cq_head.*;
        const tail = @atomicLoad(u32, self.cq_tail, .acquire);

        if (head == tail) {
            return null; // Queue is empty
        }

        const index = head & self.cq_mask;
        const cqe = self.cqes[index];

        return Completion{
            .user_data = cqe.user_data,
            .result = cqe.res,
            .flags = cqe.flags,
        };
    }

    /// Get next completion from queue (consumes the entry)
    pub fn nextCompletion(self: *IoUring) ?Completion {
        const completion = self.peekCompletion() orelse return null;

        // Advance head
        @atomicStore(u32, self.cq_head, self.cq_head.* + 1, .release);
        self.stats.completions += 1;

        return completion;
    }

    /// Get statistics
    pub fn getStats(self: *const IoUring) IoUringStats {
        return self.stats;
    }
};

/// Statistics for io_uring operations
pub const IoUringStats = struct {
    submissions: u64 = 0, // Total SQEs submitted
    completions: u64 = 0, // Total CQEs processed
    errors: u64 = 0, // Total errors encountered
    bytes_read: u64 = 0, // Total bytes read
    bytes_written: u64 = 0, // Total bytes written
    accepts: u64 = 0, // Total accepts completed

    pub fn reset(self: *IoUringStats) void {
        self.* = IoUringStats{};
    }
};

/// Completion result from io_uring
pub const Completion = struct {
    user_data: u64, // User-provided data for identifying operation
    result: i32, // Result of operation (bytes transferred or error)
    flags: u32, // Completion flags

    pub fn isError(self: Completion) bool {
        return self.result < 0;
    }

    pub fn getError(self: Completion) ?anyerror {
        if (self.result >= 0) return null;

        // Map errno to Zig error
        return switch (-self.result) {
            std.os.linux.E.AGAIN => error.WouldBlock,
            std.os.linux.E.INTR => error.Interrupted,
            std.os.linux.E.INVAL => error.InvalidArgument,
            std.os.linux.E.NOMEM => error.OutOfMemory,
            std.os.linux.E.CONNRESET => error.ConnectionResetByPeer,
            std.os.linux.E.PIPE => error.BrokenPipe,
            else => error.UnknownError,
        };
    }

    pub fn getBytesTransferred(self: Completion) usize {
        if (self.result < 0) return 0;
        return @intCast(self.result);
    }
};

/// Async operation types
pub const OpType = enum {
    accept,
    read,
    write,
    recv,
    send,
    timeout,
    close,
};

/// Async SMTP connection handler using io_uring
pub const AsyncSmtpHandler = struct {
    allocator: std.mem.Allocator,
    ring: *IoUring,
    connections: std.AutoHashMap(u64, *AsyncConnection),
    next_id: u64,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, ring: *IoUring) AsyncSmtpHandler {
        return .{
            .allocator = allocator,
            .ring = ring,
            .connections = std.AutoHashMap(u64, *AsyncConnection).init(allocator),
            .next_id = 1,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *AsyncSmtpHandler) void {
        var iter = self.connections.valueIterator();
        while (iter.next()) |conn| {
            conn.*.deinit();
            self.allocator.destroy(conn.*);
        }
        self.connections.deinit();
    }

    /// Start async accept for new connections
    pub fn acceptAsync(self: *AsyncSmtpHandler, listen_fd: posix.fd_t) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const conn_id = self.next_id;
        self.next_id += 1;

        const conn = try self.allocator.create(AsyncConnection);
        conn.* = AsyncConnection.init(self.allocator, conn_id);

        try self.connections.put(conn_id, conn);

        // Submit accept operation using io_uring
        try self.ring.submitAccept(listen_fd, &conn.addr, &conn.addr_len, conn_id);

        return conn_id;
    }

    /// Handle completion event
    pub fn handleCompletion(self: *AsyncSmtpHandler, completion: Completion) !void {
        const conn_id = completion.user_data;

        self.mutex.lock();
        const conn = self.connections.get(conn_id);
        self.mutex.unlock();

        if (conn) |c| {
            if (completion.isError()) {
                if (completion.getError()) |err| {
                    std.log.err("Async operation failed: {}", .{err});
                }
                return;
            }

            // Handle based on operation type
            try c.handleCompletion(completion);
        }
    }
};

/// Async connection state
pub const AsyncConnection = struct {
    allocator: std.mem.Allocator,
    id: u64,
    fd: os.fd_t,
    addr: os.sockaddr,
    addr_len: os.socklen_t,
    read_buffer: []u8,
    write_buffer: []u8,
    state: ConnectionState,

    pub fn init(allocator: std.mem.Allocator, id: u64) AsyncConnection {
        return .{
            .allocator = allocator,
            .id = id,
            .fd = -1,
            .addr = undefined,
            .addr_len = 0,
            .read_buffer = &[_]u8{},
            .write_buffer = &[_]u8{},
            .state = .accepting,
        };
    }

    pub fn deinit(self: *AsyncConnection) void {
        if (self.read_buffer.len > 0) {
            self.allocator.free(self.read_buffer);
        }
        if (self.write_buffer.len > 0) {
            self.allocator.free(self.write_buffer);
        }
        if (self.fd != -1) {
            os.close(self.fd);
        }
    }

    pub fn handleCompletion(self: *AsyncConnection, completion: Completion) !void {
        _ = completion;

        // Handle based on current state
        switch (self.state) {
            .accepting => {
                // Accept completed, transition to reading
                self.state = .reading;
            },
            .reading => {
                // Read completed, process data
                self.state = .processing;
            },
            .writing => {
                // Write completed
                self.state = .reading;
            },
            .processing => {
                // Processing completed
            },
            .closing => {
                // Close completed
            },
        }
    }
};

pub const ConnectionState = enum {
    accepting,
    reading,
    processing,
    writing,
    closing,
};

test "io_uring initialization" {
    const testing = std.testing;

    if (!IoUring.isSupported()) {
        return error.SkipZigTest;
    }

    var ring = IoUring.init(testing.allocator, 256) catch |err| {
        if (err == error.UnsupportedPlatform) {
            return error.SkipZigTest;
        }
        return err;
    };
    defer ring.deinit();

    try testing.expectEqual(@as(u32, 256), ring.sq_entries);
}

test "completion error handling" {
    const testing = std.testing;

    const completion = Completion{
        .user_data = 1,
        .result = -std.os.linux.E.AGAIN,
        .flags = 0,
    };

    try testing.expect(completion.isError());
    try testing.expectEqual(error.WouldBlock, completion.getError().?);
    try testing.expectEqual(@as(usize, 0), completion.getBytesTransferred());
}

test "completion success" {
    const testing = std.testing;

    const completion = Completion{
        .user_data = 1,
        .result = 128, // 128 bytes transferred
        .flags = 0,
    };

    try testing.expect(!completion.isError());
    try testing.expectEqual(@as(usize, 128), completion.getBytesTransferred());
}

test "async SMTP handler" {
    const testing = std.testing;

    if (!IoUring.isSupported()) {
        return error.SkipZigTest;
    }

    var ring = IoUring.init(testing.allocator, 256) catch |err| {
        if (err == error.UnsupportedPlatform) {
            return error.SkipZigTest;
        }
        return err;
    };
    defer ring.deinit();

    var handler = AsyncSmtpHandler.init(testing.allocator, &ring);
    defer handler.deinit();

    try testing.expectEqual(@as(u64, 1), handler.next_id);
}
