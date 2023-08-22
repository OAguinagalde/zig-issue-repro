const std = @import("std");
const zap = @import("zap");
const sqlite = @import("sqlite");

fn request_handler(request: zap.SimpleRequest) !void {

    const is_auth = if (request.getHeader("authentication")) |auth_string| std.mem.eql(u8, auth_string, "SuperSecretPasswordNotRealLol") else false;
    if (is_auth == false) return try HttpError(.unauthorized).send(request);

    if (request.path == null) return error.RequestWithoutPath;
    if (request.method == null) return error.RequestWithoutMethod;
    
    const method = request.method.?;
    const path = request.path.?;

    const out = try get_route_and_rest_from_path(path);
    const route = out.route;
    const rest = out.rest;

    std.log.debug("{s} - {s}", .{route, rest});
    
    if (routes.get(route)) |handlers| {

        if (std.mem.eql(u8, method, "GET")) {
            if (handlers.get) |f| { try f(request, rest); } 
            else try HttpError(.not_found).send(request);
        }

        else if (std.mem.eql(u8, method, "POST")) {
            if (handlers.post) |f| { try f(request, rest); } 
            else try HttpError(.not_found).send(request);
        }

        else if (std.mem.eql(u8, method, "PUT")) {
            if (handlers.put) |f| { try f(request, rest); } 
            else try HttpError(.not_found).send(request);
        }

        else if (std.mem.eql(u8, method, "DELETE")) {
            if (handlers.delete) |f| { try f(request, rest); } 
            else try HttpError(.not_found).send(request);
        }

        else if (std.mem.eql(u8, method, "PATCH")) {
            if (handlers.patch) |f| { try f(request, rest); } 
            else try HttpError(.not_found).send(request);
        }

        else {
            return error.RequestWithUnknownMethod;
        }

        return;
    }
    else {
        // No route found to handle it, so just serve index.html or something idk
        try request.sendFile("src/html/index.html");
    }

}

// TODO try while (std.tokenize("/")) |token|
fn get_route_and_rest_from_path(path: []const u8) ! struct { route: []const u8, rest: []const u8 } {
    
    const blank = .{ .route = "", .rest = "" };
    
    if (path.len == 0) return blank;
    
    if (path[0] != '/') return error.InvalidPath;
    
    if (path.len == 1) return blank;
    
    var index_of_next_slash: ?usize = null;
    for (path, 0..) |c, i| {
        if (i == 0) continue;
        if (c == '/') {
            index_of_next_slash = i;
            break;
        }
    }

    if (index_of_next_slash) |index| {
        // handle "//"
        if (index == 1) return blank;
        
        const route = path[0..index];
        // handle "/route/"
        if (path.len == index + 1) return .{ .route = route, .rest = "" };
        // handle "/route/aaa"
        // NOTE index+2 so that `rest` doesnt contain the initial slash
        return .{ .route = route, .rest = path[index+1..] };
    }
    else {
        return .{ .route = path, .rest = "" };
    }

    return error.PathParseError;
}

var error_id = std.atomic.Atomic(usize).init(0);

/// The reason this exists is because the original callback signature doesnt allow for errors,
/// but I want to have a catch it all point right before I return control back to zap so I can 
/// handle anything I need, or at the very least, let the client know that something went wrong
fn real_request_handler(request: zap.SimpleRequest) void {
    
    request_handler(request) catch |err| {
        // There should never appear an error here... But then again I programmed this so there will be errors lol
        // So lets try to log them so that they can be fixed.

        const id =  error_id.fetchAdd(1, .Monotonic);
        // Try to get a stack trace for the error
        var string = String.init(allocator);
        defer string.deinit();
        var writer = string.writer();
        if (@errorReturnTrace()) |stack_trace| {
            if (std.debug.getSelfDebugInfo()) |debug_info| {
                var arena = std.heap.ArenaAllocator.init(allocator);
                defer arena.deinit();
                const tty_config = std.io.tty.detectConfig(std.io.getStdErr());
                std.debug.writeStackTrace(stack_trace.*, writer, arena.allocator(), debug_info, tty_config) catch
                    |err2| std.log.err("[{d}] Failed to output the stack trace: {s}", .{id, @errorName(err2)});

            }
            else |err2| std.log.err("[{d}] Failed to get Self Debug information: {s}", .{id, @errorName(err2)});
        }
        else std.log.err("[{d}] Failed to obtain error stack trace, make sure this built contains error return tracing!", .{id, });

        std.log.err(
            \\
            \\==========================================================
            \\Unexpected error [{d}] ({s}) caught on request:
            \\# METHOD {s}
            \\# PATH   {s}
            \\# QUERY  {s}
            \\# BODY   {s}
            \\# Stack Trace: {s}
            \\==========================================================
            \\
            , .{
                id,
                @errorName(err),
                request.method orelse "NULL",
                request.path orelse "NULL",
                request.query orelse "NULL",
                request.body orelse "NULL",
                if (string.items.len > 0) string.items else "???"
            }
        );

        HttpError(.internal_server_error).send(request) catch |err2| std.log.err("[{d}] Failed to send 500: {s}", .{id, @errorName(err2)});
        
        // NOTE might need this later for better error reporting, not sure how to use it tho
        // const return_address = @returnAddress();
    };
}

// TODO docs

var queries: Queries = undefined;
var allocator: std.mem.Allocator = undefined;

const String = std.ArrayList(u8);

pub fn main() !void {
    
    // Initialize database connection
    var db = try sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .File = "data/data.sqlite" },
        .open_flags = .{
            .write = true,
            .create = true,
        },
        .threading_mode = .MultiThread,
    });
    defer db.deinit();
    
    queries = try Queries.init(&db);
    defer queries.deinit();

    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    allocator = gpa.allocator();

    {
        var http_server = zap.SimpleHttpListener.init(
            zap.SimpleHttpListenerSettings {
                .port = 3000,
                .on_request = real_request_handler,
                .log = true,
                // .public_folder = "some/folder",
                .max_clients = 100000,
                .max_body_size = 100 * 1024 * 1024,
            }
        );
        try http_server.listen();
        std.log.debug("Listening on http://127.0.0.1:3000", .{});
        zap.start(.{
            .threads = 2000,
            // IMPORTANT! It is crucial to only have a single worker for this example to work!
            // Multiple workers would have multiple copies of the users hashmap.
            //
            // Since zap is quite fast, you can do A LOT with a single worker.
            // Try it with `zig build run-endpoint -Drelease-fast`
            .workers = 1,
        });
    }
    std.log.debug("Has leaked: {}", .{gpa.detectLeaks()});
}

/// The signature of any function that will handle a request
pub const RequestHandler = *const fn (r: zap.SimpleRequest, args: []const u8) anyerror!void;

pub const HandlerCollection = struct {
    get: ?RequestHandler = null,
    post: ?RequestHandler = null,
    put: ?RequestHandler = null,
    delete: ?RequestHandler = null,
    patch: ?RequestHandler = null,
};

const AppErrors = Items.Error;

/// Every non 200 status eventually ends here where an error is sent to the client
fn HttpError(comptime code: zap.StatusCode) type {
    return struct {
        
        const send = if (code != zap.StatusCode.bad_request) send_http_error else send_with_context;

        /// Sends an HTTP standard error to the client, such as 404 or 500
        fn send_http_error(request: zap.SimpleRequest) !void {
            const string = std.fmt.comptimePrint(
                \\{{"http_error_code":{},"http_error_name":"{s}","http_error_message":"{s}"}}
                , .{ @intFromEnum(code), @tagName(code), comptime code.toString() }
            );
            request.setStatus(code);
            try request.sendBody(string);
        }

        /// Unlike `send_http_error`, these error includes some kind of context and is used when the error is at the application level, such as requesting and Item ID that doesnt
        /// exist or providing invalid data. These are all categorized as HTTP error 400 (AKA Bad Request). The extra information is provided as fields `app_error` and `app_error_message`
        fn send_with_context(request: zap.SimpleRequest, comptime error_code: usize, comptime error_message_format: []const u8, error_message_input: anytype) !void {
            var string = String.init(allocator);
            defer string.deinit();
            var writer = string.writer();
            try writer.print(
                \\{{"http_error_code":{},"http_error_name":"{s}","http_error_message":"{s}","app_error":{},"app_error_message":"
                    ++ error_message_format ++
                \\"}}
                , .{ @intFromEnum(code), @tagName(code), code.toString(), error_code, } ++ error_message_input
            );
            request.setStatus(code);
            try request.sendBody(string.items);
        }
    };
}

fn AppError(comptime err: AppErrors, comptime error_message_format: []const u8, comptime error_message_input_type: anytype) type {
    return struct {
        pub fn log_error_and_send(request: zap.SimpleRequest, input: error_message_input_type, related_error: anyerror) !void {
            const id =  error_id.fetchAdd(1, .Monotonic);
            var string = String.init(allocator);
            defer string.deinit();
            var writer = string.writer();
            if (std.debug.getSelfDebugInfo()) |debug_info| {
                const tty_config = std.io.tty.detectConfig(std.io.getStdErr());
                std.debug.writeCurrentStackTrace(writer, debug_info, tty_config, null) catch
                    |err2| std.log.err("[{d}] Failed to output the stack trace: {s}", .{id, @errorName(err2)});
            }
            else |err2| std.log.err("[{d}] Failed to get Self Debug information: {s}", .{id, @errorName(err2)});

            std.log.err(
                \\
                \\==========================================================
                \\Application error [{d}] ({s}) caught on request:
                \\# METHOD {s}
                \\# PATH   {s}
                \\# QUERY  {s}
                \\# BODY   {s}
                \\# Stack Trace: {s}
                \\==========================================================
                \\
                , .{
                    id,
                    @errorName(related_error),
                    request.method orelse "NULL",
                    request.path orelse "NULL",
                    request.query orelse "NULL",
                    request.body orelse "NULL",
                    if (string.items.len > 0) string.items else "???"
                }
            );

            try send(request, input);
        }

        pub fn send(request: zap.SimpleRequest, input: error_message_input_type) !void {
            try HttpError(.bad_request).send(request, @intFromError(err), error_message_format, input);
        }

    };
}

/// This endpoint is just to grafully close the server
const EndpointStop = HandlerCollection {
    .get = struct { fn callback(r: zap.SimpleRequest, args: []const u8) !void { _ = r; _ = args; zap.stop(); } }.callback
};

const EndpointError = HandlerCollection {
    .get = struct { fn callback(r: zap.SimpleRequest, args: []const u8) !void { _ = r; _ = args; return error.SomeError; } }.callback
};

const EndpointItems = HandlerCollection {
    .get = Items.get,
    .post = Items.post,
};

const routes = std.ComptimeStringMap(HandlerCollection, .{
    .{ "/stop", EndpointStop },
    .{ "/items", EndpointItems },
    .{ "/error", EndpointError },
});

const Items = struct {

    pub const Error = error {
        ItemIdInvalid,
        ItemNotFound,
        BodyNotProvided,
        ItemDescriptionInvalid,
    };

    fn app_error(comptime err: Error) type {
        const NoInput = @TypeOf(.{});
        return switch (err) {
            Error.ItemIdInvalid => AppError(err, "Couldn't parse item_id {s}", struct { []const u8 } ),
            Error.ItemNotFound => AppError(err, "Couldn't find item with id {}", struct { bl.ItemId } ),
            Error.BodyNotProvided => AppError(err, "Body was expected but it wasn't provided", NoInput),
            Error.ItemDescriptionInvalid => AppError(err, "Couldn't parse the item description provided! `{s}`", struct { []const u8 } ),
        };
    }

    pub fn get(request: zap.SimpleRequest, args: []const u8) anyerror!void {
        if (args.len == 0) {
            var items = std.ArrayList(bl.Item).init(allocator);
            defer items.deinit();
            
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            
            var all = try queries.items.get_all.all(arena.allocator());
            for (all) |*item| try items.append(item.normalized());

            var string = String.init(allocator);
            defer string.deinit();
            const json = try json_from(items.items, &string);    
            return try request.sendJson(json);
        }
        else {
            const item_id = std.fmt.parseUnsigned(bl.ItemId, args, 10) catch
                return try app_error(Error.ItemIdInvalid).send(request, .{ args });

            var result = try queries.items.get_by_id.one(.{ .id = item_id });
            if (result) |*item| {
                var string = String.init(allocator);
                defer string.deinit();
                const json = try json_from(item.normalized(), &string);
                return try request.sendJson(json);
            }
            else {
                return try app_error(Error.ItemNotFound).send(request, .{ item_id });
            }
        }
    }

    pub fn post(request: zap.SimpleRequest, args: []const u8) !void {
        _ = args;
        
        if (request.body == null) return try app_error(Error.BodyNotProvided).send(request, .{});
        const body = request.body.?;

        const NewItem = struct {
            title: []u8
        };

        var new_item = std.json.parseFromSlice(NewItem, allocator, body, .{}) catch |err|
            return try app_error(Error.ItemDescriptionInvalid).log_error_and_send(request, .{ body }, err);
        defer new_item.deinit();

        if (new_item.value.title.len > 127) return try app_error(Error.ItemDescriptionInvalid).send(request, .{ body });

        const out = try queries.items.insert.one_required(.{
            .title = new_item.value.title,
            .is_done = bl.False,
        });

        var string = String.init(allocator);
        defer string.deinit();
        const json = try json_from(out.normalized(), &string);
        return try request.sendJson(json);
    }
};

fn json_from(value: anytype, string: *String) ![]u8 {
    try std.json.stringify(value, .{}, string.writer());
    return string.items;
}

fn Query(comptime input_type: anytype, comptime output_type: anytype, comptime query: []const u8) type {
    return struct {
        
        const Self = @This();

        const Input = input_type;
        const Output = output_type;
        
        const Database = sqlite.Db;
        const Statement = sqlite.StatementType(.{}, query);

        db: *Database,
        statement: Statement,

        // Use the query via these...
        const exec = if (Self.has_output) @compileError("Cant call 'exec' with queries that expect output!") else if (Self.has_input) exec_with_input else exec_no_input;
        const one = if (!Self.has_output) @compileError("Cant call 'one' with queries that have no output!") else if (Self.has_input) one_with_input else one_no_input;
        const one_required = if (!Self.has_output) @compileError("Cant call 'one_required' with queries that have no output!") else if (Self.has_input) one_with_input_required else one_no_input_required;
        const all = if (!Self.has_output) @compileError("Cant call 'all' with queries that have no output!") else if (Self.has_input) all_with_input else all_no_input;
        const iterate = if (!Self.has_output) @compileError("Cant call 'all' with queries that have no output!") else if (Self.has_input) iterate_with_input else iterate_no_input;

        const has_input = @TypeOf(Input) != @TypeOf(.{});
        const has_output = @TypeOf(Output) != @TypeOf(.{});

        pub fn init(database: *sqlite.Db) !Self {
            var diagnostics = sqlite.Diagnostics {};
            var statement = database.prepareWithDiags(query, .{ .diags = &diagnostics }) catch |err| {
                std.log.err("Unable to prepare statement. Error: {}. Diagnostics message: {s}. Query:\n{s}", .{ err, diagnostics, query });
                return err;
            };
            return Self {
                .db = database,
                .statement = statement,
            };
        }

        /// Unline `init` it wont return a reusable object. This will just execute the query and return.
        pub fn execute(database: *sqlite.Db) !void {
            var diagnostics = sqlite.Diagnostics {};
            var statement = database.prepareWithDiags(query, .{ .diags = &diagnostics }) catch |err| {
                std.log.err("Unable to prepare statement. Error: {}. Diagnostics message: {s}. Query:\n{s}", .{ err, diagnostics, query });
                return err;
            };
            try statement.exec(.{}, .{});
            statement.deinit();
        }

        pub fn deinit(self: *Self) void {
            std.log.debug("closing",.{});
            self.statement.deinit();
        }

        fn exec_no_input(self: *Self) !void {
            self.statement.reset();
            try self.statement.exec(.{}, .{});
        }

        fn exec_with_input(self: *Self, input: Input) !void {
            self.statement.reset();
            try self.statement.exec(.{}, input);
        }

        fn one_no_input(self: *Self) !?Output {
            self.statement.reset();
            return try self.statement.one(Output, .{}, .{});
        }

        fn one_with_input(self: *Self, input: Input) !?Output {
            self.statement.reset();
            return try self.statement.one(Output, .{}, input);
        }

        fn one_no_input_required(self: *Self) !Output {
            self.statement.reset();
            const out = try self.statement.one(Output, .{}, .{});
            if (out == null) return error.ResultExpectedButNotFound;
            return out.?;
        }

        fn one_with_input_required(self: *Self, input: Input) !Output {
            self.statement.reset();
            const out = try self.statement.one(Output, .{}, input);
            if (out == null) return error.ResultExpectedButNotFound;
            return out.?;
        }

        fn iterate_with_input(self: *Self, input: Input) !sqlite.Iterator(Output) {
            self.statement.reset();
            return try self.statement.iterator(Output, input);
        }
        
        fn iterate_no_input(self: *Self) !sqlite.Iterator(Output) {
            self.statement.reset();
            return try self.statement.iterator(Output, .{});
        }

        fn all_with_input(self: *Self, alloc: std.mem.Allocator, input: Input) ![]Output {
            self.statement.reset();
            return try self.statement.all(Output, alloc, .{}, input);
        }

        fn all_no_input(self: *Self, alloc: std.mem.Allocator) ![]Output {
            self.statement.reset();
            return try self.statement.all(Output, alloc, .{}, .{});
        }

    };
}

const Queries = struct {
    
    users: struct {
        
        const drop_and_setup_queries = [_] type {
            Query( .{}, .{},
                \\drop table if exists user;
            ),
            Query( .{}, .{},
                \\PRAGMA encoding = "UTF-8";
            ),
            Query( .{}, .{},
                \\create table user (
                \\    internal_id integer unique primary key autoincrement not null,
                \\    unique_id text unique not null,
                \\    public_id text not null
                \\);
            ),
            Query( .{}, .{},
                \\create trigger readonly_user before update on user
                \\begin
                \\    select raise(abort, 'user is readonly!');
                \\end;
            ),
        };

        insert: Query(
            struct {
                unique_id: bl.Text128,
                public_id: bl.Text128,
            },
            struct {
                internal_id: bl.UserId,
            },
            \\insert into user (unique_id, public_id) values (?, ?) returning internal_id
        ),
        get_by_unique: Query(
            struct {
                unique_id: bl.Text128,
            },
            struct {
                internal_id: bl.UserId,
                public_id: bl.Text128,
            },
            \\select internal_id, public_id from user where unique_id = ?
        ),
        get_by_internal: Query(
            struct {
                internal_id: bl.UserId,
            },
            struct {
                unique_id: bl.Text128,
                public_id: bl.Text128,
            },
            \\select unique_id, public_id from user where internal_id = ?
        ),
        get_by_public: Query(
            struct {
                public_id: bl.Text128,
            },
            struct {
                unique_id: bl.Text128,
                internal_id: bl.UserId,
            },
            \\select unique_id, internal_id from user where public_id = ?
        ),
        all: Query(
            .{},
            struct {
                public_id: bl.Text128,
                unique_id: bl.Text128,
                internal_id: bl.UserId,
            },
            \\select * from user
        ),
        
    },

    items: struct {
        
        const drop_and_setup_queries = [_] type {
            Query( .{}, .{},
                \\drop table if exists item;
            ),
            Query( .{}, .{},
                \\PRAGMA encoding = "UTF-8";
            ),
            Query( .{}, .{},
                \\create table item (
                \\    
                \\    -- ** read-only data, definition of an item **
                \\    -- Notes (Oscar) I believe sqlite will create an alias for rowid... TODO Gotta check
                \\    id integer unique primary key autoincrement not null,
                \\    title text not null,
                \\    -- INTEGER as Unix Time, the number of seconds since 1970-01-01 00,00,00 UTC.
                \\    created_date integer not null default (strftime('%s','now')),
                \\    -- origin_user integer not null references user(id),
                \\    
                \\    -- ** dynamic data, might change as coupon status changes **
                \\    is_done integer check(
                \\        is_done >= 0 and
                \\        is_done <= 1
                \\    ) not null default 0
                \\
                \\);
            ),
        };

        get_by_id: Query(
            struct {
                id: bl.UserId,
            },
            bl.ItemInternal,
            \\select * from item where id = ?;
        ),
        get_all: Query(
            .{},
            bl.ItemInternal,
            \\select * from item;
        ),
        insert: Query(
            struct {
                title: []const u8,
                is_done: bl.Bool,
            },
            bl.ItemInternal,
            // NOTE not inserting id or created_date because that data will be set by default on insertion 
            \\insert into item (title, is_done)
            \\values (?, ?) returning *
        ),
        
    },

    pub fn init(database: *sqlite.Db) !Queries {
        
        var q: Queries = undefined;

        if (false) inline for (@TypeOf(q.users).drop_and_setup_queries) |query| try query.execute(database);
        if (false) inline for (@TypeOf(q.items).drop_and_setup_queries) |query| try query.execute(database);

        inline for (@typeInfo(@TypeOf(q.users)).Struct.fields) |field| {
            @field(q.users, field.name) = try @TypeOf(@field(q.users, field.name)).init(database);
        }


        inline for (@typeInfo(@TypeOf(q.items)).Struct.fields) |field| {
            @field(q.items, field.name) = try @TypeOf(@field(q.items, field.name)).init(database);
        }

        return q;
    }

    pub fn deinit(database: *Queries) void {

        inline for (@typeInfo(@TypeOf(database.*.users)).Struct.fields) |field| {
            @field(database.*.users, field.name).deinit();
        }

        inline for (@typeInfo(@TypeOf(database.*.items)).Struct.fields) |field| {
            @field(database.*.items, field.name).deinit();
        }

    }

};

/// `bl` stands for `bucket list`. This is a collection of types used in the application.
const bl = struct {
    const ItemId = u32;
    const UserId = u32;
    const Date = u64;
    const Text128 = [128:0]u8;
    const Bool = u1;
    const False: Bool = 0;
    const True: Bool = 1;

    const ItemInternal = struct {
        const Self = @This();
        id: bl.UserId,
        title: bl.Text128,
        created_date: bl.Date,
        is_done: bl.Bool,
        
        /// The returned `Item` is backed by the original `ItemInternal`
        fn normalized(self: *const Self) Item {
           return Item {
                .id = self.id,
                .title = std.mem.sliceTo(&self.title, 0),
                .created_date = self.created_date,
                .is_done = if (self.is_done == bl.True) true else false
            };
        }
    };

    const Item = struct {
        id: bl.UserId,
        title: []const u8,
        created_date: bl.Date,
        is_done: bool,
    };
};
