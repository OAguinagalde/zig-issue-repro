# About the issue

So I basically updated `zig` from version `0.11.0-dev.4282+0f21d3d4d` to `0.12.0-dev.157+8e96be008`.

I tried to build with this new version as I always do (with `zig build -Dtarget=x86_64-linux-musl` since I use `zap` and it doesn't support windows) and it complained about line 50 in `build.zig`. Aparently paths are provided via `std.build.LazyPath` now, so I change it like this:
```diff
- sqlite.addCSourceFile("./deps/zig-sqlite/c/sqlite3.c", &[_][]const u8{"-std=c99"});
+ sqlite.addCSourceFile(.{ .{ "./deps/zig-sqlite/c/sqlite3.c" },  &[_][]const u8{"-std=c99"} });
```

Now here is the problem: It worked! building after only that change did the usual thing, where zig tells me what its working on... and in less than a second, it finishes. No errors or anything, just like usual succesful zig builds. BUT, there is not `zig-out`.

Well it turns out that my `build.zig` still has issues, also related to `LazyPath`, but such as line 53 `exe.addIncludePath("./deps/zig-sqlite/c");`. Furthermore, the version of `zap` I'm using at this point also has the same issue about not using `LazyPath`. I did later on fix my issues and update `zap` to the newest release and everything works fine. It builds and `zig-out` is created with the binaries and everything is great.

So the issue showcased in this issue is that `zig` should have told me that `zap`'s `build.zig` had issues and that my `build.zig` file also had issues, but instead it was just silently terminating, so I couldn't really tell that it failed other than by the fact that `zig-out` wasn't there.

To repro, just run `zig build -Dtarget=x86_64-linux-musl` in windows with `zig` version `0.12.0-dev.157+8e96be008`. It should terminate without errors even though there are errors both in `build.zig` and in `zap`'s `build.zig`.