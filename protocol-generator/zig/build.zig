//! Build for entity-core-protocol-zig (S2 codec). std-only, no fetched deps.
//!   zig build            -> build the static codec library
//!   zig build test       -> run all in-file unit tests (std.testing.allocator)
//!   zig build conformance -- <fixture.cbor>  -> run the wire-conformance harness
//! Conformance defaults to ../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Default Debug (bounds + overflow checks on) per profile
    // [idiom].no_undefined_behavior; `-Doptimize=ReleaseSafe` keeps the checks,
    // `ReleaseFast` only after green. `-Doptimize` stays available.
    const optimize = b.standardOptimizeOption(.{});

    const root = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Static library artifact (lib_name = entitycore_codec).
    const lib = b.addLibrary(.{
        .name = "entitycore_codec",
        .root_module = root,
        .linkage = .static,
    });
    b.installArtifact(lib);

    // Unit tests (in-file `test {}` blocks across every module).
    const tests = b.addTest(.{ .root_module = root });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests (leak-checked)");
    test_step.dependOn(&run_tests.step);

    // Conformance harness executable.
    const conf_mod = b.createModule(.{
        .root_source_file = b.path("src/conformance.zig"),
        .target = target,
        .optimize = optimize,
    });
    const conf = b.addExecutable(.{ .name = "wire-conformance", .root_module = conf_mod });
    b.installArtifact(conf);
    const run_conf = b.addRunArtifact(conf);
    if (b.args) |args| run_conf.addArgs(args);
    const conf_step = b.step("conformance", "Run the ECF wire-conformance harness");
    conf_step.dependOn(&run_conf.step);

    // S3 smoke runner: two Zig peers over loopback TCP (the phase exit gate).
    const smoke_mod = b.createModule(.{
        .root_source_file = b.path("src/smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    const smoke = b.addExecutable(.{ .name = "smoke", .root_module = smoke_mod });
    b.installArtifact(smoke);
    const run_smoke = b.addRunArtifact(smoke);
    const smoke_step = b.step("smoke", "Run the S3 two-peer loopback smoke");
    smoke_step.dependOn(&run_smoke.step);

    // S4-ready standalone peer host: boots one listener; a Go oracle drives it.
    const host_mod = b.createModule(.{
        .root_source_file = b.path("src/host.zig"),
        .target = target,
        .optimize = optimize,
    });
    const host = b.addExecutable(.{ .name = "host", .root_module = host_mod });
    b.installArtifact(host);
}
