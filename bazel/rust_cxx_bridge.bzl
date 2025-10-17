# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Rust cxxbridge rules.

Copied (with some minor changes) from the cxx bridge rules defined by the Skia Team on
https://source.chromium.org/chromium/chromium/src/+/main:third_party/skia/bazel/rust_cxx_bridge.bzl.
"""

load("@rules_cc//cc:defs.bzl", "cc_library")

def rust_cxx_bridge(name, src, deps = [], visibility = None, crate_features = []):
    """Defines the C++ side of a cxx bridge between C++ and Rust.

    Through this rule, you supply the functions and types declared in `extern "C++"` blocks.
    The rule produces a library that can be used to call `extern "Rust"` functions.

    For a bridge defined in `foo.rs` (which also defines its Rust functions):

        # Provides implementation of Rust functions, and interface to call C++ functions from Rust.
        rust_library(
          name = "foo_rust"
          srcs = ["foo.rs"],
          deps = ["@crates//:cxx"],
        )

        # Provides interface to call Rust functions from C++.
        rust_cxx_bridge(
          name = "foo_cpp",
          src = "foo.rs",
          deps = [":foo_cpp_impl"]
        )

        # Provides implementation of C++ functions. ("the impl library").
        cc_library(
          name = "foo_cpp_impl",
          hdrs = ["foo.h"],
          srcs = ["foo.c"],
          deps = [":foo_cpp/include"],
        )

    Code using the bridge (from Rust or C++) must depend on *both* `:foo_rust` and `:foo_cpp`.
    C++ code using the bridge should `#include "foo.rs.h"`.

    Args:
      name: Names the C++ library exposing the bridge interface.
            "name/include" will also be generated, providing headers used by the impl library.
      src: Rust source file that contains CXX bridge definitions.
      deps: This includes the impl library and any other dependencies used in the bridge.
      visibility: Visibility of the bridge target.
      crate_features: Feature flags to enable for codegen. See https://doc.rust-lang.org/cargo/reference/features.html.
    """
    out_h = "%s.h" % src
    out_cc = "%s.cc" % src

    run_cxxbridge_cmd(
        name = "%s/generated" % name,
        srcs = [src],
        outs = [out_h, out_cc],
        args = [
            "$(location %s)" % src,
            "-o",
            "$(location %s)" % out_h,
            "-o",
            "$(location %s)" % out_cc,
        ],
        crate_features = crate_features,
    )

    # This library provides the generated header only.
    #
    # The impl library will depend on this.
    # This allows it to see shared data types, and call `extern "Rust"` functions.
    #
    # Should not be exposed publicly: it does not contain the generated thunk code we need to link.
    # This library exists to avoid a circular dependency between the impl and bridge cc_librarys.
    cc_library(
        name = "%s/include" % name,
        # Textual: this header necessarily #includes hdrs from the impl library.
        # We can't depend on that here, because it depends on this!
        textual_hdrs = [out_h],
        visibility = ["//visibility:private"],
    )

    kwargs = {}
    if visibility != None:
        kwargs["visibility"] = visibility

    # The public bridge library.
    #
    # This exposes the bridge header, and links in the generated thunk code and the impl library.
    cc_library(
        name = name,
        srcs = [out_cc],
        hdrs = [out_h],
        deps = deps + ["%s/include" % name],
        # Allow "backwards" dependencies from the impl library onto the generated thunk code.
        # (Used e.g. if it calls `extern "Rust"` functions).
        linkopts = ["-Wl,--warn-backrefs-exclude=blaze-out/*/%s/_objs/%s/*" % (native.package_name(), name)],
        **kwargs
    )

def _run_cxxbridge_cmd_impl(ctx):
    args = [
        ctx.expand_location(a)
        for a in ctx.attr.args
    ]
    for f in ctx.attr.crate_features:
        args.append("--cfg")
        args.append("feature=\"%s\"" % f)

    # https://bazel.build/rules/lib/builtins/actions.html#run
    ctx.actions.run(
        outputs = ctx.outputs.outs,
        inputs = ctx.files.srcs,
        executable = ctx.executable._cxxbridge,
        arguments = args,
        mnemonic = "RunCxxbridgeCmd",
    )

    return DefaultInfo(
        files = depset(ctx.outputs.outs),
        runfiles = ctx.runfiles(ctx.outputs.outs),
    )

run_cxxbridge_cmd = rule(
    implementation = _run_cxxbridge_cmd_impl,
    attrs = {
        "srcs": attr.label_list(
            doc = "Source dependencies for this rule",
            allow_files = True,
            mandatory = True,
        ),
        "outs": attr.output_list(
            doc = "C++ output files generated by cxxbridge_cmd.",
            mandatory = True,
        ),
        "args": attr.string_list(
            doc = "Arguments to `cxxbridge_cmd`.",
            mandatory = True,
        ),
        "crate_features": attr.string_list(
            doc = "Optional list of cargo features that CXX bridge definitions may depend on.",
        ),
        "_cxxbridge": attr.label(
            default = Label("@cxx.rs//:codegen"),
            allow_single_file = True,
            executable = True,
            cfg = "exec",
        ),
    },
)
