load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# rules_cc defines rules for generating C++ code from Protocol Buffers.
http_archive(
    name = "rules_cc",
    sha256 = "35f2fb4ea0b3e61ad64a369de284e4fbbdcdba71836a5555abb5e194cf119509",
    strip_prefix = "rules_cc-624b5d59dfb45672d4239422fa1e3de1822ee110",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_cc/archive/624b5d59dfb45672d4239422fa1e3de1822ee110.tar.gz",
        "https://github.com/bazelbuild/rules_cc/archive/624b5d59dfb45672d4239422fa1e3de1822ee110.tar.gz",
    ],
)

load("@rules_cc//cc:repositories.bzl", "rules_cc_dependencies")
rules_cc_dependencies()

# rules_proto defines abstract rules for building Protocol Buffers.
# https://github.com/bazelbuild/rules_proto
http_archive(
    name = "rules_proto",
    strip_prefix = "rules_proto-40298556293ae502c66579620a7ce867d5f57311",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_proto/archive/40298556293ae502c66579620a7ce867d5f57311.tar.gz",
        "https://github.com/bazelbuild/rules_proto/archive/40298556293ae502c66579620a7ce867d5f57311.tar.gz",
    ],
)
load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")
rules_proto_dependencies()
rules_proto_toolchains()

# Install gtest.
http_archive(
  name = "com_github_google_googletest",
  urls = ["https://github.com/google/googletest/archive/a4ab0abb93620ce26efad9de9296b73b16e88588.zip"],
  strip_prefix = "googletest-a4ab0abb93620ce26efad9de9296b73b16e88588",
)

# abseil-cpp
http_archive(
  name = "com_google_absl",
  urls = ["https://github.com/abseil/abseil-cpp/archive/6af91b35109cb35ae53cfe908e31a0c31c4a47f3.zip"],
  strip_prefix = "abseil-cpp-6af91b35109cb35ae53cfe908e31a0c31c4a47f3",
)

# BoringSSL
git_repository(
    name = "boringssl",
    commit = "3d440a3493fda30b1aa98a1aea0207dda271b4e6",  # https://boringssl.googlesource.com/boringssl/+/refs/heads/master-with-bazel
    remote = "https://boringssl.googlesource.com/boringssl",
)

# Logging
http_archive(
    name = "com_github_google_glog",
    urls = ["https://github.com/google/glog/archive/0a2e5931bd5ff22fd3bf8999eb8ce776f159cda6.zip"],
    strip_prefix = "glog-0a2e5931bd5ff22fd3bf8999eb8ce776f159cda6",
)

# gflags, needed for glog
http_archive(
    name = "com_github_gflags_gflags",
    urls = ["https://github.com/gflags/gflags/archive/v2.2.2.tar.gz"],
    sha256 = "34af2f15cf7367513b352bdcd2493ab14ce43692d2dcd9dfc499492966c64dcf",
    strip_prefix = "gflags-2.2.2",
)
android_sdk_repository(
name = "androidsdk",
# "path" omitted. "ANDROID_HOME" environment variable must be set
)

android_ndk_repository(
    name = "androidndk",
    # "path" omitted. "ANDROID_NDK_HOME" environment variable must be set.
)