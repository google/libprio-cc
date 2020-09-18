package(
    default_visibility = ["//prio:__subpackages__"],
)

licenses(["notice"])

cc_library(
    name = "seeded_prng",
    hdrs = ["seeded_prng.h"],
    deps = [
        "//prio:constants",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "aes_128_ctr_seeded_prng",
    srcs = ["aes_128_ctr_seeded_prng.cc"],
    hdrs = ["aes_128_ctr_seeded_prng.h"],
    deps = [
        ":seeded_prng",
        "//prio:constants",
        "//prio:status_macros",
        "//prio:util",
        "@boringssl//:ssl",
        "@com_google_absl//absl/base:config",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "aes_128_ctr_seeded_prng_test",
    srcs = ["aes_128_ctr_seeded_prng_test.cc"],
    deps = [
        ":aes_128_ctr_seeded_prng",
        "//prio:constants",
        "//prio/testing:status_matchers",
        "@boringssl//:ssl",
        "@com_github_google_googletest//:gtest_main",
    ],
)
