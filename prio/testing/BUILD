package(
    default_visibility = ["//prio:__subpackages__"],
)

licenses(["notice"])

cc_library(
    name = "keys",
    testonly = 1,
    hdrs = ["keys.h"],
    deps = [
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "simplified_server",
    testonly = 1,
    srcs = ["simplified_server.cc"],
    hdrs = ["simplified_server.h"],
    deps = [
        "//prio:client",
        "//prio:constants",
        "//prio:data",
        "//prio:encryption",
        "//prio:finite_field",
        "//prio:poly",
        "//prio:serialization",
        "//prio:status_macros",
        "//prio:util",
        "//prio/prng:aes_128_ctr_seeded_prng",
        "//prio/proto:algorithm_parameters_cc_proto",
        "//prio/proto:data_share_batch_cc_proto",
        "//prio/proto:sum_part_cc_proto",
        "//prio/proto:validity_batch_cc_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "status_matchers",
    testonly = 1,
    hdrs = ["status_matchers.h"],
    deps = [
        "//prio:status_macros",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
    ],
)
