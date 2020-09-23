package(
    default_visibility = ["//prio:__subpackages__"],
)

licenses(["notice"])

cc_test(
    name = "aggregation_test",
    size = "medium",
    srcs = ["aggregation_test.cc"],
    deps = [
        ":client",
        ":constants",
        ":finite_field",
        "//prio/prng:aes_128_ctr_seeded_prng",
        "//prio/proto:data_share_batch_cc_proto",
        "//prio/testing:keys",
        "//prio/testing:simplified_server",
        "//prio/testing:status_matchers",
        "@com_github_google_glog//:glog",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "client",
    srcs = ["client.cc"],
    hdrs = ["client.h"],
    deps = [
        ":constants",
        ":encryption",
        ":finite_field",
        ":poly",
        ":randomized_response",
        ":serialization",
        ":status_macros",
        ":util",
        "//prio/prng:aes_128_ctr_seeded_prng",
        "//prio/proto:algorithm_parameters_cc_proto",
        "@boringssl//:ssl",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_test(
    name = "client_test",
    size = "small",
    srcs = ["client_test.cc"],
    deps = [
        ":client",
        ":encryption",
        ":serialization",
        "//prio/prng:aes_128_ctr_seeded_prng",
        "//prio/proto:algorithm_parameters_cc_proto",
        "//prio/testing:keys",
        "//prio/testing:status_matchers",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "constants",
    hdrs = [
        "constants.h",
        "types.h",
    ],
)

cc_library(
    name = "data",
    srcs = ["data.cc"],
    hdrs = ["data.h"],
    deps = [
        ":constants",
        ":finite_field",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_library(
    name = "encryption",
    srcs = ["encryption.cc"],
    hdrs = ["encryption.h"],
    deps = [
        ":status_macros",
        ":util",
        "@boringssl//:ssl",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "encryption_test",
    srcs = ["encryption_test.cc"],
    deps = [
        ":encryption",
        "//prio/testing:keys",
        "//prio/testing:status_matchers",
        "@boringssl//:ssl",
        "@com_github_google_glog//:glog",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "finite_field",
    srcs = ["finite_field.cc"],
    hdrs = ["finite_field.h"],
    deps = [
        ":constants",
        ":util",
        "@boringssl//:ssl",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_test(
    name = "finite_field_test",
    size = "small",
    srcs = ["finite_field_test.cc"],
    deps = [
        ":constants",
        ":finite_field",
        "//prio/testing:status_matchers",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "poly",
    srcs = ["poly.cc"],
    hdrs = ["poly.h"],
    deps = [
        ":constants",
        ":finite_field",
        ":status_macros",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
    ],
)

cc_test(
    name = "poly_test",
    size = "small",
    srcs = ["poly_test.cc"],
    deps = [
        ":constants",
        ":finite_field",
        ":poly",
        "//prio/testing:status_matchers",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "randomized_response",
    srcs = ["randomized_response.cc"],
    hdrs = ["randomized_response.h"],
    deps = [
        ":constants",
        ":finite_field",
        ":status_macros",
        ":util",
        "//prio/proto:algorithm_parameters_cc_proto",
        "@boringssl//:ssl",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/types:span",
    ],
)

cc_test(
    name = "randomized_response_test",
    size = "small",
    srcs = ["randomized_response_test.cc"],
    deps = [
        ":constants",
        ":finite_field",
        ":randomized_response",
        "//prio/proto:algorithm_parameters_cc_proto",
        "//prio/testing:status_matchers",
        "@com_github_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "serialization",
    srcs = ["serialization.cc"],
    hdrs = ["serialization.h"],
    deps = [
        ":constants",
        ":data",
        ":finite_field",
        ":status_macros",
        ":util",
        "//prio/prng:aes_128_ctr_seeded_prng",
        "//prio/prng:seeded_prng",
        "//prio/proto:algorithm_parameters_cc_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "serialization_test",
    size = "small",
    srcs = ["serialization_test.cc"],
    deps = [
        ":constants",
        ":finite_field",
        ":serialization",
        ":util",
        "//prio/prng:aes_128_ctr_seeded_prng",
        "//prio/testing:status_matchers",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "status_macros",
    hdrs = ["status_macros.h"],
)

cc_library(
    name = "util",
    hdrs = ["util.h"],
    deps = [
        ":constants",
        ":status_macros",
        "//prio/proto:algorithm_parameters_cc_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_test(
    name = "util_test",
    size = "small",
    srcs = ["util_test.cc"],
    deps = [
        ":constants",
        ":util",
        "//prio/testing:status_matchers",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/status",
    ],
)
