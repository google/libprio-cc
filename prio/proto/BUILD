load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(
    default_visibility = [
        "//prio:visibility",
    ],
)

licenses(["notice"])

proto_library(
    name = "algorithm_parameters_proto",
    srcs = ["algorithm_parameters.proto"],
)

java_lite_proto_library(
    name = "algorithm_parameters_java_proto_lite",
    deps = [":algorithm_parameters_proto"],
)

java_proto_library(
    name = "algorithm_parameters_java_proto",
    deps = [":algorithm_parameters_proto"],
)

cc_proto_library(
    name = "algorithm_parameters_cc_proto",
    deps = [":algorithm_parameters_proto"],
)

proto_library(
    name = "data_share_batch_proto",
    srcs = ["data_share_batch.proto"],
    deps = [":algorithm_parameters_proto"],
)

java_proto_library(
    name = "data_share_batch_java_proto",
    deps = [":data_share_batch_proto"],
)

cc_proto_library(
    name = "data_share_batch_cc_proto",
    deps = [":data_share_batch_proto"],
)

proto_library(
    name = "validity_batch_proto",
    srcs = ["validity_batch.proto"],
    deps = [":algorithm_parameters_proto"],
)

java_proto_library(
    name = "validity_batch_java_proto",
    deps = [":validity_batch_proto"],
)

cc_proto_library(
    name = "validity_batch_cc_proto",
    deps = [":validity_batch_proto"],
)

proto_library(
    name = "sum_part_proto",
    srcs = ["sum_part.proto"],
    deps = [":algorithm_parameters_proto"],
)

java_proto_library(
    name = "sum_part_java_proto",
    deps = [":sum_part_proto"],
)

cc_proto_library(
    name = "sum_part_cc_proto",
    deps = [":sum_part_proto"],
)
