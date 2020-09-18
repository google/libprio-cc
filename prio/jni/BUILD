package(
    default_visibility = ["//prio:__subpackages__"],
)

licenses(["notice"])

proto_library(
    name = "message_proto",
    srcs = ["message.proto"],
    deps = ["//prio/proto:algorithm_parameters_proto"],
)

cc_proto_library(
    name = "message_cc_proto",
    deps = [":message_proto"],
)

java_lite_proto_library(
    name = "message_java_proto_lite",
    deps = [":message_proto"],
)

# Needs flags --crosstool_top=//external:android/crosstool --host_crosstool_top=@bazel_tools//tools/cpp:toolchain --cpu=armeabi-v7a -c opt
# Replace the --cpu with the appropriate target cpu.
cc_library(
    name = "prio_jni_cc_lib",
    srcs = ["prio_client_jni.cc"],
    deps = [
        ":message_cc_proto",
        "//prio:client",
        "//prio:encryption",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
    alwayslink = True,
)

# Needs flags --crosstool_top=//external:android/crosstool --host_crosstool_top=@bazel_tools//tools/cpp:toolchain --cpu=armeabi-v7a -c opt
# Replace the --cpu with the appropriate target cpu.
# Invoke the target libprioclient.so.stripped to produce a stripped .so.
cc_binary(
    name = "libprioclient.so",
    linkshared = True,
    deps = [
        ":prio_jni_cc_lib",
    ],
)
