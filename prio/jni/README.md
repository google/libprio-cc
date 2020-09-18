## How to build the .so files

Note that you must first install Android SDK and NDK, and set the environment
variables ANDROID_HOME and ANDROID_NDK_HOME to point to the paths to the
Android SDK and NDK respectively. See
[this website](https://developer.android.com/ndk/guides) for more details.

```
bazel build //prio/jni:libprioclient.so.stripped --crosstool_top=//external:android/crosstool --host_crosstool_top=@bazel_tools//tools/cpp:toolchain --cpu=x86_64 -c opt
bazel build //prio/jni:libprioclient.so.stripped --crosstool_top=//external:android/crosstool --host_crosstool_top=@bazel_tools//tools/cpp:toolchain --cpu=x86 -c opt
bazel build //prio/jni:libprioclient.so.stripped --crosstool_top=//external:android/crosstool --host_crosstool_top=@bazel_tools//tools/cpp:toolchain --cpu=arm64-v8a -c opt
bazel build //prio/jni:libprioclient.so.stripped --crosstool_top=//external:android/crosstool --host_crosstool_top=@bazel_tools//tools/cpp:toolchain --cpu=armeabi-v7a -c opt
```
