# libprio-cc: A Prio implementation in C++ and its JNI wrapper

This repository contains the cryptographic implementation of
[Prio](https://crypto.stanford.edu/prio/) in C++, together with a JNI wrapper.
It is intended to be interoperable with the
[libprio-rs client code implementation](https://github.com/abetterinternet/libprio-rs)
and the matching
[Rust server code implementation](https://github.com/abetterinternet/prio-server).

## About Prio

Prio is a cryptographic technology that allows clients to submit metrics to
servers in a private way, such that the servers only learn aggregated outputs.
In more detail, the client will create shares of its metrics, and send one share
to each of Server A and Server B. Server A and Server B will locally accumulate
such shares from multiple clients, and eventually engage in an interactive
cryptographic protocol that will allow Server A to learn the aggregate metric
across all clients, but nothing extra.

More details can be found in the full academic paper:
> "Prio: Private, Robust, and Scalable Computation of Aggregate Statistics"<br>
> by Henry Corrigan-Gibbs and Dan Boneh<br>
> USENIX Symposium on Networked Systems Design and Implementation<br>
> March 2017
>
> Available online at:
>    https://crypto.stanford.edu/prio/

## Building/Running Tests

This repository requires Bazel. You can install Bazel by
following the instructions for your platform on the
[Bazel website](https://docs.bazel.build/versions/master/install.html).

You must also install Android SDK and NDK, and set the environment
variables ANDROID_HOME and ANDROID_NDK_HOME to point to the paths to the
Android SDK and NDK respectively. See
[this website](https://developer.android.com/ndk/guides) for more details. These
are needed in order to support JNI compilation.

Once you have installed Bazel and set the environment variables, you can clone
this repository and run all tests that are included by navigating into the root
folder and running:

```bash
bazel test //...
```

## Building JNI shared object

To build a shared object (.so file) containing the JNI wrapped client code,
follow the instructions in prio/jni/README.md. You will find example commands
to build .so files for different platforms.

## Disclaimer

This is not an officially supported Google product.
