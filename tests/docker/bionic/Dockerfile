# Dockerfile
#
# Purpose
# -------
# Defines a Docker container suitable to build and run all tests (all.sh),
# except for those that use a proprietary toolchain.

# Copyright (C) 2006-2019, Arm Limited (or its affiliates), All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file is part of Mbed TLS (https://tls.mbed.org)

FROM ubuntu:bionic

ARG MAKEFLAGS_PARALLEL=""

ENV DEBIAN_FRONTEND noninteractive

RUN apt update \
    && apt -y install software-properties-common \
    && rm -rf /var/lib/apt/lists

RUN add-apt-repository -y ppa:team-gcc-arm-embedded/ppa

RUN apt-get update \
    && apt-get -y install \
    build-essential \
    clang \
    cmake \
    doxygen \
    gcc-arm-none-eabi \
    gcc-mingw-w64-i686 \
    gcc-multilib \
    g++-multilib \
    gdb \
    git \
    graphviz \
    python \
    python3-pip \
    python3 \
    pylint3 \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
    mbed-host-tests \
    mock
