
<A name="toc1-3" title="Curve - authentication and encryption library" />
# Curve - authentication and encryption library

Curve implements the [CurveZMQ](http://rfc.zeromq.org/spec:26) elliptic curve security mechanism, for use in ZeroMQ applications. This library is primarily a reference implementation for the CurveZMQ specification but may also be used for end-to-end security.

The ZeroMQ core library has its own implementation of CurveZMQ over TCP, since July 2013. The Curve library is intended:

* To facilitate CurveZMQ implementations in other languages by providing a reference implementation.
* To provide security for older versions of ZeroMQ.
* To provide end-to-end security over untrusted intermediaries, for instance between two chat clients connected over a public ZeroMQ-based chat server.
* To provide security over other transports that fit the one-to-one model (it will not work over multicast).

CurveZMQ creates encrypted sessions ("connections") between two peers using short term keys that it securely exchanges using long term keys. When the session is over, both sides discard their short term keys, rendering the encrypted data unreadable, even if the long term keys are captured. It is not designed for long term encryption of data. 

The design of CurveZMQ stays as close as possible to the security handshake of [CurveCP](http://curvecp.org), a protocol designed to run over UDP.

CurveZMQ is adapted here to be compatible with MPC for long-term keys. This avoids having to store these highly sensitive keys in configuration files, by keeping the long-term private keys securely into multiple MPC nodes. Only the key ID is returned and stored in the files.

<A name="toc2-19" title="Ownership and License" />
## Ownership and License

Copyright (c) the Contributors as noted in the AUTHORS file. This file is part of the Curve authentication and encryption library. This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

<A name="toc2-24" title="Contributing" />
## Contributing

This project uses the [C4.1 (Collective Code Construction Contract)](http://rfc.zeromq.org/spec:22) process for contributions.

This project uses the [CLASS (C Language Style for Scalabilty)](http://rfc.zeromq.org/spec:21) guide for code style.

To report an issue, use the [Curve issue tracker](https://github.com/zeromq/libcurve/issues) at github.com.

<A name="toc2-33" title="Dependencies" />
## Dependencies

This project needs these projects:

* libsodium - git://github.com/jedisct1/libsodium.git
* libzmq - git://github.com/zeromq/libzmq.git
* libczmq - git://github.com/zeromq/czmq.git
* ulfius - git://github.com:babelouest/ulfius.git

<A name="toc2-42" title="Building and Installing" />
## Building and Installing

This project uses autotools for packaging. To build from git you must first build ulfius, libsodium, libzmq, and libczmq. 
Notice that czmq is required to be version 3.x to be compatible with libcurve [[source]](https://github.com/zeromq/libcurve/issues/38). All example commands are for Linux:

    #   ulfius
    sudo apt install -y libmicrohttpd-dev libjansson-dev libcurl4-gnutls-dev libgnutls28-dev libgcrypt20-dev libsystemd-dev
    wget https://github.com/babelouest/ulfius/releases/download/v2.7.6/ulfius-dev-full_2.7.6_ubuntu_focal_x86_64.tar.gz
    tar xf ulfius-dev-full_2.7.6_ubuntu_focal_x86_64.tar.gz
    sudo dpkg -i --force-overwrite liborcania-dev_2.2.1_ubuntu_focal_x86_64.deb
    sudo dpkg -i --force-overwrite libyder-dev_1.4.14_ubuntu_focal_x86_64.deb
    sudo dpkg -i libulfius-dev_2.7.6_ubuntu_focal_x86_64.deb
   
    #   libsodium
    wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz
    tar xf libsodium-1.0.18-stable.tar.gz
    cd libsodium-stable
    ./configure
    make && make check
    sudo make install
    sudo ldconfig
    cd ..

    #   libzmq
    git clone git://github.com/zeromq/libzmq.git
    cd libzmq
    ./autogen.sh
    ./configure && make check
    sudo make install
    sudo ldconfig
    cd ..

    #   CZMQ
    wget https://github.com/zeromq/czmq/releases/download/v3.0.2/czmq-3.0.2.tar.gz
    tar xf czmq-3.0.2.tar.gz
    cd czmq-3.0.2
    ./configure 
    make -j 4 CPPFLAGS='-Wno-error=deprecated-declarations'
    make check 
    sudo make install
    ldconfig
    cd ..

    git clone git://github.com/duokey/libcurve.git
    cd libcurve
    git checkout dev-mpc
    sh autogen.sh
    ./autogen.sh
    ./configure && make check
    sudo make install
    sudo ldconfig
    cd ..

You will need the libtool and autotools packages. On FreeBSD, you may need to specify the default directories for configure:

    ./configure --with-libzmq=/usr/local

<A name="toc2-87" title="Linking with an Application" />
## Linking with an Application

Include `curve.h` in your application and link with libcurve. Here is a typical gcc link command:

    gcc -lcurve -lsodium -lzmq -lczmq myapp.c -o myapp

To run `curve_mpc_handshake.c`, i.e., CurveZMQ handshake with MPC:

    gcc -L/usr/local/lib -o curve_mpc_handshake curve_mpc_handshake.c mpc/key_manager.c mpc/helpers.c mpc/MPC_cert.c -lcurve -lsodium -lzmq -lczmq -lulfius ${CFLAGS} ${LDFLAGS}

Don't forget to define your bearer token, json credentials, and vault id.

<A name="toc2-94" title="Documentation" />
## Documentation

All documentation is provided in the doc/ subdirectory.

### Version
Tested on Ubuntu version 20.04.3 LTS in WSL1.
