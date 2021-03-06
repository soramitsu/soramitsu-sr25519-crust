[![Build Status](https://travis-ci.org/Warchant/sr25519-crust.svg?branch=master)](https://travis-ci.org/Warchant/sr25519-crust)
[![Gitter](https://badges.gitter.im/sr25519-crust/community.svg)](https://gitter.im/sr25519-crust/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

# Schnorrkel-crust

C bindings over RUST implementations of [sr25519 (schnorrkel)](https://github.com/w3f/schnorrkel)  and [ed25519](https://github.com/dalek-cryptography/ed25519-dalek).

## Build

1. Install rust compiler (nightly), `cargo`:
    ```bash
    curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly
    source $HOME/.cargo/env
    rustup install nightly
    rustup default nightly
    ```
2. `mkdir build && cd build`
3. Options;
   - `-DTESTING=[ON|OFF]` - enable or disable build of tests.
   - `-DCMAKE_BUILD_TYPE=[Release|Debug]` - select build type.
   - `-DBUILD_SHARED_LIBS=[TRUE|FALSE]` - build shared/static library. 
   
   ```bash
   cmake .. -DCMAKE_BUILD_TYPE=Release
   ```
4. Build and install library: 
   ```
   sudo make install
   ```

## Docs

Header with comments will be generated in `build/include/schnorrkel/schnorrkel.h`.

## Examples
### Sr25519
- [Keypair derivation](test/sr25519/derive.cpp)
- [Sign/Verify](test/sr25519/ds.cpp)
- [Keypair from seed](test/sr25519/keypair_from_seed.cpp)
- [Verifiable random function](test/sr25519/vrf.cpp)

### Ed25519
- [Keypair from seed](test/ed25519/test.cpp)
- [Sign/Verify](test/ed25519/test.cpp)
