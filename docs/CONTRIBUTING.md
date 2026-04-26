# Contributing to Mavi VPN

Thanks for checking out Mavi VPN.

The project is still early, so contributions do not have to be huge. Small fixes, docs improvements, setup feedback, bug reports, and test cases are all useful.

## Before you start

Mavi VPN is security-related software, but it is not audited yet. Please avoid presenting it as production-ready VPN software in issues, docs, or PRs.

If you find a security issue, do not open a public issue with details. Please read `SECURITY.md` first.

## Good ways to help

Useful contributions right now:

* improve setup docs
* test Docker deployment on different servers
* test the Linux client on different distros
* test the Windows client and installer flow
* improve Android build or runtime docs
* add missing tests
* clean up confusing config defaults
* improve error messages
* make the README easier to follow
* help plan an iOS client using the Rust core
* report rough edges from a real setup attempt

## Development setup

You need Rust installed.

```bash
git clone https://github.com/zerox80/mavi-vpn.git
cd mavi-vpn
cargo test -p shared
cargo test -p mavi-vpn
```

For the Linux client:

```bash
cargo test -p linux-vpn
cargo build -p linux-vpn
```

For the server Docker setup:

```bash
cd backend
cp .env.example .env
# edit .env and set a real VPN_AUTH_TOKEN
docker-compose up -d --build
```

The Android app needs Android Studio, the Android NDK, and `cargo-ndk`.

```bash
cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

Then open the `android/` folder in Android Studio.

## Pull requests

Please keep PRs focused. One fix or feature per PR is much easier to review.

Good PRs usually include:

* a short explanation of what changed
* why the change is needed
* how you tested it
* screenshots or logs if it affects the UI or setup flow

Before opening a PR, run the tests that match the area you changed.

```bash
cargo fmt
cargo test -p shared
cargo test -p mavi-vpn
```

Run more tests if you touched other crates.

## Code style

Keep the code boring where possible.

Clear names, small functions, and simple error messages are better than clever code. This project already touches networking, async Rust, system routing, Android, Windows, and Docker, so simple code helps a lot.

Please avoid large rewrites unless there is a clear reason.

## Issues

Bug reports are very welcome.

A useful bug report includes:

* your OS and version
* the Mavi VPN commit or release
* what you were trying to do
* what happened
* what you expected
* logs with secrets removed
* your Docker or client config with tokens removed

For setup problems, exact commands help a lot.

## Documentation

Docs are part of the project. If something confused you while setting it up, that is worth fixing.

Small docs PRs are welcome, especially if they make the first setup easier for someone else.

## iOS work

An iOS client is on the roadmap.

The rough idea is to reuse the Rust core where it makes sense and connect it to an iOS app through C FFI, UniFFI, or another clean bridge. The VPN side would likely use `NEPacketTunnelProvider`.

Design notes, prototypes, and research issues are welcome here.

## License

By contributing, you agree that your contribution is licensed under the MIT License, the same license used by this repository.
