# Rack Management Service Rust crate

This crate provides shared RMS protobuf wire types plus optional generated client
and server support for the NVIDIA Rack Management Service (RMS).

## Overview

The NVIDIA Rack Management Service provides functionality for managing NVIDIA
multi-node NVLINK rack-scale hardware.

## Features

- `client`: generated client APIs plus the TLS, retry, and transport stack.
- `server`: generated `rack_manager_server` service definitions.
- `serde`: serde derives for generated protobuf models.

The default feature set is `client` and `serde` to preserve existing client
consumer behavior. Consumers that only need shared types or server definitions
can use `default-features = false` and enable the smaller feature set they need.

## Testing

Run the feature matrix before publishing changes that touch generated protobuf,
client, server, or serde support:

```bash
cargo test --no-default-features
cargo test --no-default-features --features client
cargo test --no-default-features --features server
cargo test --all-features
```

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for
details.
