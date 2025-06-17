# nilauth

nilauth keeps track of blind module subscriptions and allows minting the root NUCs that grant access to them.

# Development

Make sure your system has the following dependencies installed:
* The [Rust programming language](https://www.rust-lang.org/).
* [Docker compose](https://docs.docker.com/compose/).

---

Start dependencies by running:

```bash
docker compose up
```

Once they're up, start `nilauth` by running:

```bash
cargo run -- --config-file config.sample.yaml
```

## Tests

Test the application by running:

```bash
cargo test
```

Note that tests require `docker` to be installed and will start and stop a few containers while they're running.

## nilchain

The nilchain instance can be reached at the following ports:

* JSON RPC: 26648
* gRPC: 26649
* REST: 26650

There's a single "stash" key that contains lots of funds using private key 
`97f49889fceed88a9cdddb16a161d13f6a12307c2b39163f3c3c397c3c2d2434`.
