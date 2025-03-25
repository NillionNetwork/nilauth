# nilAuth
The authority service that mints root NUC tokens

# docker compose

The docker compose setup spins up dependencies to be able to test the service locally.

## nilchain

The nilchain instance can be reached at the following ports:

* JSON RPC: 26648
* gRPC: 26649
* REST: 26650

There's a single "stash" key that contains lots of funds using private key 
`97f49889fceed88a9cdddb16a161d13f6a12307c2b39163f3c3c397c3c2d2434`.
