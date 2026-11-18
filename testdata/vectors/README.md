# Test vectors

These are copies of the Tieroute spec's test vectors: known inputs and the exact bytes they must produce, for encoding, signatures, identity chains, and recovery codes. rerouted's tests check its output against them.

The files here are for wire version 1. The files in `v2/` are for wire version 2: rerouted's tests check the parts it implements so far: composite signatures, the signed envelope, recovery keys, message keys, and key package bindings.

Don't edit them here. When the spec's vectors change, copy the new files in, and run the tests.
