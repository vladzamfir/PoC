Proof of Custody library
===

Everything seems to work, but it hasn't been really tested in practice. 

There are still edge-case security mitigations that need to be added.

Check out the in-code comments for more details


Don't mind my awful naming conventions, but:

`merkle_tree` makes a modified merkle tree, one that doesn't require an exact power of 2 number of leaves.

`stage_PoC` produces the merkle tree of data chunks, signatures of data chunks, and merkle tree of signatures

`PoC_commit` returns the merkle root of the signature tree

`produce_challenge` creates an array of 'directions' to the leafs

`PoC_response` responds to a challenge with the data merkle proof and signature merkle proof

`PoC_verify` verifies the merkle proofs against the directions, as well as the signature between the leafs
