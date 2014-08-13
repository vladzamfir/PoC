PoC
===

Basic proof-of-custody library
Everything seems to work, but it hasn't been really tested in practice. 
There are still edge-case security mitigations that need to be added.
Check out the comments for more details


The `merkle_tree` function makes a modified merkle tree, one that doesn't require an exact power of 2 number of leaves
  for example, a merkle tree with 3 leaves would look like this:
       O
      / \
     O
    / \


The convention will be to append to bigger hash to a smaller hash
	H(H1 + H2) if H1 < H2 


Don't mind my awful naming conventions, but:
`stage_PoC` produces the merkle tree of data chunks, signatures of data chunks, and merkle tree of signatures
`PoC_commit` returns the merkle root of the signature tree
`produce_challenge` creates an array of 'directions' to the leafs
`PoC_response` responds to a challenge with the data merkle proof and signature merkle proof
`PoC_verify` verifies the merkle proofs against the directions, as well as the signature between the leafs
