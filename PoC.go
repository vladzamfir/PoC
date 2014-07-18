package main

import (
        "fmt"
	"bytes"
        "encoding/hex"
        "github.com/obscuren/sha3"
	"github.com/obscuren/secp256k1-go"
    	"io/ioutil"
)

const file = "helloworld.txt"

func check(e error) {
    if e != nil {
        panic(e)
    }
}


//Simply takes the data at location 'file' and returns a bytearray of it
func read_data(file string) []byte {
	data, err := ioutil.ReadFile(file)
	check(err)
	return data
}

//makes the size of the data a multiple of chunk_size (in bytes) by padding it on the right with zeros
func pad_data(data []byte, chunk_size int) []byte  {
	data_size := len(data)
	remainder := data_size % chunk_size
	if remainder == 0 { 
		return data 
	} else {
		padding := chunk_size - remainder
		padded := make([]byte, data_size + padding)
		copy(padded[0:data_size], data)	
		return padded
	}
}

//This function returns a slice of slices of chunk_sized slices of 'data'
func slice_data(data []byte, chunk_size int) [][]byte {
	data_size := len(data)
	num_chunks := data_size/chunk_size
	data_slice := make([][]byte, num_chunks)
	for i:= range data_slice {
		data_slice[i] = make([]byte, chunk_size)
		copy(data_slice[i][0:chunk_size], data[i*chunk_size:(i+1)*chunk_size])
	}
	return data_slice
}


func Sha3(data []byte) []byte {
        d := sha3.NewKeccak256()
        d.Write(data)
        return d.Sum(nil)
}

type Node struct {
	value []byte
	child []*Node
	parent []*Node //not in use yet, but will be used for producing proofs
}

func make_orphan_nodes (data_chunks [][]byte) []*Node {
	num_chunks := len(data_chunks)
        orphans := make([]*Node, num_chunks)
        for i := 0; i < num_chunks; i++ {
                orphans[i] = new(Node)
                (*orphans[i]).value = append((*orphans[i]).value,data_chunks[i]...)
        }
	return orphans
}

/* this makes a modified merkle tree, one that doesn't require an exact power of 2 number of leaves
  for example, a merkle tree with 3 leaves would look like this:
       O
      / \
     O
    / \
*/

func merkle_tree(orphans_copy []*Node) *Node {
        num_orphans := len(orphans_copy)
	
	orphans := make([]*Node, num_orphans)
	copy(orphans, orphans_copy)
	
	//orphans are nodes without parents
	// in a merkle tree, there is exactly one orphan, and every parent has two children
	for num_orphans > 1 {
		for i := 0; i < num_orphans/2; i++ { //taking pairs of orphans and giving them parents
			new_parent := new(Node) 

			H1 := (*orphans[2*i]).value
			H2 := (*orphans[2*i + 1]).value


			var temp []byte //this'll hold the thing to be hashed
			if bytes.Compare(H1, H2) == -1 {
				temp = append(temp, H1...)
				temp = append(temp, H2...)
			} else {
                                temp = append(temp, H2...)
                                temp = append(temp, H1...)
			}
			temp = Sha3(temp)

			new_parent.value = append(new_parent.value, temp...)
			new_parent.child = append(new_parent.child, orphans[2*i:2*i + 2]...)
			(*orphans[2*i]).parent = append((*orphans[2*i]).parent, new_parent)
			(*orphans[2*i + 1]).parent = append((*orphans[2*i + 1]).parent, new_parent)
			orphans[i] = new_parent
		}
		if num_orphans % 2 == 1 {
			orphans[num_orphans/2] = orphans[num_orphans - 1]
		}
		num_orphans = num_orphans/2 + num_orphans % 2
	}
		
	return orphans[0]
}

func Bytes2Hex(d []byte) string {
        return hex.EncodeToString(d)
}

func Hex2Bytes(str string) []byte {
        h, _ := hex.DecodeString(str) //not handling errors
        return h
}


//This recursively reports the decendants of a node
//So far I've only used it to audit merkle trees
func report_decendants(parent *Node, call_num *int) {
	if *call_num == 0 {
		fmt.Printf("Root: \n")
		fmt.Println(Bytes2Hex((*parent).value))
	}

	//fmt.Println(len((*parent).child))
	for i := range (*parent).child {
		fmt.Printf("Call number: %d\n", *call_num)
		fmt.Println(Bytes2Hex((*(*parent).child[i]).value))
		*call_num += 1
		report_decendants((*parent).child[i], call_num)

	}
}



func Signature(hash []byte, key []byte) []byte {
	sig, _ := secp256k1.Sign(hash, key)
	return sig
}

func sign_chunks(data_chunks [][]byte, key []byte) [][]byte {
	num_slices := len(data_chunks)
	sigs := make([][]byte, num_slices)
	for i := range data_chunks {
		sigs[i] = *new([]byte)
		sigs[i] = append(sigs[i], Signature(data_chunks[i], key)...)
	}
	return sigs
	
}

//These next couple of function are very specialized for binary trees 
func find_sibling (brother *Node) *Node{
	parent := (*brother).parent[0]
	if (*parent).child[0] == brother {
		return (*parent).child[1]
	} else {
		return (*parent).child[0]
	}
}


func produce_merkle_proof(leaves []*Node, challenge int) [][]byte {
	proof := new([][]byte)

	current_node := leaves[challenge]
	*proof = append(*proof, (*current_node).value)
	for len((*current_node).parent) > 0 {
		H := (*find_sibling(current_node)).value
		*proof = append(*proof, H)		
		current_node = (*current_node).parent[0]
	}
	return *proof
}


func check_merkle_proof(proof [][]byte, root Node) bool {
	var H []byte
	H = append(H, proof[0]...)
	
	for i := 1; i < len(proof); i++ {
		if bytes.Compare(H, proof[i]) == -1 {
			H = append(H, proof[i]...)
		} else { 
			H = append(proof[i], H...)
		}
		H = Sha3(H)
	}
	return bytes.Compare(H, root.value) == 0	
}


//not in use, yet
func ECRecover(hash []byte, sig []byte) ([]byte, error) {
	pubkey, err := secp256k1.RecoverPubkey(hash, sig)
	if err != nil {
		return nil, err
	}
	return pubkey, nil
}

func main() {
	//Read data
	data := read_data("helloworld.txt")
	//fmt.Printf("Raw data:\n")
	//fmt.Println(data)

	//this is the largest chunk size that can be signed by secp256k1.Sign 
	//bigger data chunks would have to be hashed before signed, which opens 
	//the attack vector of sharing the hashes rather than the file, to collude
	// to produce a proof-of-custody
	chunk_size := 32

	//Pad it so it's a multiple of the chunk_size
	padded := pad_data(data, chunk_size)
	//fmt.Printf("Padded data: \n")
	//fmt.Println(padded)

	//Slice the (padded) data into chunks
	chunks := slice_data(padded, chunk_size)
	//fmt.Printf("Sliced data, \n")
	//fmt.Println(chunks)

	fmt.Printf("Note that we have %d data chunks/signatures as the leaves of the merkle trees\n\n", len(chunks))

	orphans := make_orphan_nodes(chunks)

	//Calculate the merkle root of the file
	file_root := merkle_tree(orphans)
	fmt.Printf("Merkle root of file: \n")
	fmt.Println(Bytes2Hex((*file_root).value))

	//This can be used to check the structure of the tree
	//var calls int = 0
	//report_decendants(file_root, &calls)

	challenge := 0
	proof := produce_merkle_proof(orphans, challenge)
	fmt.Printf("\nMerkle proof of leaf %d: \n", challenge) 
	for i := 0; i < len(proof); i++ {
		fmt.Println(Bytes2Hex(proof[i]))
	}

	fmt.Printf("\nProof is valid: \n")
	fmt.Println(check_merkle_proof(proof, *file_root))

	//A private key
	key := Sha3(Hex2Bytes("hello world"))
	//fmt.Printf("Private key: \n")
	//fmt.Println(Bytes2Hex(key))

	//Signatures of the data chunks
	sigs := sign_chunks(chunks, key)
	//fmt.Printf("Signatures: \n")
	//fmt.Println(sigs)

	sig_orphans := make_orphan_nodes(sigs)
	
	//Calculate merkle root of the signature
	sig_root := merkle_tree(sig_orphans)
	fmt.Printf("\n Merkle root of sigs: \n")
	fmt.Println(Bytes2Hex((*sig_root).value))
	
}
