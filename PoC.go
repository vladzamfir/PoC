package main

import (
        "fmt"
	"math/big"
	"bytes"
        "encoding/hex"
        "github.com/obscuren/sha3"
	"github.com/obscuren/secp256k1-go"
    	"io/ioutil"
)

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
	parent []*Node
	sig *Node	
}

//This makes unconnected nodes with .value fields as the slices of the data
func make_orphan_nodes (data_chunks [][]byte) []*Node {
	num_chunks := len(data_chunks)
        orphans := make([]*Node, num_chunks)
        for i := 0; i < num_chunks; i++ {
                orphans[i] = new(Node)
                (*orphans[i]).value = append((*orphans[i]).value,data_chunks[i]...)
        }
	return orphans
}


/* The following function makes a modified merkle tree, one that doesn't require an exact power of 2 number of leaves
  for example, a merkle tree with 3 leaves would look like this:
       O
      / \
     O
    / \


The convention will be to append to bigger hash to a directions hash
	H(H1 + H2) if H1 < H2 
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

func find_sibling (brother *Node) *Node{
	parent := (*brother).parent[0]
	if (*parent).child[0] == brother {
		return (*parent).child[1]
	} else {
		return (*parent).child[0]
	}
}

//returns a merkle proof of a leaf at a returned pointer
func produce_merkle_proof(starting_point *Node, using_directions bool, directions []bool) ([][]byte, *Node) {
	current_node := starting_point
	if using_directions {  //directions are from the root node
		//First, we make our way from the root to the leaf
		//the boolean array tells us how to decend down the tree
		//specifically, it says whether to go for to the child with a directions hash-value
		for i := 0; len((*current_node).child) > 0; i++ {
			kids := (*current_node).child
			if (bytes.Compare(kids[0].value, kids[1].value) == -1) == directions[i] {
				current_node = kids[0]
			} else {
				current_node = kids[1]
			}
		}
	} 
	leaf := *current_node
        //produce a merkle proof, from the leaf of the tree:
	proof := new([][]byte)
	*proof = append(*proof, (*current_node).value)
	for len((*current_node).parent) > 0 {
		H := (*find_sibling(current_node)).value
		*proof = append(*proof, H)		
		current_node = (*current_node).parent[0]
	}
	return *proof, &leaf
}



//sometimes the merkle proof will mandate an order, other times it will not
func verify_merkle_proof(proof [][]byte, root Node, check_order bool, directions []bool) bool {
	var H []byte
	H = append(H, proof[0]...)
	
	for i := 1; i < len(proof); i++ {
		if check_order {
			if (bytes.Compare(H,proof[i]) == -1) != directions[len(proof) - i - 1] {
				return false
			}
		}

		if bytes.Compare(H, proof[i]) == -1 {
			H = append(H, proof[i]...)
		} else { 
			H = append(proof[i], H...)
		}
		H = Sha3(H)
	}
	return bytes.Compare(H, root.value) == 0	
}


type PoC_stage struct {
        data []*Node
	data_root *Node //This shouldn't really be here, but for now there is no other source of the file root
        sigs []*Node
	sig_root *Node
}

//This fills the above struct - it sets up everything that is needed to produce Merkle proofs
func stage_PoC(file string, key []byte) PoC_stage {
        //this is the largest chunk size that can be signed by secp256k1.Sign
        //bigger data chunks would have to be hashed before signed, which opens
        //the attack vector of sharing the hashes rather than the file, to collude
        // to produce a proof-of-custody
	chunk_size := 32 //in bytes

	var stage PoC_stage 

        data := read_data(file)
        padded_data := pad_data(data, chunk_size)
        chunks := slice_data(padded_data, chunk_size)
        stage.data = make_orphan_nodes(chunks)
        stage.data_root = merkle_tree(stage.data)

        sigs := sign_chunks(chunks, key)
        stage.sigs = make_orphan_nodes(sigs)
        stage.sig_root = merkle_tree(stage.sigs)
	
	for i := 0; i < len(stage.data); i ++ {
		(*stage.data[i]).sig = stage.sigs[i]
	}

	return stage
}

func PoC_commit (stage PoC_stage) *Node {
	return stage.sig_root
}

//the challenge is made of N sub-challenges	
type PoC_challenge struct {
	directions [][]bool 
}

//fills the above struct with random bools, namely num_challenges slices of size tree_depth
//the tree depth, really, is the maximum tree depth - some proofs will be shorter, and that's fine
func produce_challenge(seed []byte, num_challenges int, tree_depth int) PoC_challenge {
	var chal PoC_challenge

	Z := new(big.Int)
	X := new(big.Int)
	buff := new(big.Int)
	buff.SetInt64(1024)
	X.SetBytes(Sha3(seed))	
	for i := 0; i < num_challenges; i++ {
                chal.directions = append(chal.directions, *new([]bool))
		for j := 0; j < tree_depth; j++ {
			if X.Cmp(buff) == -1 {
				X.SetBytes(Sha3(X.Bytes()))
			} 
			Y := int((Z.Mod(X,big.NewInt(2))).Int64())
			X.Div(X,big.NewInt(2))
			b := (Y == 1)
			chal.directions[i] = append(chal.directions[i], b)
		}
	}
	return chal
}

// Each [][]byte array is a merkle proof
type PoC struct {
        data_proof [][][]byte
        sig_proof [][][]byte
}

// This produces a PoC from a stage in reponse to a challenge
func PoC_response (stage PoC_stage, challenge PoC_challenge) PoC {
	var proof PoC
	data_leaf := new(Node)
	for i := 0; i < len(challenge.directions); i++ {
		proof.data_proof = append(proof.data_proof, *new([][]byte))
		proof.sig_proof = append(proof.sig_proof, *new([][]byte))
		
		proof.data_proof[i], data_leaf = produce_merkle_proof(stage.data_root, true, challenge.directions[i])
		proof.sig_proof[i], _ = produce_merkle_proof((*data_leaf).sig, false, challenge.directions[i])
	}
	return proof
}


func ECVerify(hash []byte, sig []byte) bool {
	_, err := secp256k1.RecoverPubkey(hash, sig)
	if err != nil {
		return false
	}
	return true
}

//This verifies a PoC from the file + sig root and challenge
func PoC_verify(proof PoC, file_root *Node, sig_root *Node, challenge PoC_challenge) bool {
	var valid bool = true
	for i := 0; i < len(challenge.directions); i++ {
		valid = valid && verify_merkle_proof(proof.data_proof[i], *file_root, true, challenge.directions[i])
		valid = valid && verify_merkle_proof(proof.sig_proof[i], *sig_root, false,  challenge.directions[i])
		valid = valid && ECVerify(proof.data_proof[i][0], proof.sig_proof[i][0])
		if !valid {return false}
	}
	return true
}

func main() {

	//A private key
	key := Sha3(Hex2Bytes("hello world"))
	fmt.Printf("Private key: \n")
	fmt.Println(Bytes2Hex(key))

	stage := stage_PoC("helloworld.txt", key)

	commit := PoC_commit(stage)
	fmt.Printf("\nCommitment of signature root: \n")
	fmt.Println(Bytes2Hex((*commit).value))

	challenge := produce_challenge(Hex2Bytes("hello world"), 5, 7)

	fmt.Printf("\nChallenge: \n")
	fmt.Println(challenge)

	response := PoC_response(stage, challenge)	

	valid := PoC_verify(response, stage.data_root, stage.sig_root, challenge) 

	fmt.Printf("\nProofs valid: \n")
	fmt.Println(valid)


}
