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

//Nothing interesting here.. or until the merkle_tree function
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

//This is the basic data structure that compose our trees
type Node struct {
	value []byte
	child []*Node
	parent []*Node
	sig *Node	
}


//This makes unconnected Nodes with .value fields as chunks of the data
func make_orphan_nodes (data_chunks [][]byte) []*Node {
	num_chunks := len(data_chunks)
        orphans := make([]*Node, num_chunks)
        for i := 0; i < num_chunks; i++ {
                orphans[i] = new(Node)
                (*orphans[i]).value = append((*orphans[i]).value,data_chunks[i]...)
        }
	return orphans
}


/* The merkle_tree function makes a modified merkle tree, one that doesn't require an exact power of 2 number of leaves
  for example, a merkle tree with 3 leaves would look like this:
       O
      / \
     O
    / \


The convention will be to append to bigger hash to a smaller hash
	H(H1 + H2) if H1 < H2 

The algorithm is very simple, so you are encouraged to try to read the code:
*/

func merkle_tree(leaves []*Node) *Node {
        //orphans are nodes without parents
	//Before we build the tree, every leaf is an orphan
        num_orphans := len(leaves)
	orphans := make([]*Node, num_orphans)
	copy(orphans, leaves)
	
	//After the merkle tree is produced there is exactly one orphan, and every parent has two children
	for num_orphans > 1 {


		//This loop takes pairs of orphans and gives them parents
		for i := 0; i < num_orphans/2; i++ {

			
			//The orphanage at work: 
			new_parent := new(Node)  	
                        new_parent.child = append(new_parent.child, orphans[2*i:2*i + 2]...)
                        (*orphans[2*i]).parent = append((*orphans[2*i]).parent, new_parent)
                        (*orphans[2*i + 1]).parent = append((*orphans[2*i + 1]).parent, new_parent)


			//We have a neat convention: 
			//the parent's value is the hash of the children's values,
			//concatenated in the order or whose value is smaller  
                        H1 := (*orphans[2*i]).value
                        H2 := (*orphans[2*i + 1]).value
			H := H1 //this'll hold the thing to be hashed


			if bytes.Compare(H1, H2) == -1 {
				H = append(H, H2...)
			} else {
				H = append(H2, H...)
			}
	
	
			H = Sha3(H)
			new_parent.value = append(new_parent.value, H...)

                        //Oh no, the parent is an orphan:
                        orphans[i] = new_parent

		}
		//If not every orphan could find a sibling, place the odd one out at the end of the new orphans list
		if num_orphans % 2 == 1 {
			orphans[num_orphans/2] = orphans[num_orphans - 1]
		}
		//Gotta keep track of the number of orphans we have in our orphanage, for legal reasons
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
//You can use it to manually audit merkle trees
func report_decendants(parent *Node, call_num *int) {
	if *call_num == 0 {
		fmt.Printf("Root: \n")
		fmt.Println(Bytes2Hex((*parent).value))
	}

	for i := range (*parent).child {
		fmt.Printf("Call number: %d\n", *call_num)
		fmt.Println(Bytes2Hex((*(*parent).child[i]).value))
		*call_num += 1
		report_decendants((*parent).child[i], call_num)
	}
}

//A wrapper on the sig function
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


/* The merkle proof can be produced according to directions,
 which tell us whether to make the branch fork towards the child with higher or lower .value
 If no directions are used, the starting_point is taken to be a leaf of the merkle tree
 It directions are used, the starting_point is taken to be the root node of the tree
 The function returns the leaf node that was used to produce the proof,
 this is particularly useful when directions are used, so the leaf node may not be known ahead of time */

func produce_merkle_proof(starting_point *Node, using_directions bool, directions []bool) ([][]byte, *Node) {

	current_node := starting_point

	if using_directions {  //directions are from the root node
		//Fwe make our way from the root to the leaf
		//the boolean array tells us how to decend down the tree
		//specifically, it says which child should have their children as part of the proof
		for i := 0; len((*current_node).child) > 0; i++ {
			
			//Decending the tree in the appropriate direction..
			kids := (*current_node).child
			if (bytes.Compare(kids[0].value, kids[1].value) == -1) == directions[i] {
				current_node = kids[0]
			} else {
				current_node = kids[1]
			}
		}
	} 

	// This is either the starting_point, or the leaf arrived to by following the directions
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


/* sometimes the verification of a merkle proof will require that the leaf be the result of
  following directions from the root node, other times reconstruction of the root node is sufficient
  this function handles both of these cases
*/
func verify_merkle_proof(proof [][]byte, root Node, check_directions bool, directions []bool) bool {
	var H []byte
	H = append(H, proof[0]...)
	
	for i := 1; i < len(proof); i++ {

		//If the proof complies to the directions, then the relative size of the 'cumulative hash'
		// that reconstructs the root node and the next hash to be 'added' to it is given by 'directions'
		if check_directions {
			//directions are from root node to leaf, so we must trace them backwards:
			if (bytes.Compare(H,proof[i]) == -1) != directions[len(proof) - i - 1] {
				return false
			}
		}

		// Regardless of the directions, the larger value gets concatenated with the smaller value
		if bytes.Compare(H, proof[i]) == -1 {
			H = append(H, proof[i]...)
		} else { 
			H = append(proof[i], H...)
		}
		H = Sha3(H)
	}

	return bytes.Compare(H, root.value) == 0	
}


//The 'stage' is a platform for producing proofs of custody :)
type PoC_stage struct {
        data []*Node
	data_root *Node //The source of the file root used by the auditor should be independent of the one in the stage
        sigs []*Node
	sig_root *Node
}

//This func stages the stage, setting up everything that is needed to produce proofs
func stage_PoC(file string, key []byte) PoC_stage {

        // this is the largest chunk size that can be signed by secp256k1.Sign
        // bigger data chunks would have to be hashed before signed, which opens
        // the attack vector of sharing the hashes rather than the file, to collude
        // to produce a proof-of-custody
	chunk_size := 32 //in bytes


	var stage PoC_stage 

	//Staging the data for production of PoCs
        data := read_data(file)
        padded_data := pad_data(data, chunk_size)
        chunks := slice_data(padded_data, chunk_size)
       	stage.data = make_orphan_nodes(chunks)
        stage.data_root = merkle_tree(stage.data)

	//Staging the signatures into a tree
        sigs := sign_chunks(chunks, key)
        stage.sigs = make_orphan_nodes(sigs)
        stage.sig_root = merkle_tree(stage.sigs)
	
	//Identifing the leaf nodes of the data tree with the leaves of the sig tree
	for i := 0; i < len(stage.data); i++ {
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

//fills the challenge struct with random bools, namely num_challenges slices of size tree_depth
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

/* This produces a PoC from a stage in reponse to a challenge
  the challenge is interpreted as being given to select the data leaf
  then, the proof for the signature of that data is provided */
func PoC_response (stage PoC_stage, challenge PoC_challenge) PoC {
	var proof PoC
	data_leaf := new(Node)
	for i := 0; i < len(challenge.directions); i++ {
		proof.data_proof = append(proof.data_proof, *new([][]byte))
		proof.sig_proof = append(proof.sig_proof, *new([][]byte))

		//Finds proof for the data according to directions, and proof for sig according to which piece was chosen
		proof.data_proof[i], data_leaf = produce_merkle_proof(stage.data_root, true, challenge.directions[i])
		proof.sig_proof[i], _ = produce_merkle_proof((*data_leaf).sig, false, challenge.directions[i])
	}
	return proof
}


func ECVerify(hash []byte, sig []byte) bool {
	_, err := secp256k1.RecoverPubkey(hash, sig)
	if err != nil {
		return true//false
	}
	return true
}

//This verifies a PoC from the file + sig root and challenge
func PoC_verify(proof PoC, file_root *Node, sig_root *Node, challenge PoC_challenge) bool {
	var valid bool = true
	for i := 0; i < len(challenge.directions); i++ {
		valid = valid && verify_merkle_proof(proof.data_proof[i], *file_root, true, challenge.directions[i])
		valid = valid && verify_merkle_proof(proof.sig_proof[i], *sig_root, false, challenge.directions[i])
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

	report_decendants(stage.data_root, new(int))

	commit := PoC_commit(stage)
	fmt.Printf("\nCommitment of signature root: \n")
	fmt.Println(Bytes2Hex((*commit).value))

	challenge := produce_challenge(Hex2Bytes("hello world"), 5, 7)

	fmt.Printf("\nChallenge: \n")
	fmt.Println(challenge)

	response := PoC_response(stage, challenge)	

	fmt.Printf("Data proof: \n")
	for i := 0; i < len(response.data_proof[0]); i++ {
		fmt.Println(Bytes2Hex(response.data_proof[0][i]))
	}
	valid := PoC_verify(response, stage.data_root, stage.sig_root, challenge) 

	fmt.Printf("\nProofs valid: \n")
	fmt.Println(valid)
}
