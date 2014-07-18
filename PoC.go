package main

import (
        "fmt"
        "encoding/hex"
        "github.com/obscuren/sha3"
	"github.com/obscuren/secp256k1-go"
  	//"io"
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

/* this makes a modified merkle tree, one that doesn't require even powers of 2 number of slices
  for example, a merkle tree with 3 leaves would look like this:
       O
      / \
     O
    / \
*/
func merkle_tree(data_slice [][]byte) *Node {
	num_chunks := len(data_slice) 
	
	//this guy keeps track the orphans, and begins as a copy of data_slice
	orphans := make([]*Node, num_chunks)
	for i := 0; i < num_chunks; i++ {
		orphans[i] = new(Node)
		(*orphans[i]).value = append((*orphans[i]).value,data_slice[i]...)
	}

	//orphans are nodes without parents
	// in a merkle tree, there is exactly one orphan, and every parent has two children
	num_orphans := num_chunks
	for num_orphans > 1 {
		for i := 0; i < num_orphans/2; i++ { //taking pairs of orphans and giving them parents
			new_parent := new(Node) 
			var temp []byte //this'll hold the thing to be hashed
			temp = append(temp, (*orphans[2*i]).value...)
			temp = append(temp, (*orphans[2*i + 1]).value...)
			temp = Sha3(temp)
			new_parent.value = append(new_parent.value, temp...)
			new_parent.child = append(new_parent.child, orphans[2*i:2*i + 2]...)
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
	fmt.Println(len((*parent).child))
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

	chunk_size := 32 // in bytes

	//Pad it so it's a multiple of the chunk_size
	padded := pad_data(data, chunk_size)
	//fmt.Printf("Padded data: \n")
	//fmt.Println(padded)

	//Slice the (padded) data into chunks
	chunks := slice_data(padded, chunk_size)
	//fmt.Printf("Sliced data, \n")
	//fmt.Println(chunks)

	fmt.Printf("Note that we have %d data chunks/signatures as the leaves of the merkle trees\n", len(chunks))

	//Calculate the merkle root of the file
	file_root := merkle_tree(chunks)
	fmt.Printf("Merkle root of file: \n")
	fmt.Println(Bytes2Hex((*file_root).value))

	//This can be used to check the structure of the tree
	//var calls int = 0
	//report_decendants(file_root, &calls)

	//A private key
	key := Sha3(Hex2Bytes("hello world"))
	fmt.Printf("Private key: \n")
	fmt.Println(Bytes2Hex(key))

	//Signatures of the data chunks
	sigs := sign_chunks(chunks, key)
	//fmt.Printf("Signatures: \n")
	//fmt.Println(sigs)
	
	//Calculate merkle root of the signature
	sig_root := merkle_tree(sigs)
	fmt.Printf("Merkle root of sigs: \n")
	fmt.Println(Bytes2Hex((*sig_root).value))
	
}
