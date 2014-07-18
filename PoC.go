package main

import (
        "fmt"
        "encoding/hex"
        "github.com/obscuren/sha3"
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

//makes the size of the data a multiple of chunk_size (in bytes)
//returns the result
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
}

/*this makes a modified merkle tree, one that doesn't require even powers of 2 number of slices
  for example, a merkle tree with 3 leaves would look like this:
       O
      / \
     O
    / \
/*
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

func report_decendants(parent *Node, call_num *int) {
	for i := range (*parent).child {
		fmt.Printf("Call number: %d\n", *call_num)
		fmt.Println(Bytes2Hex((*(*parent).child[i]).value))
		*call_num += 1
		report_decendants((*parent).child[i], call_num)

	}
}

func main() {
	
	data := read_data("helloworld.txt")
	fmt.Println(data)
	padded := pad_data(data, 256)
	fmt.Println(padded)
	sliced := slice_data(padded, 16)
	fmt.Println(sliced)

	root := merkle_tree(sliced)
	var call_count int = 0
	report_decendants(root, &call_count) 
	
}
