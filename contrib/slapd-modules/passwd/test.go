package main
import "C"
func main(){}

//export test
func test() C.int{
	return C.int(0)
}
