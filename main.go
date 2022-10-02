package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/latortuga71/GoCoffLdr/pkg/coff"
)

func main() {
	rawCoff, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	coff.ParseCoff(rawCoff)
}
