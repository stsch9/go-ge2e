package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/stsch9/ge2e/ge2e"
)

const usage = `Usage:
	ge2e [-s KEYFILE_PATH] mkdr DATAROOM_PATH
	ge2e [-s KEYFILE_PATH] upload FILE_PATH DATAROOM_PATH
	ge2e [-s KEYFILE_PATH] ls DATAROOM_PATH
	ge2e [-s KEYFILE_PATH] download FILE_PATH DESTINATION
	ge2e [-s KEYFILE_PATH] keyrotate DATAROOM_PATH
	ge2e rekey DATAROOM_PATH
	
Options:
	-s PATH		Path to Secret Key File. Default: secretkey
	-f PATH		Path to factor File. Default: factor
	-r PATH		Path to Recipient File. Default: recipient
	-e PATH		Path to Encapsulation File. Default: <INPUT_File>.encap`

func main() {
	keyFlag := flag.String("s", "secretkey", "secret_key file path")

	flag.Parse()

	// If not enough args, return usage
	if len(flag.Args()) < 1 {
		fmt.Println(usage)
		os.Exit(0)
	}

	function := flag.Arg(0)

	switch function {
	case "help":
		fmt.Println(usage)
		os.Exit(0)
	case "mkdr":
		mkdrHandle(*keyFlag)
	case "upload":
		uploadHandle(*keyFlag)
	case "ls":
		lsHandle(*keyFlag)
	case "download":
		downHandle(*keyFlag)
	case "keyrotate":
		keyrotateHandle(*keyFlag)
	case "rekey":
		rekeyHandle()
	default:
		fmt.Println("Run ge2e help to show usage.")
		os.Exit(1)
	}
}

func mkdrHandle(keyfile string) {
	if len(flag.Args()) != 2 {
		fmt.Println(usage)
		os.Exit(0)
	}

	dataroompath := flag.Arg(1)

	if validateFile(dataroompath) {
		fmt.Println(dataroompath + " already exists")
		os.Exit(1)
	}

	if validateFile(keyfile) {
		fmt.Println(keyfile + " already exists")
		os.Exit(1)
	}

	if err := os.MkdirAll(dataroompath+"/.meta", os.ModePerm); err != nil {
		panic(err)
	}

	ge2e.CreateDataroom(dataroompath, keyfile)
}

func uploadHandle(keyfile string) {
	if len(flag.Args()) != 3 {
		fmt.Println(usage)
		os.Exit(0)
	}

	file := flag.Arg(1)
	dataroompath := flag.Arg(2)

	if !validateFile(file) {
		fmt.Println("File " + file + " not found")
		os.Exit(1)
	}

	if !validateFile(dataroompath) {
		fmt.Println("Dataroom " + dataroompath + " not found")
		os.Exit(1)
	}

	key := readKeyFile(keyfile)

	ge2e.UploadFile(dataroompath, file, key)
}

func lsHandle(keyfile string) {
	if len(flag.Args()) != 2 {
		fmt.Println(usage)
		os.Exit(0)
	}

	dataroompath := flag.Arg(1)

	if !validateFile(dataroompath) {
		fmt.Println("Dataroom " + dataroompath + " not found")
		os.Exit(1)
	}

	key := readKeyFile(keyfile)

	ge2e.ShowFiles(dataroompath, key)
}

func downHandle(keyfile string) {
	if len(flag.Args()) != 3 {
		fmt.Println(usage)
		os.Exit(0)
	}

	file := flag.Arg(1)
	filename := filepath.Base(file)
	dataroompath := filepath.Dir(file)
	dest := flag.Arg(2)
	dest2 := filepath.Clean(dest)

	if !validateFile(dest) {
		fmt.Println("Destination " + dest + " not found")
		os.Exit(1)
	}

	if dataroompath == "." {
		fmt.Println("Use a valid dataroom")
		os.Exit(1)
	}

	if !validateFile(dataroompath) {
		fmt.Println("Dataroom " + dataroompath + " not found")
		os.Exit(1)
	}

	key := readKeyFile(keyfile)

	ge2e.DownloadFile(dataroompath, filename, dest2, key)
}

func keyrotateHandle(keyfile string) {
	if len(flag.Args()) != 2 {
		fmt.Println(usage)
		os.Exit(0)
	}

	dataroompath := flag.Arg(1)

	if !validateFile(dataroompath + "/.meta") {
		fmt.Println("Path " + dataroompath + "/.meta not found")
		os.Exit(1)
	}

	key := readKeyFile(keyfile)

	ge2e.KeyRotate(key, keyfile, dataroompath)
}

func rekeyHandle() {
	if len(flag.Args()) != 2 {
		fmt.Println(usage)
		os.Exit(0)
	}

	dataroompath := flag.Arg(1)

	if !validateFile(dataroompath + "/.meta/factor") {
		fmt.Println("Factor file " + dataroompath + "/.meta/factor not found")
		os.Exit(1)
	}

	if !validateFile(dataroompath + "/.meta/encap") {
		fmt.Println("File " + dataroompath + "/.meta/encap not found")
		os.Exit(1)
	}

	ge2e.ReKey(dataroompath)
}

func validateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}

	return true
}

func readKeyFile(keyfile string) (key []byte) {
	if !validateFile(keyfile) {
		fmt.Println("File " + keyfile + " not found")
		os.Exit(1)
	}

	data, err := os.ReadFile(keyfile)
	if err != nil {
		panic(err)
	}

	key, err = hex.DecodeString(string(data))
	if err != nil {
		panic(err)
	}

	return
}
