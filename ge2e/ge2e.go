package ge2e

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/cipher/ascon"
	"github.com/cloudflare/circl/group"
	"golang.org/x/crypto/hkdf"
)

type FileKeys struct {
	Version int                  `json:"Version"`
	Keys    map[string][2]string `json:"Keys"`
}

const r255label = "filekey"

var g group.Group = group.Ristretto255

func CreateDataroom(dataroompath string, keyfile string) {
	// create Roomkey
	sk := g.RandomScalar(rand.Reader)

	skEnc, err := sk.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(keyfile, []byte(hex.EncodeToString(skEnc)), 0600)
	if err != nil {
		panic(err)
	}

	// Create FileKey File
	k := make(map[string][2]string)
	fk := FileKeys{1, k}
	jsonFileKey, err := json.Marshal(fk)
	if err != nil {
		panic(err)
	}

	EncryptFileKeysFile(sk, dataroompath, jsonFileKey)
}

func UploadFile(dataroompath string, file string, key []byte) {
	mode := ascon.Ascon128

	sk := g.NewScalar()
	sk.UnmarshalBinary(key)

	filekeys := LoadFileKeys(sk, dataroompath)

	// check file already exists
	filename := filepath.Base(file)
	if _, ok := filekeys.Keys[filename]; ok {
		fmt.Println("File " + filename + " already exits in dataroom " + dataroompath)
		os.Exit(0)
	}

	// increment version
	filekeys.Version += 1

	// create file key
	fk := make([]byte, mode.KeySize())
	if _, err := rand.Read(fk); err != nil {
		panic(err)
	}

	// create random filename
	fn := make([]byte, 32)
	if _, err := rand.Read(fn); err != nil {
		panic(err)
	}

	filekeys.Keys[filename] = [2]string{hex.EncodeToString(fk), hex.EncodeToString(fn)}

	jsonFileKey, err := json.Marshal(filekeys)
	if err != nil {
		panic(err)
	}

	// encrypt + write file
	ivf := make([]byte, 16)
	if _, err := rand.Read(ivf); err != nil {
		panic(err)
	}

	af, err := ascon.New(fk, mode)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(dataroompath+"/"+hex.EncodeToString(fn), ivf, 0644)
	if err != nil {
		panic(err)
	}

	filef, err := os.OpenFile(dataroompath+"/"+hex.EncodeToString(fn), os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer filef.Close()

	data, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}

	if _, err := filef.Write(af.Seal(data[:0], ivf, data, nil)); err != nil {
		panic(err)
	}

	fmt.Println(string(jsonFileKey))

	// encrypt + write FileKey File
	EncryptFileKeysFile(sk, dataroompath, jsonFileKey)
}

func ShowFiles(dataroompath string, key []byte) {
	sk := g.NewScalar()
	sk.UnmarshalBinary(key)

	filekeys := LoadFileKeys(sk, dataroompath)

	for key := range filekeys.Keys {
		fmt.Println(key)
	}
}

func DownloadFile(dataroompath string, filename string, dest string, key []byte) {
	sk := g.NewScalar()
	sk.UnmarshalBinary(key)

	filekeys := LoadFileKeys(sk, dataroompath)

	// check file exists
	filekey, ok := filekeys.Keys[filename]
	if ok {
		if !validateFile(dataroompath + "/" + filekey[1]) {
			fmt.Println("ERROR: File Key exists, but File " + filekey[1] + " not found")
			os.Exit(1)
		}
	} else {
		fmt.Println("File " + filename + " not found in dataroom " + dataroompath)
		os.Exit(0)
	}

	// decrypt file
	mode := ascon.Ascon128

	fk, err := hex.DecodeString(filekey[0])
	if err != nil {
		panic(err)
	}
	a, err := ascon.New(fk, mode)
	if err != nil {
		panic(err)
	}

	data, err := os.ReadFile(dataroompath + "/" + filekey[1])
	if err != nil {
		panic(err)
	}

	nonce, ciphertext := data[:a.NonceSize()], data[a.NonceSize():]

	plain, err := a.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(dest+"/"+filename, plain, 0644)
	if err != nil {
		panic(err)
	}
}

func KeyRotate(key []byte, keyfile string, dataroompath string) {
	// read old secret key
	sk := g.NewScalar()
	sk.UnmarshalBinary(key)

	// generate new secret key
	skNew := g.RandomScalar(rand.Reader)

	skNewEnc, err := skNew.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// calculate factor
	factor := g.NewScalar().Inv(skNew)
	factor.Mul(sk, factor)

	//new secret key + store factor
	err = os.WriteFile(keyfile, []byte(hex.EncodeToString(skNewEnc)), 0600)
	if err != nil {
		panic(err)
	}

	factorEnc, err := factor.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(dataroompath+"/.meta/factor", factorEnc, 0640)
	if err != nil {
		panic(err)
	}
}

func ReKey(dataroompath string) {
	// load ephemeral ristretto255 public key
	data, err := os.ReadFile(dataroompath + "/.meta/encap")
	if err != nil {
		panic(err)
	}

	encap := g.NewElement()
	encap.UnmarshalBinary(data)

	f, err := os.ReadFile(dataroompath + "/.meta/factor")
	if err != nil {
		panic(err)
	}

	factor := g.NewScalar()
	factor.UnmarshalBinary(f)

	encap.Mul(encap, factor)

	// store new encap file
	encapEnc, err := encap.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(dataroompath+"/.meta/encap", encapEnc, 0644)
	if err != nil {
		panic(err)
	}

	// delete factor file
	err = os.Remove(dataroompath + "/.meta/factor")
	if err != nil {
		panic(err)
	}
}

func LoadFileKeys(sk group.Scalar, dataroompath string) (filekeys FileKeys) {
	data, err := os.ReadFile(dataroompath + "/.meta/Filekeys")
	if err != nil {
		panic(err)
	}

	mode := ascon.Ascon128
	nonce, iv, ciphertext := data[:32], data[32:32+ascon.NonceSize], data[32+ascon.NonceSize:]

	key := DeriveSymKey(sk, nonce, dataroompath, mode.KeySize())

	a, err := ascon.New(key, mode)
	if err != nil {
		panic(err)
	}

	plain, err := a.Open(ciphertext[:0], iv, ciphertext, nil)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(plain, &filekeys)
	if err != nil {
		panic(err)
	}
	return
}

func EncryptFileKeysFile(sk group.Scalar, dataroompath string, jsonFileKey []byte) {
	mode := ascon.Ascon128
	nonce, key := DeriveNewSymKey(sk, dataroompath, mode.KeySize(), 32+ascon.NonceSize)

	// encrypt FileKey File
	afk, err := ascon.New(key, mode)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(dataroompath+"/.meta/Filekeys", nonce, 0644)
	if err != nil {
		panic(err)
	}

	filefk, err := os.OpenFile(dataroompath+"/.meta/Filekeys", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer filefk.Close()

	if _, err := filefk.Write(afk.Seal(jsonFileKey[:0], nonce[32:], jsonFileKey, nil)); err != nil {
		panic(err)
	}
}

func validateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}

	return true
}

func DeriveSymKey(sk group.Scalar, nonce []byte, dataroompath string, keysize int) (key []byte) {
	// load ephemeral ristretto255 public key
	data, err := os.ReadFile(dataroompath + "/.meta/encap")
	if err != nil {
		panic(err)
	}

	encap := g.NewElement()
	encap.UnmarshalBinary(data)

	// calculate shared Key = epemeral scalar * recipient Element
	sharedKey := g.NewElement()
	sharedKey.Mul(encap, sk)

	sharedKey.MarshalBinary()
	sharedKeyEnc, err := sharedKey.MarshalBinary()
	if err != nil {
		panic(err)
	}

	//  derive file key
	h := hkdf.New(sha256.New, sharedKeyEnc, nonce, []byte(r255label))

	key = make([]byte, keysize)
	if _, err := io.ReadFull(h, key); err != nil {
		panic(err)
	}

	return
}

func DeriveNewSymKey(sk group.Scalar, dataroompath string, keysize int, noncesize int) (nonce []byte, key []byte) {
	// generate ephemeral ristretto255 key pair
	ek := g.RandomScalar(rand.Reader)
	encap := g.NewElement()

	encap.MulGen(ek)

	encapEnc, err := encap.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(dataroompath+"/.meta/encap", encapEnc, 0644)
	if err != nil {
		panic(err)
	}

	// calculate shared Key = epemeral scalar * recipient Element
	sharedKey := g.NewElement()
	sharedKey.Mul(encap, sk)

	sharedKey.MarshalBinary()
	sharedKeyEnc, err := sharedKey.MarshalBinary()
	if err != nil {
		panic(err)
	}

	nonce = make([]byte, noncesize)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	//  derive file key
	h := hkdf.New(sha256.New, sharedKeyEnc, nonce[:32], []byte(r255label))

	key = make([]byte, keysize)
	if _, err := io.ReadFull(h, key); err != nil {
		panic(err)
	}

	return
}
