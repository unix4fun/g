package main

import (
	"bytes"
	"errors"
	"io/ioutil"
	"os"

	//"github.com/unix4fun/pemaead"
	"../pemaead"
)

var (
	ErrIO     = errors.New("I/O error")
	ErrCrypto = errors.New("crypto error")
)

func fileCreate(fileName string, password []byte) error {
	fd, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_EXCL|os.O_SYNC, 0700)
	if err != nil {
		return err
	}

	pemfd, err := pemaead.NewWriter(fd, password, pemaead.CipherAESGCM, pemaead.DerivateArgon2)
	if err != nil {
		return ErrCrypto
	}

	t := &totpMap{}
	tJson, err := t.marshal()
	if err != nil {
		return err
	}
	_, err = pemfd.Write(tJson)
	if err != nil {
		return err
	}

	return pemfd.Close()
}

func fileRead(fileName string, password []byte) (*totpMap, error) {
	fd, err := os.Open(fileName)
	if err != nil {
		//return nil, err
		return nil, err
	}
	defer fd.Close()

	pemfd, err := pemaead.NewReader(fd, password)
	if err != nil {
		//return nil, err
		return nil, ErrCrypto
	}

	jsonMap, err := ioutil.ReadAll(pemfd)
	if err != nil {
		//return nil, err
		return nil, err
	}

	return unmarshal(jsonMap)
}

func fileRawRead(filename string, password []byte) ([]byte, error) {
	fd, err := os.Open(filename)
	if err != nil {
		//return nil, err
		return nil, err
	}
	defer fd.Close()

	pemfd, err := pemaead.NewReader(fd, password)
	if err != nil {
		//return nil, err
		panic(err)
		return nil, ErrCrypto
	}

	return ioutil.ReadAll(pemfd)
}

// quick hack to make a bytes.Buffer a WriteCloser interface
type wcbuf struct {
	b bytes.Buffer
}

func (w *wcbuf) Close() error {
	return nil
}

func (w *wcbuf) Write(b []byte) (int, error) {
	return w.b.Write(b)
}

func (w *wcbuf) Bytes() []byte {
	return w.b.Bytes()
}

func fileRawWrite(filename string, password []byte) ([]byte, error) {
	var b wcbuf

	fd, err := os.Open(filename)
	if err != nil {
		//return nil, err
		return nil, err
	}
	defer fd.Close()

	fileReadBuf, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}

	pemfd, err := pemaead.NewWriter(&b, password, pemaead.CipherAESGCM, pemaead.DerivateArgon2)
	if err != nil {
		return nil, ErrCrypto
	}

	_, err = pemfd.Write(fileReadBuf)
	if err != nil {
		return nil, err
	}

	err = pemfd.Close()
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil

}

func fileWrite(fileName string, password []byte, tmap *totpMap) error {
	fd, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0700)
	if err != nil {
		return err
	}

	pemfd, err := pemaead.NewWriter(fd, password, pemaead.CipherAESGCM, pemaead.DerivateArgon2)
	if err != nil {
		return ErrCrypto
	}

	tJson, err := tmap.marshal()
	if err != nil {
		return err
	}
	_, err = pemfd.Write(tJson)
	if err != nil {
		return err
	}

	return pemfd.Close()
}
