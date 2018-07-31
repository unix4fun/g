package main

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/tuotoo/qrcode"
	"github.com/unix4fun/pemaead"
)

var (
	ErrIO         = errors.New("I/O error")
	ErrCrypto     = errors.New("crypto error")
	ErrInvalidUrl = errors.New("invalid otp url")
	ErrInvalidQr  = errors.New("invalid qrcode")
)

// XXX this function is not clean yet.. but does the job for now..
func urlToTotpEntry(otpurl string) (string, *totpEntry, error) {
	var issuer string

	u, err := url.Parse(otpurl)
	if err != nil {
		return "", nil, err
	}

	if u.Host != "totp" {
		return "", nil, ErrInvalidQr
	}

	v, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", nil, err
	}

	// issuer
	issuerArray := strings.Split(u.Path[1:], ":")
	switch len(issuerArray) {
	case 1:
		issuer = issuerArray[0]
	case 2:
		issuer = issuerArray[1]
	default:
		return "", nil, ErrInvalidQr
	}

	sstr, ok := v["secret"]
	if !ok {
		return "", nil, ErrInvalidQr
	}

	dstr, ok := v["digits"]
	if !ok {
		return "", nil, ErrInvalidQr
	}

	d, err := strconv.Atoi(dstr[0])
	if err != nil {
		return "", nil, err
	}

	pstr, ok := v["period"]
	if !ok {
		return "", nil, ErrInvalidQr
	}
	p, err := strconv.Atoi(pstr[0])
	if err != nil {
		return "", nil, err
	}

	hstr, ok := v["algorithm"]
	if !ok {
		return "", nil, ErrInvalidQr
	}
	h := strings.ToLower(hstr[0])
	e := totpEntry{
		Secret: sstr[0],
		Digit:  d,
		Period: p,
		Hash:   h,
	}

	return issuer, &e, nil
}

func qrRead(filename string) (string, *totpEntry, error) {
	fi, err := os.Open(filename)
	if err != nil {
		return "", nil, err
	}
	defer fi.Close()

	qrmatrix, err := qrcode.Decode(fi)
	if err != nil {
		return "", nil, err
	}

	otpurl := qrmatrix.Content
	return urlToTotpEntry(otpurl)
}

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
