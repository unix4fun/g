package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrExist        = errors.New("error id already exist")
	ErrInvalidEntry = errors.New("invalid entry")
)

//type totpMap map[string]string
type totpEntry struct {
	Secret string `json:"secret"`
	//normSecret []byte // not exported just runtime..
	Hash   string `json:"hash"`
	Digit  int    `json:"digit"`
	Period int    `json:"period"`
}

type totpMap map[string]totpEntry

func (e totpEntry) Validate() error {
	// check secret
	_, err := normalizeGoogleAuthSecret(e.Secret)
	if err != nil {
		return ErrInvalidEntry
	}

	if len(e.Secret) <= 0 {
		return ErrInvalidEntry
	}

	switch e.Hash {
	case "sha1", "sha256", "sha512":
	default:
		return ErrInvalidEntry
	}

	switch e.Digit {
	case 6, 7, 8:
	default:
		return ErrInvalidEntry
	}

	return nil
}

//func (am *totpMap) get(name string) (a []totpEntry) {
//func (am *totpMap) get(name string) *totpMap {
func (am *totpMap) get(names []string) *totpMap {
	res := totpMap{}

	if len(names) == 0 {
		res = (*am)
		return &res
	}

	for k, v := range *am {
		for _, name := range names {
			//fmt.Printf("key: %s V: %v / %T\n", k, v, v)
			if strings.Contains(strings.ToLower(k), strings.ToLower(name)) {
				res[k] = v
			}
		}
	}
	return &res
}

func (am *totpMap) add(name string, e totpEntry) error {
	_, ok := (*am)[name]
	if ok {
		return ErrExist
	}
	(*am)[name] = e
	return nil
}

func (am *totpMap) update(name string, e totpEntry) {
	_, ok := (*am)[name]
	if ok {
		fmt.Printf("updating %s\n", name)
	}
	(*am)[name] = e
}

func (am *totpMap) remove(name string) {
	delete((*am), name)
}

func (am *totpMap) marshal() ([]byte, error) {
	return json.MarshalIndent(am, "", " ")
}

func unmarshal(j []byte) (*totpMap, error) {
	a := &totpMap{}
	err := json.Unmarshal(j, a)
	if err != nil {
		return nil, err
	}
	return a, nil
}
