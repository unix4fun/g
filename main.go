package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path"
	"strings"
	"time"

	"github.com/unix4fun/totp"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	Version              = "0.1.1"
	totpPemFile          = ".config/g.pem"
	regularDisplayFormat = []string{
		"%-10.10s | %-6s\n", // display header
		"invalid", "invalid",
		"invalid", "invalid", "invalid",
		"%-10.10s | %06d\n", // display for 6 digits
		"%-10.10s | %07d\n", // display for 7 digits
		"%-10.10s | %08d\n", // display for 8 digits
	}
	extendedDisplayFormat = []string{ // XXX not ready
		"%-10.10s | %-6s %-6s %-6s\n", // display header
		"invalid", "invalid",
		"invalid", "invalid", "invalid",
		"%-10.10s | %-6d %-6d %-6d\n",
		"%-10.10s | %-7d %-7d %-7d\n",
		"%-10.10s | %-8d %-8d %-8d\n"}
	progressFormat = "\n[%-10s] TTL\n" // XXX temporary
	trimCutset     = "\",!?'`"
	// some errors
	ErrInvalidOpt  = errors.New("invalid options")
	ErrInvalidTerm = errors.New("invalid tty")
	ErrMismatch    = errors.New("password mismatch")
)

// base32 stdencoding alphabet is ALWAYS the safe according to RFC 4648
// actually the secret CANNOT be different from this.. :)
// makes the bruteforcing SO MUCH EASIER :)
// base32 standard alphabet:
// ABCDEFGHIJKLMNOPQRSTUVWXYZ234567 (= pad)
//
func normalizeGoogleAuthSecret(secret string) ([]byte, error) {
	secEncoded := strings.ToUpper(strings.Replace(strings.Replace(secret, "-", "", -1), " ", "", -1))
	secEndodedPadLen := 8 - (len(secEncoded) % 8)
	if secEndodedPadLen < 8 {
		secEncoded = secEncoded + strings.Repeat("=", secEndodedPadLen)
	}
	//fmt.Printf("NORMALIZED: %s\n", secEncoded)
	return base32.StdEncoding.DecodeString(secEncoded)
}

func terminalInitPasswd(prefix string) ([]byte, error) {
	if terminal.IsTerminal(0) {

		oldState, err := terminal.MakeRaw(0)
		if err != nil {
			return nil, err
		}

		fmt.Printf("%sPassword:", prefix)
		passwd_one, err := terminal.ReadPassword(0)
		if err != nil {
			terminal.Restore(0, oldState)
			return nil, err
		}
		terminal.Restore(0, oldState)
		fmt.Printf("\n")

		// second one
		oldState, err = terminal.MakeRaw(0)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Retype %sPassword:", prefix)
		passwd_two, err := terminal.ReadPassword(0)
		if err != nil {
			terminal.Restore(0, oldState)
			return nil, err
		}
		terminal.Restore(0, oldState)
		fmt.Printf("\n")

		if bytes.Equal(passwd_one, passwd_two) {
			return passwd_one, nil
		}

		return nil, ErrMismatch
	}

	return nil, ErrInvalidTerm
}

func terminalUpdatePasswd() ([]byte, error) {
	// check old password by opening it
	// call terminal InitPasswd now..
	return nil, nil
}

func terminalGetPasswd(prefix string) ([]byte, error) {
	// remember the state and make raw
	if terminal.IsTerminal(0) {
		oldState, err := terminal.MakeRaw(0)
		if err != nil {
			return nil, err
		}

		fmt.Printf("%sPassword:", prefix)
		passwd, err := terminal.ReadPassword(0)
		if err != nil {
			terminal.Restore(0, oldState)
			return nil, err
		}
		// to make sure the display is ready.
		terminal.Restore(0, oldState)
		fmt.Printf("\n")

		return passwd, nil
	}

	return nil, ErrInvalidTerm
}

type cmdOptions struct {
	pemFile       string
	pemFilePasswd []byte
	pemFileMap    *totpMap

	otpEntry  string
	otpSecret string
	otpDigit  int
	otpPeriod int
	otpHmac   string
}

func (cmd *cmdOptions) validate() error {
	switch cmd.otpHmac {
	case "sha1", "sha256", "sha512":
	default:
		return ErrInvalidOpt
	}

	switch cmd.otpDigit {
	case 6, 7, 8:
	default:
		return ErrInvalidOpt
	}

	return nil
}

func (cmd *cmdOptions) getPasswd() (err error) {
	cmd.pemFilePasswd, err = terminalGetPasswd("")
	if err != nil {
		return err
	}
	// load the file
	cmd.pemFileMap, err = fileRead(cmd.pemFile, cmd.pemFilePasswd)
	if err != nil {
		return err
	}

	return nil
}

func (cmd *cmdOptions) qrCmdHandler(imgfile string) error {
	name, e, err := qrRead(imgfile)
	if err != nil {
		return err
	}

	err = e.Validate()
	if err != nil {
		return err
	}

	err = cmd.pemFileMap.add(name, *e)
	if err != nil {
		return err
	}

	err = fileWrite(cmd.pemFile, cmd.pemFilePasswd, cmd.pemFileMap)
	if err != nil {
		return err
	}

	return nil
}

func (cmd *cmdOptions) addCmdHandler(name string) error {
	fmt.Printf("adding %s now!\n", name)
	if len(cmd.otpSecret) == 0 {
		fmt.Printf("no secret\n")
		return ErrInvalidOpt
	}
	// TODO SANITIZATION
	//sane := strconv.Quote(name)

	e := totpEntry{
		Secret: cmd.otpSecret,
		Digit:  cmd.otpDigit,
		Period: cmd.otpPeriod,
		Hash:   cmd.otpHmac,
	}

	fmt.Printf("ADDING ENTRY: %s/%v/%d\n", name, e, len(e.Secret))
	err := e.Validate()
	if err != nil {
		return err
	}
	// check basic values
	err = cmd.pemFileMap.add(name, e)
	if err != nil {
		return err
	}

	err = fileWrite(cmd.pemFile, cmd.pemFilePasswd, cmd.pemFileMap)
	if err != nil {
		return err
	}

	return nil
}

func (cmd *cmdOptions) rmCmdHandler(name string) error {
	// TODO SANITIZATION
	//sane := strconv.Quote(name)

	// XXX test if nil
	cmd.pemFileMap.remove(name)

	err := fileWrite(cmd.pemFile, cmd.pemFilePasswd, cmd.pemFileMap)
	if err != nil {
		return err
	}

	return nil
}

func (cmd *cmdOptions) updCmdHandler(name string) error {
	fmt.Printf("update %s now!\n", name)
	if len(cmd.otpSecret) == 0 {
		fmt.Printf("no secret\n")
		return ErrInvalidOpt
	}
	//
	e := totpEntry{
		Secret: cmd.otpSecret,
		Digit:  cmd.otpDigit,
		Hash:   cmd.otpHmac,
	}

	err := e.Validate()
	if err != nil {
		return err
	}

	cmd.pemFileMap.update(name, e)
	/*
		cmd.pemFileMap.remove(name)

		err = cmd.pemFileMap.add(name, e)
		if err != nil {
			return err
		}
	*/

	err = fileWrite(cmd.pemFile, cmd.pemFilePasswd, cmd.pemFileMap)
	if err != nil {
		return err
	}

	return nil
}

// CLI, let's keep it simple
//
// ./g <account>
//
// [-pem <filename>] or default filename
//
// -init (bool)
// -pass (bool)
// -dec (bool)
// -enc (bool)
// -add <name>
// -rm <name>
// -up <name>
//
// -pem <filename> (operate on that file)
//
//
// -add <name> [options]
//  add <name> in the current/default pemfile (minimum -sec)
// -rm <name> [options]
//  remove <name> from the current/default pemfile (minimum -sec)
// -upd <name> [options]
//  update <name> in the current default pemfile (minimum -sec)
//
// [options]
// -sec <secret string>
// -digit <int> (default: 6)
// -hmac <string> (default: sha1)
//
// typical usage
// 1. g [-pem <filename>] -init
// ..password setup asked..
// 2. g [-pem <filename>] -pass
// ..change pemfile password..
// 3. g [-pem <filename>] -dec
// ..decrypt pemfile and output to stdout
// 4. g [-pem <filename>] -enc
// ..encrypt pemfile and output to stdout
// 5. g [-pem <filename>] -add gmailu4f -sec xxxx-yyyy-zzzz
// ..password being asked..
// 6. g [-pem <filename>] gmail
// ..password being asked..

func (cmd *cmdOptions) pemInitFile() (err error) {
	cmd.pemFilePasswd, err = terminalInitPasswd("Init ")
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return err
	}
	err = fileCreate(cmd.pemFile, cmd.pemFilePasswd)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return err
	}

	return nil
}

func (cmd *cmdOptions) pemPassFile() (err error) {
	passwd, err := terminalGetPasswd("Old ")
	if err != nil {
		return err
	}
	// load the file
	tmap, err := fileRead(cmd.pemFile, passwd)
	if err != nil {
		return err
	}
	cmd.pemFilePasswd, err = terminalInitPasswd("New ")
	if err != nil {
		return err
	}

	err = fileWrite(cmd.pemFile, cmd.pemFilePasswd, tmap)
	if err != nil {
		return err
	}

	return nil
}

func (cmd *cmdOptions) pemDecryptFile(w io.Writer) error {
	passwd, err := terminalGetPasswd("")
	if err != nil {
		return err
	}

	decrypted, err := fileRawRead(cmd.pemFile, passwd)
	if err != nil {
		return err
	}

	_, err = w.Write(decrypted)
	return err

}

func (cmd *cmdOptions) pemEncryptFile(w io.Writer) error {
	passwd, err := terminalInitPasswd("Set ")
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return err
	}

	encrypted, err := fileRawWrite(cmd.pemFile, passwd)
	if err != nil {
		return err
	}

	_, err = w.Write(encrypted)
	return err

}

func main() {
	//fmt.Println("gator")
	//hmac := "sha1"

	user, err := user.Current()
	if err != nil {
		panic(err)
	}

	totpPem := path.Join(user.HomeDir, totpPemFile)

	// first command
	//pemFlag := flag.Bool("pem", false, "PEM subcommands")
	pemFlag := flag.String("pem", totpPem, "PEM filename to use")

	// these are PEM file operation nothing else..exist after executing the
	// operation.
	pemInitFlag := flag.Bool("init", false, "initialize the PEM file (will truncate if existing)")
	pemPassFlag := flag.Bool("pass", false, "update PEM file password")
	pemEncryptFlag := flag.Bool("enc", false, "encrypt PEM file and output on stdout")
	pemDecryptFlag := flag.Bool("dec", false, "decrypt PEM file and output on stdout")

	// actual command operation
	addQrFlag := flag.String("qr", "", "scan & add from QRcode image file")
	addFlag := flag.String("add", "", "add entry <name>")
	rmFlag := flag.String("rm", "", "remove entry <name>")
	updFlag := flag.String("upd", "", "update entry <name>")
	secFlag := flag.String("sec", "", "TOTP shared secret (valid: len>0)")
	digitFlag := flag.Int("digit", 6, "TOTP token size (valid: {6,7,8})")
	periodFlag := flag.Int("period", 30, "TOTP window (default: 30)")
	hmacFlag := flag.String("hmac", "sha1", "TOTP hmac function (valid {sha1|sha256|sha512}) (default: sha1)")

	flag.Parse()

	// remaining arguments
	sargs := flag.Args()

	//fmt.Printf("sargs: %v\n", sargs)

	cmd := &cmdOptions{
		pemFile:   *pemFlag,
		otpSecret: strings.TrimSpace(*secFlag),
		otpDigit:  *digitFlag,
		otpPeriod: *periodFlag,
		otpHmac:   strings.TrimSpace(*hmacFlag),
	}

	switch {
	case *pemPassFlag:
		//fmt.Printf("change pem file passwd: %s\n", cmd.pemFile)
		err := cmd.pemPassFile()
		if err != nil {
			panic(err)
		}
		os.Exit(0)
	case *pemEncryptFlag:
		//fmt.Printf("encrypt pem file: %s\n", cmd.pemFile)
		//return pemEncryptFile(cmd.pemFile, os.Stdout)
		err := cmd.pemEncryptFile(os.Stdout)
		if err != nil {
			panic(err)
		}
		os.Exit(0)
	case *pemDecryptFlag:
		//fmt.Printf("decrypt pem file: %s\n", cmd.pemFile)
		//return pemDecryptFile(cmd.pemFile, os.Stdout)
		err := cmd.pemDecryptFile(os.Stdout)
		if err != nil {
			panic(err)
		}
		os.Exit(0)
	case *pemInitFlag:
		//fmt.Printf("init pem file (truncate): %s\n", cmd.pemFile)
		err := cmd.pemInitFile()
		if err != nil {
			panic(err)
		}
		os.Exit(0)
	}

	if cmd.validate() != nil {
		panic(err)
	}
	//fmt.Printf("on continue: %v\n", *addFlag)

	// read password now
	/* XXX temporary disable
	cmd.pemFilePasswd, err = terminalGetPasswd("")
	if err != nil {
		panic(err)
	}
	// load the file
	cmd.pemFileMap, err = fileRead(cmd.pemFile, cmd.pemFilePasswd)
	if err != nil {
		panic(err)
	}
	*/

	addqr := strings.TrimSpace(*addQrFlag)
	add := strings.TrimSpace(*addFlag)
	rm := strings.TrimSpace(*rmFlag)
	upd := strings.TrimSpace(*updFlag)

	switch {
	case len(addqr) > 0:
		fmt.Printf("qr code add: %s\n", addqr)
		err := cmd.getPasswd()
		if err != nil {
			panic(err)
		}
		err = cmd.qrCmdHandler(addqr)
		if err != nil {
			panic(err)
		}
	case len(add) > 0:
		//fmt.Printf("add '%v' to %s\n", *addFlag, cmd.pemFile)
		err := cmd.getPasswd()
		if err != nil {
			panic(err)
		}
		err = cmd.addCmdHandler(add)
		if err != nil {
			panic(err)
		}
	case len(rm) > 0:
		// remove only simple.
		//fmt.Printf("ici rm '%v' from %s\n", *rmFlag, cmd.pemFile)
		err := cmd.getPasswd()
		if err != nil {
			panic(err)
		}

		//fmt.Printf("rici m '%v' to %s\n", *rmFlag, cmd.pemFile)
		cmd.rmCmdHandler(rm)
	case len(upd) > 0:
		// can update digit / secret / hmac
		//fmt.Printf("update '%v' to %s\n", *updFlag, cmd.pemFile)
		//cmd.update(*updFlag)
		err := cmd.getPasswd()
		if err != nil {
			panic(err)
		}

		//fmt.Printf("update '%v' to %s\n", *updFlag, cmd.pemFile)
		cmd.updCmdHandler(upd)
	default:
		// sargs
		//fmt.Printf("params: %v\n", sargs)
		err := cmd.getPasswd()
		if err != nil {
			panic(err)
		}
		list := cmd.pemFileMap.get(sargs)

		fmt.Printf(regularDisplayFormat[0], "account", "totp")
		fmt.Printf(regularDisplayFormat[0], "----------", "----")
		//fmt.Printf("-------------------------------\n")
		for k, v := range *list {
			//var f func() hash.Hash
			f := sha1.New

			b32secret, err := normalizeGoogleAuthSecret(v.Secret)
			if err != nil {
				panic(err)
			}

			switch cmd.otpHmac {
			case "sha256":
				f = sha256.New
			case "sha512":
				f = sha512.New
			}

			t := totp.New(f, b32secret, v.Digit, v.Period)
			//left, token, err := t.GetNowWithStep()
			token, err := t.GetNow()
			if err != nil {
				panic(err)
			}

			fmt.Printf(regularDisplayFormat[v.Digit], k, token)
		}
		left := int(time.Now().Unix()%30) / 3
		//fmt.Printf(regularDisplayFormat[0], "----------", "----")
		fmt.Printf(progressFormat, strings.Repeat("=", left))
	}

	os.Exit(1)

}
