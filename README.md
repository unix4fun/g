# g

A Simple "google authenticator" / TOTP client tool


## Purpose

a simple TOTP / google authenticator client.
it will generate TOTP tokens for the configured accounts and secure data at rest.

*WARNING*
This is a project in development, some trivial backup/rollback strategies are being implemented,
but it seems reliable enough that i use it everyday on various accounts.


## Installation
make sure you have a properly installed [golang](https://golang.org) and $GOPATH etc..
then :
```
$ go get github.com/unix4fun/g
$ g -h

Usage of g:
  -add string
    	add entry <name>
  -dec
    	decrypt PEM file and output on stdout
  -digit int
    	TOTP token size (valid: {6,7,8}) (default 6)
  -enc
    	encrypt PEM file and output on stdout
  -hmac string
    	TOTP hmac function (valid {sha1|sha256|sha512}) (default: sha1) (default "sha1")
  -init
    	initialize the PEM file (will truncate if existing)
  -pass
    	update PEM file password
  -pem string
    	PEM filename to use (default "/home/rival/.config/g.pem")
  -rm string
    	remove entry <name>
  -sec string
    	TOTP shared secret (valid: len>0)
  -upd string
    	update entry <name>

```

## Usage

the default secret storage lies in ~/.config/g.pem but you can ALWAYS give the pem file you want to operate on by using:
```
...  -pem <pemfile>
```

### Initialize Secret Storage

to access your tokens, you will be asked your password/passphrase whatever..

```
$ g -init
Init Password: <type your password>
Retype Init Password: <type your password again>
```

### Add Entry then Get Token

like you're setting up  your 2FA for your gmail account.
*WARNING*
Remember if you have an history file, THIS WILL BE IN YOUR HISTORY.
Most shells allows to execute a command without being history logged check your shell documentation.

Example, for now with bash, you can tell history to NOT log this command:
```
   export HISTIGNORE="g *"
```
or setup a no history space prefix like :
```
   export HISTCONTROL=ignorespace
```
and prefix your commands for token by a space.


This might be the reason for a format/editing change later.

```
$ g -add gmail -sec <google 2fa secret>
Password:
.. debug message to say it's ok...
$ g 
Password:
account    | totp  
---------- | ----  
gmail      | 357119

[==        ] TTL
```

now you can add all your tokens one by one when necessary.
tokens by default adopts google authenticator baseline (sha1 / 6 digits)

but some services provides even higher baseline, like sha256 / 8 digits token, which is also supported:
```
$ g -add patatra -sec <my secret> -hmac sha256 -digit 8
...
$ g
Password:
account    | totp
---------- | ----
gmail      | 707792
patatra    | 71997833

[========= ] TTL
```

## Data at rest

token config are in a JSON format encrypted using [PEMAEAD](https://github.com/unix4fun/pemaead)
you can decrypt them at any moment to peek if necessary and re-encrypt a payload as necessary too

```
$ g -dec
Password:
{
 	"gmail": {
  	"secret": "proutpro",
  	"hash": "sha1",
  	"digit": 6
 	},
 	"patatra": {
  	"secret": "geonimo",
  	"hash": "sha256",
  	"digit": 8
 	}
}
```

No particular reason for using JSON, i guess i was brainwashed by the whole JSON crap craze everywhere instead of using a simpler format (CSV?), which mean i might move to a simpler format later, but the tool will manage to handle backward compatibility so don't worry.


## TODO
* remove debug messages.
* might move the secret input as a terminal input instead of command line (to avoid people leave their history full of secret)
* cleaner CLI.
* rewrite help messages.
* implement unit test everywhere.
* implement QR code reader (from jpg)
