package utils

import (
	"fmt"
	"log"
	"os"
)

var (
	debugLog *log.Logger
	verbose  bool
)

func EnableDebug() {
	verbose = true
	debugLog = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
}

func Debugf(format string, args ...interface{}) {
	if verbose {
		debugLog.Output(2, fmt.Sprintf(format, args...))
	}
}

func IsVerbose() bool {
	return verbose
}

func Infof(format string, args ...interface{}) { log.Printf(format, args...) }

// SafeGo keeps a transport worker panic from killing the VPN process.
func SafeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PANIC] recovered in %s: %v", name, r)
			}
		}()
		fn()
	}()
}
