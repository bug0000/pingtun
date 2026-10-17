//go:build android

package main

/*
#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"net/netip"
	"sync"

	"github.com/bug0000/pingtun/internal/carrier"
	"github.com/bug0000/pingtun/internal/engine"
	"github.com/bug0000/pingtun/internal/mobileprofile"
)

var state struct {
	sync.Mutex
	current *engine.Engine
}

//export ptStart
func ptStart(fd C.int, profile *C.char) *C.char {
	state.Lock()
	defer state.Unlock()
	if state.current != nil {
		return C.CString("VPN engine is already running")
	}
	p, err := mobileprofile.Decode([]byte(C.GoString(profile)))
	if err != nil {
		return C.CString(err.Error())
	}
	t, err := engine.NewFDTUN(int(fd), p.Config.MTU)
	if err != nil {
		return C.CString(err.Error())
	}
	remote := netip.MustParseAddr(p.Config.ServerIP)
	e, err := engine.Start(p.Config, t, func() (carrier.EchoSocket, error) {
		return carrier.ListenPing(remote, func(fd int) error {
			if C.pt_protect_socket(C.int(fd)) == 0 {
				return errors.New("VPN socket protection failed")
			}
			return nil
		})
	})
	if err != nil {
		return C.CString("ICMP VPN could not start. Check network permission and ping-socket availability.")
	}
	state.current = e
	return nil
}

//export ptStop
func ptStop() {
	state.Lock()
	defer state.Unlock()
	if state.current != nil {
		state.current.Close()
		state.current = nil
	}
}

//export ptSnapshot
func ptSnapshot() *C.char {
	state.Lock()
	defer state.Unlock()
	if state.current == nil {
		return C.CString("{}")
	}
	b, _ := json.Marshal(state.current.Snapshot())
	return C.CString(string(b))
}

//export ptInspect
func ptInspect(profile *C.char) *C.char {
	p, err := mobileprofile.Decode([]byte(C.GoString(profile)))
	if err != nil {
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(b))
	}
	b, _ := json.Marshal(p.Info())
	return C.CString(string(b))
}

//export ptProbe
func ptProbe() *C.char {
	s, err := carrier.ListenPing(netip.MustParseAddr("127.0.0.1"), nil)
	if err != nil {
		return C.CString(err.Error())
	}
	s.Close()
	return nil
}
func main() {}
