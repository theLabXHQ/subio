package resolver

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// procNetUDP is a variable so a test can point it at a table of its own.
var procNetUDP = []string{"/proc/net/udp", "/proc/net/udp6"}

// dropsForPort returns the kernel's discard count for a local UDP port, and
// whether a line for it was found at all.
func dropsForPort(port uint16) (int64, bool) {
	if port == 0 {
		return 0, false
	}
	for _, path := range procNetUDP {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		header := true
		for sc.Scan() {
			if header {
				header = false
				continue
			}

			fields := strings.Fields(sc.Text())
			if len(fields) < 13 {
				continue
			}
			colon := strings.LastIndexByte(fields[1], ':')
			if colon < 0 {
				continue
			}
			p, err := strconv.ParseUint(fields[1][colon+1:], 16, 16)
			if err != nil || uint16(p) != port {
				continue
			}
			n, err := strconv.ParseInt(fields[12], 10, 64)
			if err != nil {
				continue
			}
			_ = f.Close()
			return n, true
		}
		_ = f.Close()
	}
	return 0, false
}

// localPort pulls the port out of "ip:port", including the bracketed IPv6
// form.
func localPort(addr string) uint16 {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return 0
	}
	p, err := strconv.ParseUint(addr[i+1:], 10, 16)
	if err != nil {
		return 0
	}
	return uint16(p)
}

// noteKernelDrops records what this worker's socket lost, before it closes.
func (w *worker) noteKernelDrops() {
	if w.conn == nil {
		return
	}
	n, ok := dropsForPort(localPort(w.conn.LocalAddr().String()))
	if !ok {
		return
	}
	w.r.dropsKnown.Store(true)
	if n > 0 {
		w.r.drops.Add(n)
	}
}

// KernelDrops reports how many datagrams this machine discarded before the
// resolver could read them, and whether the figure is available.
func (r *Resolver) KernelDrops() (int64, bool) {
	return r.drops.Load(), r.dropsKnown.Load()
}
