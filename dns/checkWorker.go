package dns

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	dnslib "github.com/miekg/dns"
)

const (
	defaultTimeout       = 500
	defaultCheckInterval = 30
	defaultTryTimes      = 3
)

// CheckWorker checks service status over layer 4.
type CheckWorker struct {
	dns    *Service
	domain string
	ips    []string
	port   int

	wg sync.WaitGroup

	closing chan struct{}
}

// New Check Worker
func NewCheckWork(domain string, ips []string, port int, s *Service) (*CheckWorker, error) {
	return &CheckWorker{
		domain:  domain,
		dns:     s,
		ips:     ips,
		port:    port,
		closing: make(chan struct{}),
	}, nil
}

// Run Check Worker
func (w *CheckWorker) Run() {
	w.dns.logger.Warningf("start health check worker:%s", w.domain)
	ticker := time.NewTicker(time.Duration(defaultCheckInterval) * time.Second)
	for {
		select {
		case <-ticker.C:
			var res []dnslib.RR
			for _, ip := range w.ips {
				w.wg.Add(1)
				go func(ip string) {
					defer w.wg.Add(-1)
					addr := fmt.Sprintf("%s:%d", ip, w.port)
					for i := 0; i <= defaultTryTimes; i++ {
						conn, err := net.DialTimeout("tcp", addr, time.Duration(defaultTimeout)*time.Millisecond)
						if err != nil {
							w.dns.logger.Infof("check health failed:%s", err)
							time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
							continue
						}
						conn.Close()
						rr, err := dnslib.NewRR(fmt.Sprintf("%s A %s", w.domain, ip))
						if err == nil {
							rr.Header().Ttl = 60
							res = append(res, rr)
							break
						}
					}
				}(ip)
			}
			w.wg.Wait()
			w.dns.mu.Lock()
			// update health status if exist in cache
			if _, ok := w.dns.cache[w.domain]; ok {
				w.dns.cache[w.domain] = res
				w.dns.mu.Unlock()
			} else {
				w.dns.mu.Unlock()
				// exit if not in cache
				return
			}
		case <-w.closing:
			return
		}
	}
}

// Close closes Worker
func (w *CheckWorker) Close() {
	w.dns.logger.Warningf("close health check worker:%s", w.domain)
	close(w.closing)
}

// Check checks health status
func (w *CheckWorker) Check() []dnslib.RR {
	var res []dnslib.RR
	for _, ip := range w.ips {
		w.wg.Add(1)
		go func(ip string) {
			defer w.wg.Add(-1)
			addr := fmt.Sprintf("%s:%d", ip, w.port)
			conn, err := net.DialTimeout("tcp", addr, time.Duration(defaultTimeout)*time.Millisecond)
			if err != nil {
				w.dns.logger.Infof("check health failed:%s", err)
				return
			}
			conn.Close()
			rr, err := dnslib.NewRR(fmt.Sprintf("%s A %s", w.domain, ip))
			if err == nil {
				rr.Header().Ttl = 60
				res = append(res, rr)
			}

		}(ip)
	}
	w.wg.Wait()
	return res
}
