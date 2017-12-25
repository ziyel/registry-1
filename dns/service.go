package dns

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lodastack/log"
	"github.com/lodastack/registry/config"
	"github.com/lodastack/registry/httpd"
	"github.com/lodastack/registry/model"
	"github.com/lodastack/registry/tree"

	dnslib "github.com/miekg/dns"
)

const (
	resType       = "machine"
	domainSuffix  = "."
	domainPrefix  = "_"
	matchIPPrefix = "10."
	purgeInterval = 2
)

// Service provides DNS service.
type Service struct {
	enable bool
	port   int
	conf   config.DNSConfig
	server *dnslib.Server

	mu    sync.RWMutex
	cache map[string][]dnslib.RR

	wmu        sync.RWMutex
	checkWorks map[string]*CheckWorker

	tree tree.TreeMethod

	logger *log.Logger
}

// New DNS service
func New(c config.DNSConfig, cluster httpd.Cluster) (*Service, error) {
	tree, err := tree.NewTree(cluster)
	if err != nil {
		log.Errorf("init tree fail: %s", err.Error())
		return nil, err
	}
	return &Service{
		enable:     c.Enable,
		port:       c.Port,
		conf:       c,
		server:     &dnslib.Server{Addr: ":" + strconv.Itoa(c.Port), Net: "udp"},
		cache:      make(map[string][]dnslib.RR),
		checkWorks: make(map[string]*CheckWorker),
		tree:       tree,

		logger: log.New("INFO", "dns", model.LogBackend),
	}, nil
}

// Start DNS service
func (s *Service) Start() error {
	if !s.enable {
		s.logger.Info("DNS module not enable")
		return nil
	}
	// attach request handler func
	dnslib.HandleFunc("loda.", s.handleDNSRequest)

	// start server
	s.logger.Infof("Starting DNS module at %d", s.port)
	go func() {
		err := s.server.ListenAndServe()
		if err != nil {
			s.logger.Errorf("Failed to start DNS service: %s", err.Error())
		}
	}()
	go s.purgeCache()
	return nil
}

// Close DNS service
func (s *Service) Close() error {
	return s.server.Shutdown()
}

func (s *Service) parseQuery(m *dnslib.Msg) {
	machines := func(s *Service, ns string, domain string) []dnslib.RR {
		var res []dnslib.RR
		var port int
		var err error
		// port handler
		if strings.HasPrefix(ns, domainPrefix) {
			portns := strings.SplitAfterN(ns, domainSuffix, 2)
			if len(portns) < 2 {
				return res
			}
			ns = portns[1]
			port, err = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(portns[0], domainPrefix), domainSuffix))
			if err != nil {
				s.logger.Errorf("parse port to int failed: %s %s", err, portns[0])
				return res
			}
		}
		resList, err := s.tree.GetResourceList(ns, resType)
		if err != nil {
			s.logger.Errorf("DNS search failed: %s", err)
			return res
		}
		if resList == nil {
			return res
		}

		var iparray []string
		for _, r := range *resList {
			if ips, ok := r[model.IpProp]; ok {
				iparray = append(iparray, strings.Split(ips, ",")...)
			}
		}
		uniqIPArray := removeRepByMap(iparray)
		// health status check
		if port != 0 {
			// health status do not support more than 200
			if len(uniqIPArray) > 200 {
				return res
			}
			w, err := NewCheckWork(domain, uniqIPArray, port, s)
			if err != nil {
				s.logger.Errorf("new check worker failed:%s", err)
				return res
			}
			res = w.Check()
			s.wmu.Lock()
			s.checkWorks[domain] = w
			go w.Run()
			s.wmu.Unlock()
		} else {
			for _, ip := range uniqIPArray {
				rr, err := dnslib.NewRR(fmt.Sprintf("%s A %s", domain, ip))
				if err == nil {
					rr.Header().Ttl = 60
					res = append(res, rr)
				}
			}
		}

		s.mu.Lock()
		s.cache[domain] = res
		s.mu.Unlock()
		return res
	}

	for _, q := range m.Question {
		switch q.Qtype {
		case dnslib.TypeA:
			s.logger.Infof("Query for %s", q.Name)
			ns := strings.TrimSuffix(q.Name, domainSuffix)
			s.mu.RLock()
			answer, ok := s.cache[q.Name]
			s.mu.RUnlock()
			if ok {
				m.Answer = answer
				return
			}
			m.Answer = machines(s, ns, q.Name)
			return
		}
	}
}

func (s *Service) handleDNSRequest(w dnslib.ResponseWriter, r *dnslib.Msg) {
	m := new(dnslib.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dnslib.OpcodeQuery:
		s.parseQuery(m)
	}

	w.WriteMsg(m)
}

func (s *Service) purgeCache() {
	ticker := time.NewTicker(time.Duration(purgeInterval) * time.Minute)
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			s.cache = make(map[string][]dnslib.RR)
			s.mu.Unlock()
		}
	}
}

func removeRepByMap(slc []string) []string {
	var result []string
	tempMap := map[string]byte{}
	for _, e := range slc {
		//IP filter
		if e == "" || !strings.HasPrefix(e, matchIPPrefix) {
			continue
		}
		l := len(tempMap)
		tempMap[e] = 0
		if len(tempMap) != l {
			result = append(result, e)
		}
	}
	return result
}
