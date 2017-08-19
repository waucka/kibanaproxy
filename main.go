package main

import (
	"io/ioutil"
	"fmt"
	"net/url"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"time"
	"regexp"
	"bytes"
	"errors"
	"encoding/json"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"gopkg.in/yaml.v2"
	"github.com/go-redis/redis"
	"github.com/gobwas/glob"
)

var (
	config *Config = nil
	redisConn *redis.Client = nil
	hostPort string
	rejector *httptest.Server = nil

	indexWhitelist = map[string]bool{
		".kibana": true,
		".kibana-devnull": true,
	}

	headWhitelist = map[string]bool{
		"/": true,
	}
	getWhitelist = map[string]bool{
		"/_nodes": true,
		"/_cluster/health/.kibana": true,
	}
	postWhitelist = map[string]bool{
	}

	ErrNoMatch = errors.New("Nothing matched")
)

type RedisConfig struct {
	Network string `yaml:"network"`
	Addr string `yaml:"addr"`
	Password string `yaml:"password"`
	DB int `yaml:"db"`
}

type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	LogLevel string `yaml:"log_level"`
	AuthHeader string `yaml:"auth_header"`
	Redis *RedisConfig `yaml:"redis"`
	Elasticsearch *ElasticConfig `yaml:"elasticsearch"`
	Overrides map[string][]string `yaml:"overrides"`
}

type PreProcessor func([]string, *http.Request) bool
type PostProcessor func(*http.Request, *http.Response) error

type IndexSpec struct {
	Indexes []string `json:"index"`
}

type PathPattern struct {
	Method string
	Pattern *regexp.Regexp
	RoundTripper http.RoundTripper
	PreProc PreProcessor
	PostProc PostProcessor
}

func NewPathPattern(method string, pattern *regexp.Regexp, preProc PreProcessor, postProc PostProcessor) *PathPattern {
	return &PathPattern{
		Method: method,
		Pattern: pattern,
		RoundTripper: http.DefaultTransport,
		PreProc: preProc,
		PostProc: postProc,
	}
}

func (self *PathPattern) HandleRequest(req *http.Request) (ok bool, resp *http.Response, err error) {
	if self.Method != req.Method {
		return false, nil, nil
	}
	if !self.Pattern.MatchString(req.URL.Path) {
		//log.Debugf("This rule does not apply to %s", reqPath)
		return false, nil, nil
	}
	//log.Debugf("Found a pattern to use for %s", reqPath)
	matches := self.Pattern.FindStringSubmatch(req.URL.Path)

	if !self.PreProc(matches, req) {
		return false, nil, nil
	}

	addAuth(req)

	resp, err = self.RoundTripper.RoundTrip(req)
	if err != nil {
		log.Error(err.Error())
		return false, nil, err
	}

	if self.PostProc != nil {
		err = self.PostProc(req, resp)
		if err != nil {
			log.Error(err.Error())
			return true, nil, err
		}
	}

	log.Debugf("Content Length: %d", resp.ContentLength)

	return true, resp, nil
}

type ElasticConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Host string `yaml:"host"`
	Port int `yaml:"port"`
	Scheme string `yaml:"scheme"`
}

type Proxy struct {
	Patterns []*PathPattern
}

func (self *Proxy) RoundTrip(req *http.Request) (*http.Response, error) {
	if isWhitelisted(req) {
		addAuth(req)
		return http.DefaultTransport.RoundTrip(req)
	} else {
		for _, pattern := range self.Patterns {
			allow, resp, err := pattern.HandleRequest(req)
			if err != nil {
				return resp, err
			}
			if allow {
				log.Debugf("Request: %s %s allowed", req.Method, req.URL)
				
				if req.Method == "POST" {
					argh, _ := httputil.DumpRequestOut(req, true)
					fmt.Println("########################################")
					fmt.Println(string(argh))
					fmt.Println("########################################")
				}
				return resp, nil
			}
		}
	}

	log.Debugf("Request: %s %s rejected", req.Method, req.URL)
	var err error
	req.URL, err = url.Parse(rejector.URL)
	if err != nil {
		return nil, err
	}
	return http.DefaultTransport.RoundTrip(req)
}

type esShards struct {
	Total int `json:"total"`
	Successful int `json:"successful"`
	Failed int `json:"failed"`
}

type esIndexHit struct {
	Index string `json:"_index"`
	Type string `json:"_type"`
	Id string `json:"_id"`
	Score int `json:"_score"`
}

type esIndexHitList struct {
	Total int `json:"total"`
	MaxScore int `json:"max_score"`
	Hits []esIndexHit `json:"hits"`
}

type esIndexSearchResult struct {
	Took int `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards esShards `json:"_shards"`
	Hits esIndexHitList `json:"hits"`
}

type esIndexPatternSource struct {
	Title string `json:"title"`
	TitleFieldName string `json:"timeFieldName"`
	Fields string `json:"fields"`
}

type esIndexPatternHit struct {
	Index string `json:"_index"`
	Type string `json:"_type"`
	Id string `json:"_id"`
	Score float32 `json:"_score"`
	//Source esIndexPatternSource `json:"_source"`
}

type esIndexPatternHitList struct {
	Total int `json:"total"`
	MaxScore float32 `json:"max_score"`
	Hits []esIndexPatternHit `json:"hits"`
}

type esIndexPatternSearchResult struct {
	Took int `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards esShards `json:"_shards"`
	Hits esIndexPatternHitList `json:"hits"`
}

func main() {
	app := cli.NewApp()
	app.Name = "kibanaproxy"
	app.Usage = "Protect access to logs"
	app.Version = "1.0"
	app.Action = runServer
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Value: "/etc/kibanaproxy.yaml",
			Usage: "Configuration file",
		},
	}
	app.Run(os.Args)
}

func runServer(c *cli.Context) {
	configPath := c.String("config")
	configBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		panic(err)
	}

	switch config.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "panic":
		log.SetLevel(log.PanicLevel)
	default:
		log.SetLevel(log.ErrorLevel)
	}

	hostPort = fmt.Sprintf("%s:%d", config.Elasticsearch.Host, config.Elasticsearch.Port)
	rejector = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Forbidden"))
	}))
	redisConn = redis.NewClient(&redis.Options{
		Network: config.Redis.Network,
		Addr: config.Redis.Addr,
		Password: config.Redis.Password,
		DB: config.Redis.DB,
	})

	_, err = redisConn.Ping().Result()
	if err != nil {
		panic(err)
	}
	s := &http.Server{
		Addr: config.ListenAddr,
		Handler: NewProxy(redisConn),
		ReadTimeout: 120 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Fatal(s.ListenAndServe())
}

func isWhitelisted(req *http.Request) bool{
	if req.Method == "HEAD" {
		allowed, ok := headWhitelist[req.URL.Path]
		return allowed && ok
	} else if req.Method == "GET" {
		allowed, ok := getWhitelist[req.URL.Path]
		return allowed && ok
	} else if req.Method == "POST" {
		allowed, ok := postWhitelist[req.URL.Path]
		return allowed && ok
	}

	return false
}

func addAuth(req *http.Request) {
	req.SetBasicAuth(
		config.Elasticsearch.Username,
		config.Elasticsearch.Password,
	)
	newUrl := &url.URL{
		Scheme: config.Elasticsearch.Scheme,
		Opaque: req.URL.Opaque,
		Host: hostPort,
		User: req.URL.User,
		Path: req.URL.Path,
		RawPath: req.URL.RawPath,
		ForceQuery: req.URL.ForceQuery,
		RawQuery: req.URL.RawQuery,
		Fragment: req.URL.Fragment,
	}
	req.URL = newUrl
}

func searchOverrides(username string, index string) bool {
	ovrList, ok := config.Overrides[username]
	if !ok {
		return false
	}
	for _, ovr := range ovrList {
		if ovr == "*" {
			return true
		}
		match, err := regexp.MatchString(ovr, index)
		if err == nil && match {
			return true
		}
	}
	return false
}

func checkIndex(username, idx string) bool {
	log.Debugf("Is %s whitelisted?", idx)
	whitelisted, ok := indexWhitelist[idx]
	if whitelisted && ok {
		return true
	}

	if searchOverrides(username, idx) {
		return true
	}

	key := fmt.Sprintf("patterns:%s", username)
	members, err := redisConn.SMembers(key).Result()
	if err != nil {
		log.Error(err.Error())
		return false
	}
	log.Debugf("WTF? %#v", members)

	for _, pattern := range members {
		log.Debugf("Checking %s against %s", idx, pattern)
		g, err := glob.Compile(pattern)
		if err != nil {
			log.Errorf("Invalid pattern in %s: %s", key, pattern)
			continue
		}
		if g.Match(idx) {
			return true
		}
	}
	return false
}

func checkIndexPattern(username, idx string) bool {
	if searchOverrides(username, idx) {
		return true
	}

	key := fmt.Sprintf("patterns:%s", username)
	member, err := redisConn.SIsMember(key, idx).Result()
	if err != nil {
		log.Error(err.Error())
		return false
	}
	return member
}

func checkIndexFromMatches(matches []string, req *http.Request) bool {
	username := req.Header.Get(config.AuthHeader)
	log.Debugf("Username: %s", username)
	if len(matches) < 2 {
		return false
	}
	idx := matches[1]
	return checkIndex(username, idx)
}

func ProcessGetMappingSource(matches []string, req *http.Request) bool {
	return checkIndexFromMatches(matches, req)
}

func ProcessGetMapping(matches []string, req *http.Request) bool {
	return checkIndexFromMatches(matches, req)
}

func ProcessConfigSearch(matches []string, req *http.Request) bool {
	return checkIndexFromMatches(matches, req)
}

func ProcessConfigGet(matches []string, req *http.Request) bool {
	return checkIndexFromMatches(matches, req)
}

func ProcessIndexPatternGet([]string, *http.Request) bool {
	return true
}

//TODO: Find a way to avoid showing patterns to users who can't use them
/*func PostProcessIndexPatternGet(req *http.Request, resp *http.Response) error {
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err.Error())
		return err
	}
	err = resp.Body.Close()
	if err != nil {
		log.Error(err.Error())
		return err
	}
	var res esIndexPatternSearchResult
	err = json.Unmarshal(b, &res)
	if err != nil {
		log.Error(err.Error())
		return err
	}
	//log.Debug(string(b))
	var maxScore float32 = 0.0
	okIdx := make([]esIndexPatternHit, 0)
	username := req.Header.Get(config.AuthHeader)
	for _, idx := range res.Hits.Hits {
		if checkIndexPattern(username, idx.Id) {
			okIdx = append(okIdx, idx)
			if maxScore < idx.Score {
				maxScore = idx.Score
			}
		} else {
			log.Debugf("Can't see %s!", idx.Id)
		}
	}
	res.Hits.MaxScore = maxScore
	res.Hits.Total = len(okIdx)
	res.Hits.Hits = okIdx
	newBodyBytes, err := json.Marshal(res)
	if err != nil {
		log.Error(err.Error())
		return err
	}
	fmt.Println("########################################")
	fmt.Println(string(newBodyBytes))
	fmt.Println("########################################")
	resp.Body = ioutil.NopCloser(bytes.NewReader(newBodyBytes))
	resp.ContentLength = int64(len(newBodyBytes))
	return nil
}*/

type esMgetDoc struct {
	Index string `json:"_index"`
	Type string `json:"_type"`
	Id string `json:"_id"`
}

type esMgetRequest struct {
	Docs []esMgetDoc `json:"docs"`
}

func parseBody(body []byte, splitlines bool, jsonThingy interface{}) error {
	if splitlines {
		bodyLines := bytes.Split(body, []byte("\n"))
		for _, line := range bodyLines {
			err := json.Unmarshal([]byte(line), jsonThingy)
			if err == nil {
				return nil
			}
		}
	} else {
		return json.Unmarshal(body, jsonThingy)
	}
	return ErrNoMatch
}

func ProcessMget(matches []string, req *http.Request) bool {
	if req.Body == nil {
		return false
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		req.Body = nil
		return false
	} else {
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
	}
	username := req.Header.Get(config.AuthHeader)

	var mget esMgetRequest
	err = parseBody(body, false, &mget)
	for _, doc := range mget.Docs {
		if !checkIndex(username, doc.Index) {
			return false
		}
	}

	return true
}

func ProcessMsearch(matches []string, req *http.Request) bool {
	if req.Body == nil {
		return false
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		req.Body = nil
		return false
	} else {
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
	}
	username := req.Header.Get(config.AuthHeader)

	var idxList IndexSpec
	err = parseBody(body, true, &idxList)
	for _, idx := range idxList.Indexes {
		log.Debugf("Checking %s", idx)
		if !checkIndex(username, idx) {
			return false
		}
	}

	return true
}

func ProcessSearchScroll([]string, *http.Request) bool {
	// TODO
	return false
}

func ProcessSearch(matches []string, req *http.Request) bool {
	return checkIndexFromMatches(matches, req)
}

func ProcessFieldStats(matches []string, req *http.Request) bool {
	return checkIndexFromMatches(matches, req)
}

func NewProxy(redisConn *redis.Client) *httputil.ReverseProxy {
	pathPatterns := [...]*PathPattern{
		NewPathPattern("GET", regexp.MustCompile("/([^/]+)/_mapping/\\*/field/_source"), ProcessGetMappingSource, nil),
		NewPathPattern("GET", regexp.MustCompile("/([^/]+)/_mapping/field/\\*"), ProcessGetMapping, nil),
		NewPathPattern("POST", regexp.MustCompile("/([^/]+)/config/_search"), ProcessConfigSearch, nil),
		NewPathPattern("POST", regexp.MustCompile("/([^/]+)/config/[0-9].*"), ProcessConfigGet, nil),
		NewPathPattern("POST", regexp.MustCompile("/.kibana/index-pattern/_search"), ProcessIndexPatternGet, nil),
		NewPathPattern("POST", regexp.MustCompile("/_mget"), ProcessMget, nil),
		NewPathPattern("POST", regexp.MustCompile("/_msearch"), ProcessMsearch, nil),
		NewPathPattern("POST", regexp.MustCompile("/_search/scroll"), ProcessSearchScroll, nil),
		NewPathPattern("POST", regexp.MustCompile("/([^/]+)/_search"), ProcessSearch, nil),
		NewPathPattern("POST", regexp.MustCompile("/([^/]+)/_field_stats"), ProcessFieldStats, nil),
	}

	proxy := &Proxy{
		Patterns: pathPatterns[:],
	}

	return &httputil.ReverseProxy{
		Director: func(*http.Request) {},
		Transport: proxy,
		FlushInterval: 0,
		ErrorLog: nil,
		BufferPool: nil,
		// Not present in Go 1.7?
		// ModifyResponse: nil,
	}
}
