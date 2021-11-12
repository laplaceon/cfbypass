package cfbypass

import (
	"context"
	"fmt"
	"github.com/robertkrimen/otto"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)
const (
	pList    = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"
	defaultP = ""
)
var (
	client = &http.Client{}
	vm = otto.New()
)
func randomp() string {
	// Retrieve the bytes of the user-agent list
	pxlist, err := httpclient.GetString(pList)
	if err != nil {
		return defaultP
	}

	// Split all user-agents into a slice and return a
	// single random one
	ua := strings.Split(pxlist, "\n")
	if len(ua) == 0 {
		return defaultP
	}
	return ua[rand.Intn(len(ua))]
}
func copyStrSlice(in []string) []string {
	r := make([]string, 0, len(in))
	r = append(r, in...)
	return r
}

func copyHeader(header http.Header) http.Header {
	m := make(map[string][]string)

	for k, v := range header {
		m[k] = copyStrSlice(v)
	}

	return m
}

func GetString(url string, ua string, ipFamily string) string {
	cookies := GetTokens(url, ua, ipFamily)
	
	if cookies != nil {
		cookiesString := ""
		numCookies := len(cookies)
		for i := 0; i < numCookies; i++ {
			cookie := cookies[i]
			cookiesString += cookie.Name + "=" + cookie.Value + "; "
		}
		curlString := fmt.Sprintf(`curl %s -b "%s" -A "%s"`, url, cookiesString, ua)
		if ipFamily == "4" {
			curlString += " -4"
		}
		if ipFamily == "6" {
			curlString += " -6"
		}
		return curlString
	}
	
	return ""
}

func GetTokens(url string, ua string, ipFamily string) []*http.Cookie {
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	
	switch ipFamily {
		case "6":
			ipv6Transport := &http.Transport{
				Proxy: http.ProxyURL(randomUA()),
				MaxIdleConns: 100,
				IdleConnTimeout: 90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}
			ipv6Transport.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp6", addr)
			}
			client.Transport = ipv6Transport
			fmt.Println("Forcing ipv6")
		case "4":
			ipv4Transport := &http.Transport{
				Proxy: http.ProxyURL(randomUA()),
				MaxIdleConns: 100,
				IdleConnTimeout: 90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}
			ipv4Transport.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp4", addr)
			}
			client.Transport = ipv4Transport
			fmt.Println("Forcing ipv4")
		case "":
		default:
			fmt.Println("Unknown ip family entered. Using default.")
	}
	
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", ua)

	res, resErr := client.Do(req)
	if resErr != nil {
		fmt.Println("There was an error getting a response")
		return nil
	}
	
	defer res.Body.Close()
	
	if isRestricted(res) {
		return bypass(req, res)
	}
	
	return nil
}

func bypass(req *http.Request, r *http.Response) []*http.Cookie {
	body, _ := ioutil.ReadAll(r.Body)
	time.Sleep(8 * time.Second)
	js := extractJavascript(body, req.URL.Host)
	answer := strings.TrimSpace(parseChallenge(js))

	vc, _ := regexp.Compile(`name="jschl_vc" value="(\w+)"`)
	pass, _ := regexp.Compile(`name="pass" value="(.+?)"`)
	
	vcMatch := vc.FindSubmatch(body)
	passMatch := pass.FindSubmatch(body)
	
	if !(len(vcMatch) == 2 && len(passMatch) == 2) {
		return nil
	}
	
	url, _ := url.Parse(fmt.Sprintf("%s://%s/cdn-cgi/l/chk_jschl", req.URL.Scheme, req.URL.Host))
	
	query := url.Query()
	query.Set("jschl_vc", string(vcMatch[1]))
	query.Set("pass", string(passMatch[1]))
	query.Set("jschl_answer", answer)
	url.RawQuery = query.Encode()
	
	
	nReq, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		panic(err)
	}

	nReq.Header = copyHeader(r.Header)
	nReq.Header.Set("Referer", req.URL.String())
	nReq.Header.Set("User-Agent", req.Header.Get("User-Agent"))
	
	_, resErr := client.Do(nReq)
	if resErr != nil {
		panic(resErr)
	}
	
	cookies := client.Jar.Cookies(req.URL)
	
	return cookies
}

func parseChallenge(js string) string {
	result, _ := vm.Run(js)
	return result.String()
}

func extractJavascript(body []byte, domain string) string {
	r1, _ := regexp.Compile(`setTimeout\(function\(\){\s+(var s,t,o,p,b,r,e,a,k,i,n,g,f.+?\r?\n[\s\S]+?a\.value =.+?)\r?\n`)
	r2, _ := regexp.Compile(`a\.value = (.+ \+ t\.length)`)
	r3, _ := regexp.Compile(`\s{3,}[a-z](?: = |\.).+`)
	r4, _ := regexp.Compile(`[\n\\']`)
	
	r1Match := r1.FindSubmatch(body)
	
	if len(r1Match) != 2 {
		return ""
	}
	
	js := string(r1Match[1])
	js = r2.ReplaceAllString(js, "$1")
	js = r3.ReplaceAllString(js, "")
	
	js = strings.Replace(js, "t.length", fmt.Sprintf("%d", len(domain)), -1)
	
	js = r4.ReplaceAllString(js, "")
	
	lastSemicolon := strings.LastIndex(js, ";")
	if lastSemicolon >= 0 {
		js = js[:lastSemicolon]
	}
	
	return js
}

func IsRestricted(url string) bool {
	req, _ := http.NewRequest("GET", url, nil)
	res, _ := client.Do(req)
	return isRestricted(res)
}

func isRestricted(r *http.Response) bool {
	if r.StatusCode == 503 && strings.Contains(r.Header.Get("Server"), "cloudflare") {
		return true
	}
	return false
}
