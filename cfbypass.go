package cfbypass

import (
	"fmt"
	"github.com/robertkrimen/otto"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"strconv"
	"time"
)

var (
	client *http.Client
	vm = otto.New()
)

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

func GetCurlString(url string, ua string) string {
	cookies := GetTokens(url, ua)
	
	if cookies != nil {
		cookiesString := ""
		numCookies := len(cookies)
		for i := 0; i < numCookies; i++ {
			cookie := cookies[i]
			cookiesString += cookie.Name + "=" + cookie.Value + "; "
		}
		return fmt.Sprintf(`curl %s -b "%s" -A "%s"`, url, cookiesString, ua)
	}
	
	return ""
}

func GetTokens(url string, ua string) []*http.Cookie {
	jar, _ := cookiejar.New(nil)
	client = &http.Client{Jar: jar,}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", ua)

	res, resErr := client.Do(req)
	if resErr != nil {
		panic(resErr)
	}
	defer res.Body.Close()
	
	if IsRestricted(res) {
		return bypass(req, res)
	}
	
	return nil
}

func bypass(req *http.Request, r *http.Response) []*http.Cookie {
	body, _ := ioutil.ReadAll(r.Body)
	time.Sleep(5 * time.Second)
	js := extractJavascript(body)
	answer := strings.TrimSpace(parseChallenge(js))
	
	resultI, _ := strconv.Atoi(answer)

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
	query.Set("jschl_answer", fmt.Sprintf("%d", resultI + len(req.URL.Host)))
	query.Set("pass", string(passMatch[1]))
	url.RawQuery = query.Encode()
	
	nReq, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		panic(err)
	}

	nReq.Header = copyHeader(req.Header)
	nReq.Header.Set("Referer", req.URL.String())
	
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

func extractJavascript(body []byte) string {
	r1, _ := regexp.Compile(`setTimeout\(function\(\){\s+(var s,t,o,p,b,r,e,a,k,i,n,g,f.+?\r?\n[\s\S]+?a\.value =.+?)\r?\n`)
	r2, _ := regexp.Compile(`a\.value = (parseInt\(.+?\)) \+ .+?;`)
	r3, _ := regexp.Compile(`\s{3,}[a-z](?: = |\.).+`)
	r4, _ := regexp.Compile(`[\n\\']`)
	
	r1Match := r1.FindSubmatch(body)
	
	if len(r1Match) != 2 {
		return ""
	}
	
	js := string(r1Match[1])
	js = r2.ReplaceAllString(js, "$1")
	js = r3.ReplaceAllString(js, "")
	js = r4.ReplaceAllString(js, "")
	
	lastSemicolon := strings.LastIndex(js, ";")
	if lastSemicolon >= 0 {
		js = js[:lastSemicolon]
	}
	
	return js
}

func IsRestricted(r *http.Response) bool {
	if r.StatusCode == 503 {
		return true
	}
	return false
}