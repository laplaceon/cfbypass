package cfbypass

import "testing"

func TestIsRestricted(t *testing.T) {
	var rs []bool
	
	urls := []string{"http://kissmanga.com", "http://google.com"}
	
	for i := 0; i < len(urls); i++ {
		rs = append(rs, IsRestricted(urls[i]))
	}
	
	if !(rs[0] && !rs[1]) {
		t.Error("IsRestricted incorrectly recognizing pages")
	}
}