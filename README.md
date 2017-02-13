# cfbypass

Golang port of Anorov's cloudflare-scrape (https://github.com/Anorov/cloudflare-scrape)

Uses parts of go-cfscrape (https://github.com/sammy007/go-cfscrape) - Specifically, the copy header functions and regex paths.

Has 3 functions:
+ *GetTokens(url, useragent, iptype)* returns a slice containing the cookies required to bypass the IUAM page for a certain url given a certain useragent and ip family, either "4" or "6". Leaving the iptype empty as "", will use the default configuration by your system and if that fails, switch to the other family.
+ *IsRestricted(url)* determines if a response suggests that a url is using Cloudflare protection
+ *GetCurlString(url, useragent, iptype)* returns a string to use with command line curl

I wrote this because Anorov's library lacked forced ipv6 or ipv4 resolution (which I needed) and also appeared difficult to do in Python.
