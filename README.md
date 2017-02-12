# cfbypass

Golang port of Anorov's cloudflare-scrape (https://github.com/Anorov/cloudflare-scrape)

Uses parts of go-cfscrape (https://github.com/sammy007/go-cfscrape)

Specifically, the copy header functions and also regex paths.

Has 3 functions:

*GetTokens(url, useragent)* returns a slice containing the cookies required to bypass the IUAM page for a certain url given a certain useragent
*IsRestricted(response)* determines if a response suggests that a url is using Cloudflare protection
*GetCurlString(url, useragent)* returns a string to use with command line curl
