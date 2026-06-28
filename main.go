package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

func main() {

	var domains []string

	var dates bool
	flag.BoolVar(&dates, "dates", false, "show date of fetch in the first column")

	var noSubs bool
	flag.BoolVar(&noSubs, "no-subs", false, "don't include subdomains of the target domain")

	var getVersionsFlag bool
	flag.BoolVar(&getVersionsFlag, "get-versions", false, "list URLs for crawled versions of input URL(s)")

	flag.Parse()

	if flag.NArg() > 0 {
		// fetch for a single domain
		domains = []string{flag.Arg(0)}
	} else {

		// fetch for all domains from stdin
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			domains = append(domains, sc.Text())
		}

		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}

	// get-versions mode
	if getVersionsFlag {

		for _, u := range domains {
			versions, err := getVersions(u)
			if err != nil {
				continue
			}
			fmt.Println(strings.Join(versions, "\n"))
		}

		return
	}

	fetchFns := []fetchFn{
		getWaybackURLs,
		getCommonCrawlURLs,
		getVirusTotalURLs,
	}

	for _, domain := range domains {

		var wg sync.WaitGroup
		wurls := make(chan wurl)

		for _, fn := range fetchFns {
			wg.Add(1)
			fetch := fn
			go func() {
				defer wg.Done()
				resp, err := fetch(domain, noSubs)
				if err != nil {
					return
				}
				for _, r := range resp {
					if noSubs && isSubdomain(r.url, domain) {
						continue
					}
					wurls <- r
				}
			}()
		}

		go func() {
			wg.Wait()
			close(wurls)
		}()

		seen := make(map[string]bool)
		for w := range wurls {
			if _, ok := seen[w.url]; ok {
				continue
			}
			seen[w.url] = true

			if dates {

				d, err := time.Parse("20060102150405", w.date)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to parse date [%s] for URL [%s]\n", w.date, w.url)
				}

				fmt.Printf("%s %s\n", d.Format(time.RFC3339), w.url)

			} else {
				fmt.Println(w.url)
			}
		}
	}

}

type wurl struct {
	date string
	url  string
}

type fetchFn func(string, bool) ([]wurl, error)

func getWaybackURLs(domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	params := url.Values{}
	params.Set("url", subsWildcard+domain+"/*")
	params.Set("output", "json")
	params.Set("collapse", "urlkey")

	res, err := httpClient.Get("https://web.archive.org/cdx/search/cdx?" + params.Encode())
	if err != nil {
		return []wurl{}, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return []wurl{}, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return []wurl{}, err
	}

	var wrapper [][]string
	err = json.Unmarshal(raw, &wrapper)
	if err != nil {
		return []wurl{}, err
	}

	out := make([]wurl, 0, len(wrapper))

	skip := true
	for _, urls := range wrapper {
		if skip {
			skip = false
			continue
		}
		if len(urls) < 3 {
			continue
		}
		out = append(out, wurl{date: urls[1], url: urls[2]})
	}

	return out, nil

}

func getCommonCrawlURLs(domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	params := url.Values{}
	params.Set("url", subsWildcard+domain+"/*")
	params.Set("output", "json")

	res, err := httpClient.Get("https://index.commoncrawl.org/CC-MAIN-2026-25-index?" + params.Encode())
	if err != nil {
		return []wurl{}, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return []wurl{}, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	sc := bufio.NewScanner(res.Body)

	out := make([]wurl, 0)

	for sc.Scan() {

		wrapper := struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}{}
		err = json.Unmarshal([]byte(sc.Text()), &wrapper)

		if err != nil {
			continue
		}

		out = append(out, wurl{date: wrapper.Timestamp, url: wrapper.URL})
	}

	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to scan Common Crawl response: %s\n", err)
	}

	return out, nil

}

func getVirusTotalURLs(domain string, noSubs bool) ([]wurl, error) {
	out := make([]wurl, 0)

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		return out, nil
	}

	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/urls?limit=40", url.PathEscape(domain)),
		nil,
	)
	if err != nil {
		return out, err
	}
	req.Header.Set("x-apikey", apiKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var wrapper struct {
		Data []struct {
			Attributes struct {
				URL string `json:"url"`
			} `json:"attributes"`
		} `json:"data"`
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&wrapper)
	if err != nil {
		return out, err
	}

	for _, u := range wrapper.Data {
		out = append(out, wurl{url: u.Attributes.URL})
	}

	return out, nil

}

func isSubdomain(rawUrl, domain string) bool {
	u, err := url.Parse(rawUrl)
	if err != nil {
		// we can't parse the URL so just
		// err on the side of including it in output
		return false
	}

	return strings.ToLower(u.Hostname()) != strings.ToLower(domain)
}

func getVersions(u string) ([]string, error) {
	out := make([]string, 0)

	params := url.Values{}
	params.Set("url", u)
	params.Set("output", "json")

	resp, err := httpClient.Get("https://web.archive.org/cdx/search/cdx?" + params.Encode())
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	r := [][]string{}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&r)
	if err != nil {
		return out, err
	}

	first := true
	seen := make(map[string]bool)
	for _, s := range r {
		if first {
			first = false
			continue
		}
		if len(s) < 6 {
			continue
		}
		if seen[s[5]] {
			continue
		}
		seen[s[5]] = true
		out = append(out, fmt.Sprintf("https://web.archive.org/web/%sif_/%s", s[1], s[2]))
	}

	return out, nil
}
