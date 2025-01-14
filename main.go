package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"sync"
	"runtime"

	"github.com/bobesa/go-domain-util/domainutil"
	"github.com/manuelbua/goaltdns/altdns"
	"github.com/manuelbua/goaltdns/util"
)

func loge(text string, args ...interface{}) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, text)
	} else {
		fmt.Fprintf(os.Stderr, text, args...)
	}
}

type Config struct {
	Host		string
	List 		string
	Output		string
	Verbose		bool
	Concurrency int
	Altdns		altdns.Config
}

func main() {
	var config Config

	flag.StringVar(&config.Host, "h", "", "Host to generate permutations for")
	flag.StringVar(&config.List, "l", "", "List of hosts to generate permutations for")
	flag.StringVar(&config.Altdns.Wordlist, "w", "words.txt", "Wordlist to generate permutations with")
	flag.StringVar(&config.Output, "o", "", "File to write permutation output to (optional)")
	flag.BoolVar(&config.Verbose, "v", false, "Enable verbosity")
	flag.IntVar(&config.Concurrency, "c", 0, "Specify concurrency (0 means auto adjust)")

	flag.BoolVar(&config.Altdns.NoInsertIndices, "1", false, "Disable insert indices")
	flag.BoolVar(&config.Altdns.NoInsertDashes, "2", false, "Disable insert dashes")
	flag.BoolVar(&config.Altdns.NoInsertNumberSuffixes, "3", false, "Disable insert number suffixes")
	flag.BoolVar(&config.Altdns.NoInsertWordsSubdomains, "4", false, "Disable insert words in subdomain")
	flag.BoolVar(&config.Altdns.NoExpandNumbers, "5", false, "Disable expand numbers")

	flag.Parse()

	if config.Host == "" && config.List == "" && !util.PipeGiven() {
		fmt.Printf("%s: no host/hosts specified!\n", os.Args[0])
		os.Exit(1)
	}

	hostList := []string{}
	if config.Host != "" {
		hostList = append(hostList, config.Host)
	}

	if config.List != "" {
		hostList = append(hostList, util.LinesInFile(config.List)...)
	}

	if util.PipeGiven() {
		hostList = append(hostList, util.LinesInStdin()...)
	}

	var outfile *os.File = os.Stdout

	var err error
	if config.Output != "" {
		outfile, err = os.OpenFile(config.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Printf("output: %s\n", err)
			os.Exit(1)
		}

		defer outfile.Close()
	}

	adns, err := altdns.New(config.Altdns)
	if err != nil {
		fmt.Printf("wordlist: %s\n", err)
		os.Exit(1)
	}

	writequeue := make(chan string, 10000)

	writerJob := sync.WaitGroup{}
	writerJob.Add(1)
	go func() {
		defer writerJob.Done()

		w := bufio.NewWriter(outfile)
		defer w.Flush()

		for permutation := range writequeue {
			w.WriteString(permutation)
		}
	}()


	hosts := make(chan string)
	jobs := sync.WaitGroup{}

	var concurrency int = int(math.Round( float64(runtime.NumCPU()) * 1.5 ))
	if config.Concurrency > 0 {
		concurrency = config.Concurrency
	}

	if config.Verbose {
		loge("Concurrency set to %d\n", concurrency)
		var yesno string

		loge("Permutations:\n")
		yesno = "X"; if config.Altdns.NoInsertIndices { yesno = " " }; loge("  [%s] Insert indices\n", yesno)
		yesno = "X"; if config.Altdns.NoInsertDashes { yesno = " " }; loge("  [%s] Insert dashes\n", yesno)
		yesno = "X"; if config.Altdns.NoInsertNumberSuffixes { yesno = " " }; loge("  [%s] Insert number suffixes\n", yesno)
		yesno = "X"; if config.Altdns.NoInsertWordsSubdomains { yesno = " " }; loge("  [%s] Join words with subdomain\n", yesno)
		yesno = "X"; if config.Altdns.NoExpandNumbers { yesno = " " }; loge("  [%s] Expand numbers\n", yesno)
	}

	for i := 0; i < concurrency; i++ {
		jobs.Add(1)
		go func() {
			defer jobs.Done()
			for h := range hosts {
				subdomain := domainutil.Subdomain(h)
				domainSuffix := domainutil.Domain(h)

				uniq := make(map[string]bool)
				for r := range adns.Permute(subdomain) {
					permutation := fmt.Sprintf("%s.%s\n", r, domainSuffix)

					// avoid duplicates
					if uniq[permutation] {
						continue
					}

					uniq[permutation] = true

					writequeue <- permutation
				}
			}
		}()
	}

	for _, u := range hostList {
		hosts <- u
	}
	close(hosts)

	jobs.Wait()

	close(writequeue)

	writerJob.Wait()
}
