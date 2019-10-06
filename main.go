package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"sync"
	// "time"
	"runtime"

	"github.com/bobesa/go-domain-util/domainutil"
	"github.com/subfinder/goaltdns/altdns"
	"github.com/manuelbua/goaltdns/util"
)

func loge(text string, args ...interface{}) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, text)
	} else {
		fmt.Fprintf(os.Stderr, text, args...)
	}
}

func main() {
	var wordlist, host, list, output string
	var verbose bool

	flag.StringVar(&host, "h", "", "Host to generate permutations for")
	flag.StringVar(&list, "l", "", "List of hosts to generate permutations for")
	flag.StringVar(&wordlist, "w", "words.txt", "Wordlist to generate permutations with")
	flag.StringVar(&output, "o", "", "File to write permutation output to (optional)")
	flag.BoolVar(&verbose, "v", false, "Enable verbosity")

	flag.Parse()

	if host == "" && list == "" && !util.PipeGiven() {
		fmt.Printf("%s: no host/hosts specified!\n", os.Args[0])
		os.Exit(1)
	}

	hostList := []string{}
	if host != "" {
		hostList = append(hostList, host)
	}

	if list != "" {
		hostList = append(hostList, util.LinesInFile(list)...)
	}

	if util.PipeGiven() {
		hostList = append(hostList, util.LinesInStdin()...)
	}

	var outfile *os.File = os.Stdout

	var err error
	if output != "" {
		outfile, err = os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Printf("output: %s\n", err)
			os.Exit(1)
		}

		defer outfile.Close()
	}

	altdns, err := altdns.New(wordlist)
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
	if verbose {
		loge("Concurrency set to %d\n", concurrency)
	}

	for i := 0; i < concurrency; i++ {
		jobs.Add(1)
		go func() {
			defer jobs.Done()
			for h := range hosts {
				subdomain := domainutil.Subdomain(h)
				domainSuffix := domainutil.Domain(h)

				uniq := make(map[string]bool)
				for r := range altdns.Permute(subdomain) {
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
