package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sync"
	// "time"
	// "runtime"

	"github.com/bobesa/go-domain-util/domainutil"
	"github.com/subfinder/goaltdns/altdns"
	"github.com/subfinder/goaltdns/util"
)

func main() {
	var wordlist, host, list/*, output*/ string
	hostList := []string{}
	flag.StringVar(&host, "h", "", "Host to generate permutations for")
	flag.StringVar(&list, "l", "", "List of hosts to generate permutations for")
	flag.StringVar(&wordlist, "w", "words.txt", "Wordlist to generate permutations with")
	// flag.StringVar(&output, "o", "", "File to write permutation output to (optional)")

	flag.Parse()

	if host == "" && list == "" && !util.PipeGiven() {
		fmt.Printf("%s: no host/hosts specified!\n", os.Args[0])
		os.Exit(1)
	}

	if host != "" {
		hostList = append(hostList, host)
	}

	if list != "" {
		hostList = append(hostList, util.LinesInFile(list)...)
	}

	if util.PipeGiven() {
		hostList = append(hostList, util.LinesInStdin()...)
	}

	// var f *os.File
	var err error
	// if output != "" {
	// 	f, err = os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	// 	if err != nil {
	// 		fmt.Printf("output: %s\n", err)
	// 		os.Exit(1)
	// 	}

	// 	defer f.Close()
	// }

	altdns, err := altdns.New(wordlist)
	if err != nil {
		fmt.Printf("wordlist: %s\n", err)
		os.Exit(1)
	}

	writerJob := sync.WaitGroup{}

	writequeue := make(chan string, 10000)

	writerJob.Add(1)
	go func() {
		defer writerJob.Done()

		w := bufio.NewWriter(os.Stdout)
		defer w.Flush()

		for permutation := range writequeue {
			w.WriteString(permutation)
		}
	}()


	hosts := make(chan string)
	jobs := sync.WaitGroup{}
	for i := 0; i < 16; i++ {
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

					// if output == "" {
					// 	fmt.Printf("%s", permutation)
					// } else {
					writequeue <- permutation
					// }
				}
			}
		}()
	}

	for _, u := range hostList {
		hosts <- u
	}
	close(hosts)

	// for _, u := range hostList {
	// 	subdomain := domainutil.Subdomain(u)
	// 	domainSuffix := domainutil.Domain(u)
	// 	jobs.Add(1)
	// 	go func(domain string) {
	// 		defer jobs.Done()
	// 		uniq := make(map[string]bool)
	// 		for r := range altdns.Permute(subdomain) {
	// 			permutation := fmt.Sprintf("%s.%s\n", r, domainSuffix)

	// 			// avoid duplicates
	// 			if uniq[permutation] {
	// 				continue
	// 			}

	// 			uniq[permutation] = true

	// 			// if output == "" {
	// 			// 	fmt.Printf("%s", permutation)
	// 			// } else {
	// 			writequeue <- permutation
	// 			// }
	// 		}
	// 		uniq = nil
	// 	}(u)
	// }

	// ticker := time.NewTicker(1 * time.Second)
	// done := make(chan bool)
	// go func() {
	// 	for {
	// 		select {
	// 		case <- done:
	// 			return
	// 		case <-ticker.C:
	// 			runtime.GC()
	// 		}
	// 	}
	// }()

	jobs.Wait()

	close(writequeue)

	writerJob.Wait()
	// ticker.Stop()
	// done <- true
}
