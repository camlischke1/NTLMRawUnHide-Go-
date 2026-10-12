package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func decodeString(b []byte) string {
	return strings.Trim(string(b), "\x00")
}

func decodeInt(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}

func writeOutfile(output, outstr string) error {
	f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(outstr + "\n")
	return err
}

func searchCaptureFile(infile, outfile string, verbose, follow, quiet bool, offset int64) error {
	readbuff, err := os.ReadFile(infile)
	if err != nil {
		return err
	}

	lastByte := int64(len(readbuff))
	var serverChallenge []byte

	ntlmssp := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}
	ntlmsspType1 := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00}
	ntlmsspType2 := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00}
	ntlmsspType3 := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00}

	for offset != -1 {
		if offset != 0 {
			offset = offset + int64(len(ntlmssp))
		}

		idx := bytes.Index(readbuff[offset:], ntlmssp)
		if idx == -1 {
			offset = -1
			break
		}
		offset = offset + int64(idx)

		// Check for NTLMSSP Type 1
		if offset+int64(len(ntlmsspType1)) <= int64(len(readbuff)) {
			if bytes.Equal(readbuff[offset:offset+int64(len(ntlmsspType1))], ntlmsspType1) {
				if !quiet {
					if verbose {
						fmt.Printf("\033[1;37mFound NTLMSSP Message Type 1 :\033[1;32m Negotiation\033[0;37m    \033[1;30m>\033[0;37m Offset %d\033[0;37m\n", offset)
					} else {
						fmt.Printf("\033[1;37mFound NTLMSSP Message Type 1 :\033[1;32m Negotiation\033[0;37m\n")
					}
					fmt.Println()
				}
			}
		}

		// Check for NTLMSSP Type 2
		if offset+int64(len(ntlmsspType2)) <= int64(len(readbuff)) {
			if bytes.Equal(readbuff[offset:offset+int64(len(ntlmsspType2))], ntlmsspType2) {
				serverChallenge = readbuff[offset+24 : offset+32]

				if !quiet {
					if verbose {
						fmt.Printf("\033[1;37mFound NTLMSSP Message Type 2 :\033[1;32m Challenge      \033[1;30m>\033[0;37m Offset %d\033[0;37m\n", offset)
					} else {
						fmt.Printf("\033[1;37mFound NTLMSSP Message Type 2 :\033[1;32m Challenge\033[0;37m\n")
					}
					fmt.Printf("    \033[1;34m>\033[1;37m Server Challenge       :\033[0;97m %s\033[0;37m\n", hex.EncodeToString(serverChallenge))
					fmt.Println()
				}
			}
		}

		// Check for NTLMSSP Type 3
		if offset+int64(len(ntlmsspType3)) <= int64(len(readbuff)) {
			if bytes.Equal(readbuff[offset:offset+int64(len(ntlmsspType3))], ntlmsspType3) {
				if !quiet {
					if verbose {
						fmt.Printf("\033[1;37mFound NTLMSSP Message Type 3 :\033[1;32m Authentication \033[1;30m>\033[0;37m Offset %d\033[0;37m\n", offset)
					} else {
						fmt.Printf("\033[1;37mFound NTLMSSP Message Type 3 :\033[1;32m Authentication\033[0;37m\n")
					}
				}

				// Find domain
				domainLengthRaw := readbuff[offset+28 : offset+28+2]
				domainLength := decodeInt(append(domainLengthRaw, 0, 0))

				domainOffsetRaw := readbuff[offset+28+2+2 : offset+28+2+2+4]
				domainOffset := decodeInt(domainOffsetRaw)

				domain := readbuff[offset+int64(domainOffset) : offset+int64(domainOffset)+int64(domainLength)]

				if !quiet {
					fmt.Printf("    \033[1;34m>\033[1;37m Domain                 :\033[0;97m %s\033[0;37m\n", decodeString(domain))

					if verbose {
						fmt.Printf("      Domain length          : %d\n", domainLength)
						fmt.Printf("      Domain offset          : %d\n", domainOffset)
						fmt.Println()
					}
				}

				// Find username
				usernameLengthRaw := readbuff[offset+36 : offset+36+2]
				usernameLength := decodeInt(append(usernameLengthRaw, 0, 0))

				usernameOffsetRaw := readbuff[offset+36+2+2 : offset+36+2+2+4]
				usernameOffset := decodeInt(usernameOffsetRaw)

				username := readbuff[offset+int64(usernameOffset) : offset+int64(usernameOffset)+int64(usernameLength)]

				if !quiet {
					fmt.Printf("    \033[1;34m>\033[1;37m Username               :\033[0;97m %s\033[0;37m\n", decodeString(username))

					if verbose {
						fmt.Printf("      Username length        : %d\n", usernameLength)
						fmt.Printf("      Username offset        : %d\n", usernameOffset)
						fmt.Println()
					}
				}

				// Find workstation
				workstationLengthRaw := readbuff[offset+44 : offset+44+2]
				workstationLength := decodeInt(append(workstationLengthRaw, 0, 0))

				workstationOffsetRaw := readbuff[offset+44+2+2 : offset+44+2+2+4]
				workstationOffset := decodeInt(workstationOffsetRaw)

				workstation := readbuff[offset+int64(workstationOffset) : offset+int64(workstationOffset)+int64(workstationLength)]

				if !quiet {
					fmt.Printf("    \033[1;34m>\033[1;37m Workstation            :\033[0;97m %s\033[0;37m\n", decodeString(workstation))

					if verbose {
						fmt.Printf("      Workstation length     : %d\n", workstationLength)
						fmt.Printf("      Workstation offset     : %d\n", workstationOffset)
						fmt.Println()
					}
				}

				// Find NTLM response
				ntlmLengthRaw := readbuff[offset+20 : offset+20+2]
				ntlmLength := decodeInt(append(ntlmLengthRaw, 0, 0))

				ntlmOffsetRaw := readbuff[offset+20+2+2 : offset+20+2+2+4]
				ntlmOffset := decodeInt(ntlmOffsetRaw)

				ntproofstr := readbuff[offset+int64(ntlmOffset) : offset+int64(ntlmOffset)+16]
				ntlmv2Response := readbuff[offset+int64(ntlmOffset)+16 : offset+int64(ntlmOffset)+int64(ntlmLength)]

				if !quiet {
					if verbose {
						fmt.Printf("      NTLM length            : %d\n", ntlmLength)
						fmt.Printf("      NTLM offset            : %d\n", ntlmOffset)
						fmt.Printf("    \033[1;34m>\033[1;37m NTProofStr             :\033[0;37m %s\n", hex.EncodeToString(ntproofstr))
						fmt.Printf("    \033[1;34m>\033[1;37m NTLMv2 Response        :\033[0;37m %s\n", hex.EncodeToString(ntlmv2Response))
					}
					fmt.Println()
				}

				// Prepare NTLMv2 Hash for output
				if serverChallenge != nil {
					if !quiet {
						fmt.Printf("\033[1;37mNTLMv2 Hash recovered:\033[0;97m\n")
					}

					if ntlmLength == 0 {
						if !quiet {
							fmt.Printf("\033[0;37mNTLM NULL session found... no hash to generate\033[0;37m\n")
						}
					} else {
						var hashOut string
						if domainLength == 0 {
							hashOut = fmt.Sprintf("%s::%s:%s:%s:%s",
								decodeString(username),
								decodeString(workstation),
								hex.EncodeToString(serverChallenge),
								hex.EncodeToString(ntproofstr),
								hex.EncodeToString(ntlmv2Response))
						} else {
							hashOut = fmt.Sprintf("%s::%s:%s:%s:%s",
								decodeString(username),
								decodeString(domain),
								hex.EncodeToString(serverChallenge),
								hex.EncodeToString(ntproofstr),
								hex.EncodeToString(ntlmv2Response))
						}

						fmt.Println(hashOut)
						if outfile != "" {
							writeOutfile(outfile, hashOut)
						}
					}

					fmt.Println()
					serverChallenge = nil
				} else {
					if !quiet {
						fmt.Printf("\033[1;31mServer Challenge not found... can't create crackable hash :-/\033[0;37m\n")
						fmt.Println()
					}
				}
			}
		}
	}

	if follow {
		for {
			time.Sleep(1 * time.Second)
			if err := searchCaptureFile(infile, outfile, verbose, follow, quiet, lastByte); err != nil {
				return err
			}
		}
	}

	return nil
}

func banner() {
	fmt.Print("")
}

func usage() {
	fmt.Printf("\033[1;37m")
	fmt.Println("usage: NTLMRawUnHide -i <inputfile> [-o <outputfile>] [-f] [-h] [-q] [-v]")
	fmt.Printf("\033[0;97m\n")
}

func showHelp() {
	usage()
	fmt.Println("Main options:")
	fmt.Println("  -f, --follow               Continuously \"follow\" (e.g. \"read from\")")
	fmt.Println("                             input file for new data")
	fmt.Println("  -h, --help")
	fmt.Println("  -i, --input  <inputfile>   Binary packet data input file")
	fmt.Println("                             (.pcap, .pcapng, .cap, .etl, others?)")
	fmt.Println("  -o, --output <outputfile>  Output file to record any found NTLM")
	fmt.Println("                             hashes")
	fmt.Println("  -q, --quiet                Be a lot more quiet and only output")
	fmt.Println("                             found NTLM hashes. --quiet will also")
	fmt.Println("                             disable verbose, if specified.")
	fmt.Println("  -v, --verbose")
	fmt.Println()
}

func main() {
	infile := flag.String("i", "", "Input file")
	input := flag.String("input", "", "Input file")
	outfile := flag.String("o", "", "Output file")
	output := flag.String("output", "", "Output file")
	verbose := flag.Bool("v", false, "Verbose output")
	verboseLong := flag.Bool("verbose", false, "Verbose output")
	follow := flag.Bool("f", false, "Follow file for new data")
	followLong := flag.Bool("follow", false, "Follow file for new data")
	quiet := flag.Bool("q", false, "Quiet mode")
	quietLong := flag.Bool("quiet", false, "Quiet mode")
	help := flag.Bool("h", false, "Help")
	helpLong := flag.Bool("help", false, "Help")

	flag.Parse()

	if flag.NFlag() == 0 {
		banner()
		usage()
		os.Exit(0)
	}

	if *help || *helpLong {
		banner()
		showHelp()
		os.Exit(0)
	}

	// Resolve conflicting flags
	if *input != "" {
		*infile = *input
	}
	if *output != "" {
		*outfile = *output
	}
	if *verboseLong {
		*verbose = true
	}
	if *followLong {
		*follow = true
	}
	if *quietLong {
		*quiet = true
	}

	if *quiet {
		*verbose = false
	}

	if *infile == "" {
		fmt.Printf("\033[1;31m[!]\033[0;97m Error: Input file not specified. Did you mean to specify -i?\n")
		os.Exit(1)
	}

	if _, err := os.Stat(*infile); os.IsNotExist(err) {
		fmt.Printf("\033[1;31m[!]\033[0;97m Error: Input file not found.\n")
		os.Exit(1)
	}

	if !*quiet {
		banner()
	}

	fmt.Printf("\033[1;37mSearching %s for NTLMv2 hashes...\n", filepath.Base(*infile))
	if *outfile != "" {
		fmt.Printf("Writing output to: %s\n", *outfile)
	}
	fmt.Printf("\033[0;97m\n")

	if err := searchCaptureFile(*infile, *outfile, *verbose, *follow, *quiet, 0); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
