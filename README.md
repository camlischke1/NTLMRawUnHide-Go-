# NTLMRawUnHide (Go)

A Go port of the Python NTLMRawUnHide tool. This tool parses network packet capture files and extracts NTLMv2 hashes in a crackable format.

## Supported Formats

- `.pcap`
- `.pcapng`
- `.cap`
- `.etl`

## Usage

```bash
go run main.go -i <inputfile> [-o <outputfile>] [-f] [-h] [-q] [-v]
```

or build and run:

```bash
go build -o NTLMRawUnHide
./NTLMRawUnHide -i <inputfile> [-o <outputfile>] [-f] [-h] [-q] [-v]
```

## Options

- `-i, --input <inputfile>` - Binary packet data input file (required)
- `-o, --output <outputfile>` - Output file to record found NTLM hashes
- `-f, --follow` - Continuously "follow" (e.g. "read from") input file for new data
- `-v, --verbose` - Verbose output
- `-q, --quiet` - Quiet mode, only output found NTLM hashes
- `-h, --help` - Display help message

## Examples

### Basic extraction:
```bash
./NTLMRawUnHide -i capture.pcap
```

### Extract to output file:
```bash
./NTLMRawUnHide -i capture.pcap -o hashes.txt
```


## About

This is a Go port of the original Python NTLMRawUnHide tool. The tool extracts NTLMv2 hashes from network packet captures for use with hashcat or similar password cracking tools.

For the original Python version, see: https://github.com/mlgualtieri/NTLMRawUnhide
# NTLMRawUnHide-Go-
