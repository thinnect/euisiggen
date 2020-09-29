package main

import "os"
import "fmt"
import "io/ioutil"
import "strings"
import "strconv"
import "errors"
import "crypto/x509"
import "crypto/ecdsa"
import "encoding/pem"
import "encoding/binary"
import "bytes"
import "crypto/rand"
import "time"
import "bufio"
import "path/filepath"

import "github.com/jessevdk/go-flags"

var g_version_major uint8 = 0
var g_version_minor uint8 = 0
var g_version_patch uint8 = 1

const LICENSE_TYPE = 4

type eui64 uint64

type BeatstackParams struct {
	nodesInCluster uint8
	partnershipsNr uint8
	clustersNr     uint8
}

type PreSigning struct {
	LicenseId  uint8
	Eui64      eui64
	UnixTime   int64
	BeatParams BeatstackParams
}

func TimestampString(t time.Time) string {
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
}

func printGeneratorVersion() {
	fmt.Printf("Device signature generator %d.%d.%d\n", g_version_major, g_version_minor, g_version_patch)
}

func getEuiList(infile string) ([]string, error) {
	var splits []string

	b, err := ioutil.ReadFile(infile)
	if err != nil {
		return splits, err
	}
	str := string(b)
	splits = strings.Split(str, "\n")

	return splits, nil
}

func getBeatstackParams(infile string) (BeatstackParams, error) {
	var p BeatstackParams

	f, err := os.Open(infile)
	if err != nil {
	    return p, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
	    if strings.Contains(scanner.Text(), "BEATS_IN_CYCLE") {
	    	splits := strings.Split(scanner.Text(), " = ")
	    	clNr, err := strconv.ParseUint(splits[1], 10, 32)
	    	p.clustersNr = uint8(clNr)
	    	if err != nil {
				return p, err
			}
	    } else if strings.Contains(scanner.Text(), "NODES_IN_BEAT") {
	    	splits := strings.Split(scanner.Text(), " = ")
	    	nic, err := strconv.ParseUint(splits[1], 10, 32)
	    	p.nodesInCluster = uint8(nic)
	    	if err != nil {
				return p, err
			}
	    } else if strings.Contains(scanner.Text(), "MAX_PARTNER_COUNT_FOR_NODE") {
	    	splits := strings.Split(scanner.Text(), " = ")
		   	prtnrs, err := strconv.ParseUint(splits[1], 10, 32)
		   	p.partnershipsNr = uint8(prtnrs)
	    	if err != nil {
				return p, err
			}
	    }
	}

	if err := scanner.Err(); err != nil {
		return p, err
	}
	return p, nil
}

func parseEui(s string) (eui64, error) {
	if len(s) != 16 {
		return 0, errors.New(fmt.Sprintf("%s is not a valid EUI-64", s))
	}

	eui, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, errors.New(fmt.Sprintf("%s is not a valid EUI-64", s))
	}

	return eui64(eui), nil
}

func getPrivateKey(infile string) (*ecdsa.PrivateKey, error) {
	var privKey *ecdsa.PrivateKey
	key_in, err := ioutil.ReadFile(infile)
	if err != nil {
		return privKey, err
	}

	block, _ := pem.Decode(key_in)
	privKey, _ = x509.ParseECPrivateKey(block.Bytes)

	return privKey, nil
}

func ConstructPreSign(eui eui64, t time.Time, p BeatstackParams) (PreSigning) {
	var ps PreSigning

	ps.LicenseId = LICENSE_TYPE
	ps.Eui64 = eui
	ps.UnixTime = t.Unix()
	ps.BeatParams = p

	return ps
}

func Serialize(ps PreSigning) ([]byte, error) {
	var err error
	buf := new(bytes.Buffer)

	err = binary.Write(buf, binary.BigEndian, ps)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func main() {
	var opts struct {
		Eui          string       `long:"eui"          description:"EUI64."`
		Keyfile      string       `long:"keyfile"      description:"Private key file."`
		Euifile      string       `long:"euifile"      description:"Eui file."`
		BstkConf     string       `long:"bstkconf"     description:"Beatstack configuration file."`

		Timestamp int64 `long:"timestamp" description:"Use the specified timestamp."`

		Licdir  string `long:"licdir"  default:"licensedata" description:"Where to store EUI_XXXXXXXXXXXXXXXX.bin files."`
		Output string `long:"out" default:"license.bin" description:"The output file name."`

		ShowVersion func() `short:"V" description:"Show generator version."`
		Debug       bool   `long:"debug" description:"Enable debug messages"`
	}

	var eui eui64
	var err error
	var bp BeatstackParams

	opts.ShowVersion = func() {
		printGeneratorVersion()
		os.Exit(0)
	}

	parser := flags.NewParser(&opts, flags.Default)
	_, err = parser.Parse()
	if err != nil {
		fmt.Printf("ERROR parsing arguments\n")
		os.Exit(1)
	}

	// We are generating a signature. Verify mandatory options for this operation
	required_opts := []string{"keyfile", "bstkconf"}
	for _, long_opt_name := range required_opts {
		opt := parser.FindOptionByLongName(long_opt_name)
		if !opt.IsSet() {
			fmt.Printf("Required flag `--%s' was not specified\n", long_opt_name)
			os.Exit(2)
		}
	}

	if (len(opts.Eui) == 0) && (len(opts.Euifile) == 0) {
		fmt.Printf("Specify eui or euifile\n")
		os.Exit(2)
	}

	if _, err = os.Stat(opts.Licdir); os.IsNotExist(err) {
		err = os.Mkdir(opts.Licdir, 0770)
		if err != nil {
			fmt.Printf("ERROR creating output directory: %s\n", err)
			os.Exit(1)
		}
	}

	var timestamp time.Time
	if opts.Timestamp > 0 {
		timestamp = time.Unix(opts.Timestamp, 0).UTC()
	} else {
		timestamp = time.Now().UTC()
	}

	bp, err = getBeatstackParams(opts.BstkConf)
	if err != nil {
		fmt.Printf("ERROR getting Beatstack configuration: %s\n", err)
		os.Exit(1)
	}

	privKey, err := getPrivateKey(opts.Keyfile)
	if err != nil {
		fmt.Printf("ERROR getting private key: %s\n", err)
		os.Exit(1)
	}

	var euiList []string
	overrideEui := false
	if len(opts.Eui) > 0 {
		if len(opts.Eui) != 16 {
			fmt.Printf("ERROR specified override EUI64 '%s' is not suitable!", opts.Eui)
			os.Exit(1)
		}
		overrideEui = true
		euiList = strings.Split(opts.Eui, " ")
	} else {
		euiList, err = getEuiList(opts.Euifile)
		if err != nil {
			fmt.Printf("ERROR getting EUI64: %s\n", err)
			os.Exit(1)
		}
	}

	for _, euiString := range euiList {
		eui, err = parseEui(euiString)
		preSign := ConstructPreSign(eui, timestamp, bp)

		serPreSign, err := Serialize(preSign)
		if err != nil {
			fmt.Printf("ERROR generating serPreSign: %s\n", err)
			os.Exit(1)
		}

		r, s, err := ecdsa.Sign(rand.Reader, privKey, serPreSign)
		if err != nil {
			fmt.Printf("ERROR signing the message: %s\n", err)
			os.Exit(1)
		}

		licfile := filepath.Join(opts.Licdir, fmt.Sprintf("EUI-64_%016X.bin", eui))
		if overrideEui == false {
			if _, err := os.Stat(licfile); err == nil {
				fmt.Printf("ERROR generating licdata: license file for %016X exists at %s\n", eui, licfile)
				os.Exit(1)
			}
		}

		licdata := append(serPreSign, r.Bytes()...)
		licdata = append(licdata, s.Bytes()...)
		if err := ioutil.WriteFile(licfile, licdata, 0440); err != nil {
			fmt.Printf("ERROR writing output file: %s\n", err)
			os.Exit(1)
		}

		if err := ioutil.WriteFile(opts.Output, licdata, 0640); err != nil {
			fmt.Printf("ERROR writing output file: %s\n", err)
			os.Exit(1)
		}
	}

	if opts.Debug {
		printGeneratorVersion()
		fmt.Printf("Timestamp:    %d (%s)\n", timestamp.UTC().Unix(), TimestampString(timestamp.UTC()))
		fmt.Printf("Eui:         %s\n", opts.Eui)
		fmt.Printf("Keyfile:      %s\n", opts.Keyfile)
		fmt.Printf("BstkConf:      %s\n", opts.BstkConf)

		fmt.Printf("Output:       %s\n", opts.Output)
		fmt.Printf("Licdir:       %s\n", opts.Licdir)
		fmt.Printf("Euifile:      %s\n", opts.Euifile)
	}
}
