// Author  Raido Pahtma
// License MIT

package main

import "os"
import "fmt"
import "io/ioutil"
import "strings"
import "strconv"
import "errors"
import "encoding/binary"
import "bytes"
import "time"
import "bufio"
import "path/filepath"

import "github.com/jessevdk/go-flags"
import "github.com/joaojeronimo/go-crc16"
import "github.com/satori/go.uuid"

var g_version_major uint8 = 3
var g_version_minor uint8 = 0
var g_version_patch uint8 = 0

type UserSignature struct {
}

type EUISignature struct {
	sig_version_major uint8
	sig_version_minor uint8
	sig_version_patch uint8

	signature_size uint16
	signature_type uint8

	unix_time int64 // nx_int64_t unix_time; // Same moment in time

	eui64 uint64

	// crc uint16
}

type ComponentSignature struct {
	sig_version_major uint8
	sig_version_minor uint8
	sig_version_patch uint8

	signature_size uint16
	signature_type uint8

	unix_time int64 // nx_int64_t unix_time; // Same moment in time

	name [16]byte //char boardname[16]; // up to 16 chars or 0 terminated

	version_major    uint8 // nx_uint8_t pcb_version_major;
	version_minor    uint8 // nx_uint8_t pcb_version_minor;
	version_assembly uint8 // nx_uint8_t pcb_version_assembly;

	component_uuid    [16]byte
	manufacturer_uuid [16]byte

	// crc uint16
}

func (self *UserSignature) ConstructEUISignature(t time.Time, eui64 uint64) (*EUISignature, error) {
	sig := new(EUISignature)
	sig.sig_version_major = g_version_major
	sig.sig_version_minor = g_version_minor
	sig.sig_version_patch = g_version_patch

	sig.signature_size = uint16(binary.Size(sig)) + 2
	sig.signature_type = 0
	sig.eui64 = eui64

	sig.unix_time = t.Unix()

	return sig, nil
}

func (self *UserSignature) ConstructComponentSignature(t time.Time, boardname string, boardversion BoardVersion, boarduuid string, manufuuid string, signature_type uint8) (*ComponentSignature, error) {
	var err error
	sig := new(ComponentSignature)
	sig.sig_version_major = g_version_major
	sig.sig_version_minor = g_version_minor
	sig.sig_version_patch = g_version_patch

	sig.signature_size = uint16(binary.Size(sig)) + 2
	sig.signature_type = signature_type

	sig.unix_time = t.Unix()

	if len(boardname) == 0 {
		return nil, errors.New(fmt.Sprintf("Boardname is too short(%d)", len(boardname)))
	}

	if len(boardname) > len(sig.name) {
		return nil, errors.New(fmt.Sprintf("Boardname is too long(%d), maximum allowed length is %d", len(boardname), len(sig.name)))
	}
	copy(sig.name[:], boardname)

	sig.version_major = boardversion.major
	sig.version_minor = boardversion.minor
	sig.version_assembly = boardversion.assembly

	sig.component_uuid, err = uuid.FromString(boarduuid)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Board UUID error(%d)", err))
	}

	sig.manufacturer_uuid, err = uuid.FromString(manufuuid)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Manufacturer UUID error(%d)", err))
	}

	return sig, nil
}

func (self *UserSignature) Serialize(sig interface{}) ([]byte, error) {
	var err error
	buf := new(bytes.Buffer)

	err = binary.Write(buf, binary.BigEndian, sig)
	if err != nil {
		return nil, err
	}

	crc := crc16.Crc16(buf.Bytes())
	//fmt.Printf("CRC %X\n", crc)

	err = binary.Write(buf, binary.BigEndian, crc)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (self *ComponentSignature) BoardName() string {
	n := bytes.Index(self.name[:], []byte{0})
	if n < 0 {
		n = 16
	}
	return string(self.name[:n])
}

func (self *ComponentSignature) BoardVersion() string {
	return fmt.Sprintf("%d.%d.%d", self.version_major, self.version_minor, self.version_assembly)
}

func (self *ComponentSignature) TimestampString() string {
	return "" //fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", self.year, self.month, self.day, self.hours, self.minutes, self.seconds)
}

type BoardVersion struct {
	major    uint8
	minor    uint8
	assembly uint8
}

func (v BoardVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.assembly)
}

func (v *BoardVersion) UnmarshalFlag(value string) error {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return errors.New("Expected 3 numbers as MAJOR.MINOR.ASSEMBLY")
	}

	major, err := strconv.ParseInt(parts[0], 10, 32)
	if err != nil {
		return err
	}
	minor, err := strconv.ParseInt(parts[1], 10, 32)
	if err != nil {
		return err
	}
	assembly, err := strconv.ParseInt(parts[2], 10, 32)
	if err != nil {
		return err
	}

	v.major = uint8(major)
	v.minor = uint8(minor)
	v.assembly = uint8(assembly)

	return nil
}

func (v BoardVersion) MarshalFlag() (string, error) {
	return fmt.Sprintf("%s", v), nil
}

func parseEui(s string) (uint64, error) {
	if len(s) != 16 {
		return 0, errors.New(fmt.Sprintf("%s is not a valid EUI-64", s))
	}

	eui, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, errors.New(fmt.Sprintf("%s is not a valid EUI-64", s))
	}

	return eui, nil
}

func getEui(infile string) (uint64, error) {
	in, err := os.Open(infile)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	scanner := bufio.NewScanner(bufio.NewReader(in))

	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(t, "#") == false {
			splits := strings.Split(t, ",")
			// fmt.Printf("l %d %s\n", len(splits), splits)

			if len(splits) == 1 || (len(splits) == 2 && len(splits[1]) == 0) {
				return parseEui(splits[0])
			}
		}
	}

	return 0, errors.New(fmt.Sprintf("Could not find a suitable EUI64 in %s!", infile))
}

func markEui(infile string, esig EUISignature, csig ComponentSignature) error {
	infile, err := filepath.Abs(infile)
	if err != nil {
		return err
	}

	in, err := os.Open(infile)
	if err != nil {
		return err
	}
	defer in.Close()

	outfile := filepath.Join(filepath.Dir(infile), fmt.Sprintf("eui_temp_%d.txt", esig.unix_time))
	out, err := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0660)
	if err != nil {
		return err
	}
	defer out.Close()

	scanner := bufio.NewScanner(bufio.NewReader(in))
	writer := bufio.NewWriter(out)

	//fmt.Printf("infile %s\n", infile)
	//fmt.Printf("outfile %s\n", outfile)

	marked := false
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(t, "#") == false {
			splits := strings.Split(t, ",")

			if !marked && (len(splits) == 1 || (len(splits) == 2 && len(splits[1]) == 0)) {
				val, err := parseEui(splits[0])
				if err != nil {
					return err
				}

				if val == esig.eui64 {
					m := fmt.Sprintf("%s,%s,%d,%x,%x", csig.BoardName(), csig.BoardVersion(), csig.unix_time, csig.component_uuid, csig.manufacturer_uuid)
					writer.WriteString(fmt.Sprintf("%s,%s", splits[0], m))
					marked = true
				} else if !marked {
					fmt.Printf("Found unmarked %016X != %016X", val, esig.eui64)
				}
			} else {
				writer.WriteString(t)
			}
		} else {
			writer.WriteString(scanner.Text())
		}
		writer.WriteString("\n")
	}

	in.Close()

	writer.Flush()
	out.Close()

	err = os.Remove(infile)
	if err != nil {
		return err
	}

	err = os.Rename(outfile, infile)
	if err != nil {
		return err
	}

	return nil
}

func printGeneratorVersion() {
	fmt.Printf("User Signature Area generator %d.%d.%d\n", g_version_major, g_version_minor, g_version_patch)
}

func main() {
	var opts struct {
		Boardname   string       `long:"boardname" required:"true" description:"The name of the PCB that the user signature will be used for."`
		Version     BoardVersion `long:"version" required:"true" description:"The version of the board X.Y.Z."`
		Board_uuid  string       `long:"boarduuid" required:"true" description:"Board UUID. 16 bytes"`
		Manuf_uuid  string       `long:"manuuid" required:"true" description:"Manufacturer UUID. 16 bytes"`
		Output      string       `long:"out" default:"sigdata.bin" description:"The output file name."`
		Sigdir      string       `long:"sigdir" default:"sigdata" description:"Where to store EUI_XXXXXXXXXXXXXXXX.bin files."`
		Euifile     string       `long:"euifile" default:"eui.txt" description:"The file containing available EUIs."`
		Sign_type   uint8        `long:"type" required:"true" description:"Signature type."`
		Timestamp   int64        `long:"timestamp" required:"false" description:"Use the specified timestamp."`
		ShowVersion func()       `short:"V" description:"Show generator version."`
		Debug       bool         `long:"debug" description:"The file containing available EUIs."`
	}

	var eui uint64

	opts.ShowVersion = func() {
		printGeneratorVersion()
		os.Exit(0)
	}

	_, err := flags.Parse(&opts)
	if err != nil {
		fmt.Printf("ERROR parsing arguments\n")
		os.Exit(1)
	}

	if _, err := os.Stat(opts.Sigdir); os.IsNotExist(err) {
		err = os.Mkdir(opts.Sigdir, 0770)
		if err != nil {
			fmt.Printf("ERROR creating output directory: %s\n", err)
			os.Exit(1)
		}
	}

	if opts.Sign_type == 0 {
		eui, err = getEui(opts.Euifile)
		if err != nil {
			fmt.Printf("ERROR getting EUI64: %s\n", err)
			os.Exit(1)
		}
	} else {
		eui = 0
	}

	sigfile := filepath.Join(opts.Sigdir, fmt.Sprintf("EUI-64_%016X.bin", eui))
	if _, err := os.Stat(sigfile); err == nil {
		fmt.Printf("ERROR generating sigdata: signature file for %016X exists at %s\n", eui, sigfile)
		os.Exit(1)
	}

	var gen UserSignature
	var timestamp time.Time
	if opts.Timestamp > 0 {
		timestamp = time.Unix(opts.Timestamp, 0).UTC()
	} else {
		timestamp = time.Now().UTC()
	}

	var esig *EUISignature
	esig, err = gen.ConstructEUISignature(timestamp, eui)
	if err != nil {
		fmt.Printf("ERROR generating sigdata: %s\n", err)
		os.Exit(1)
	}

	var csig *ComponentSignature
	csig, err = gen.ConstructComponentSignature(timestamp, opts.Boardname, opts.Version, opts.Board_uuid, opts.Manuf_uuid, 1)
	if err != nil {
		fmt.Printf("ERROR generating sigdata: %s\n", err)
		os.Exit(1)
	}

	esigdata, err := gen.Serialize(esig)
	if err != nil {
		fmt.Printf("ERROR generating sigdata: %s\n", err)
		os.Exit(1)
	}

	csigdata, err := gen.Serialize(csig)
	if err != nil {
		fmt.Printf("ERROR generating sigdata: %s\n", err)
		os.Exit(1)
	}

	sigdata := append(esigdata, csigdata...)

	err = ioutil.WriteFile(sigfile, sigdata, 0440)
	if err != nil {
		fmt.Printf("ERROR writing output file: %s\n", err)
		os.Exit(1)
	}

	if opts.Sign_type == 0 {
		err = markEui(opts.Euifile, *esig, *csig)
		if err != nil {
			fmt.Printf("ERROR marking %016X in %s: %s\n", eui, opts.Euifile, err)
			os.Exit(1)
		}
	}

	err = ioutil.WriteFile(opts.Output, sigdata, 0640)
	if err != nil {
		fmt.Printf("ERROR writing output file: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("EUI-64: %016X\n", esig.eui64)
	if opts.Debug {
		printGeneratorVersion()
		fmt.Printf("Timestamp: %d (%s)\n", esig.unix_time, "")
		//esig.TimestampString())
		fmt.Printf("Boardname: %s\n", opts.Boardname)
		fmt.Printf("Version:   %s\n", opts.Version)
		fmt.Printf("Output:    %s\n", opts.Output)
		fmt.Printf("Sigdir:    %s\n", opts.Sigdir)
		fmt.Printf("Euifile:   %s\n", opts.Euifile)

		fmt.Printf("SIG(%d):\n", len(sigdata))
		fmt.Printf("%X\n", sigdata[0:256])
		fmt.Printf("%X\n", sigdata[256:512])
		fmt.Printf("%X\n", sigdata[512:768])
	}

}
