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

const SIGNATURE_TYPE_EUI64 = 0     // EUI64 is the IEEE Extended Unique Identifier
const SIGNATURE_TYPE_BOARD = 1     // Boards are the core of the system - MCU
const SIGNATURE_TYPE_PLATFORM = 2  // Platforms define the set of components
const SIGNATURE_TYPE_COMPONENT = 3 // Components list individual parts of a platform

type UserSignature struct {
}

type EUISignature struct {
	sig_version_major uint8
	sig_version_minor uint8
	sig_version_patch uint8

	signature_size uint16
	signature_type uint8

	unix_time int64 // Signature generation time

	eui64 uint64 // EUI-64, byte array

	// crc uint16
}

type ComponentSignature struct {
	sig_version_major uint8
	sig_version_minor uint8
	sig_version_patch uint8

	signature_size uint16
	signature_type uint8

	unix_time int64 // Signature generation time

	component_uuid [16]byte
	name           [16]byte //char boardname[16]; // up to 16 chars or 0 terminated

	version_major    uint8 // nx_uint8_t pcb_version_major;
	version_minor    uint8 // nx_uint8_t pcb_version_minor;
	version_assembly uint8 // nx_uint8_t pcb_version_assembly;

	serial_number [16]byte // Possibly an UUID, but could be a \0 terminated string

	manufacturer_uuid [16]byte

	position uint8 // Position / index of the component (when multiple)

	data_length uint16 // Length of the component specific data
	// data     []byte  // compoent specific data - calibration etc

	// crc uint16
}

func (self *UserSignature) ConstructEUISignature(t time.Time, eui64 uint64) (*EUISignature, error) {
	sig := new(EUISignature)
	sig.sig_version_major = g_version_major
	sig.sig_version_minor = g_version_minor
	sig.sig_version_patch = g_version_patch

	sig.signature_size = uint16(binary.Size(sig)) + 2
	sig.signature_type = SIGNATURE_TYPE_EUI64
	sig.eui64 = eui64

	sig.unix_time = t.Unix()

	return sig, nil
}

func (self *UserSignature) ConstructComponentSignature(t time.Time, boardname string,
	boardversion BoardVersion, uuid [16]byte, manufuuid [16]byte,
	serial [16]byte, component_position uint8,
	signature_type uint8) (*ComponentSignature, error) {

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

	sig.component_uuid = uuid

	sig.serial_number = serial

	sig.manufacturer_uuid = manufuuid

	sig.position = component_position

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

func TimestampString(t time.Time) string {
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
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
	fmt.Printf("Device signature generator %d.%d.%d\n", g_version_major, g_version_minor, g_version_patch)
}

func main() {
	var opts struct {
		Type string `long:"type" required:"true" description:"Signature type - board, platform, component"`

		Name         string       `long:"name"         required:"true"  description:"The name of the component that the user signature will be used for."`
		Version      BoardVersion `long:"version"      required:"true"  description:"The version of the board X.Y.Z."`
		UUID         string       `long:"uuid"         required:"true"  description:"Board/Platform/Component UUID. 16 bytes."`
		Manufacturer string       `long:"manufacturer" required:"true"  description:"Manufacturer UUID. 16 bytes."`
		Position     uint8        `long:"position"     required:"false" description:"Component position/index (when multiple)."`

		Serial     string `long:"serial"     required:"false" description:"Serial number, string format. Up to 16 characters."`
		SerialUUID string `long:"serialuuid" required:"false" description:"Serial number, UUID format. 16 bytes."`

		Eui     string `long:"eui"     default:""        description:"Do not retrieve EUI from euifile, override with the specified EUI."`
		Euifile string `long:"euifile" default:"eui.txt" description:"The file containing available EUIs."`
		Sigdir  string `long:"sigdir"  default:"sigdata" description:"Where to store EUI_XXXXXXXXXXXXXXXX.bin files."`

		Timestamp int64 `long:"timestamp" required:"false" description:"Use the specified timestamp."`

		Output string `long:"out" default:"sigdata.bin" description:"The output file name."`

		ShowVersion func() `short:"V" description:"Show generator version."`
		Debug       bool   `long:"debug" description:"The file containing available EUIs."`
	}

	var gen UserSignature
	var eui uint64
	var err error
	var sigdata []byte

	opts.ShowVersion = func() {
		printGeneratorVersion()
		os.Exit(0)
	}

	_, err = flags.Parse(&opts)
	if err != nil {
		fmt.Printf("ERROR parsing arguments\n")
		os.Exit(1)
	}

	if _, err = os.Stat(opts.Sigdir); os.IsNotExist(err) {
		err = os.Mkdir(opts.Sigdir, 0770)
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

	var component_uuid [16]byte
	component_uuid, err = uuid.FromString(opts.UUID)
	if err != nil {
		fmt.Printf("UUID error(%d)", err)
		os.Exit(1)
	}

	var manufacturer_uuid [16]byte
	manufacturer_uuid, err = uuid.FromString(opts.Manufacturer)
	if err != nil {
		fmt.Printf("Manufacturer UUID error(%d)", err)
		os.Exit(1)
	}

	var serial [16]byte
	if len(opts.SerialUUID) > 0 {
		serial, err = uuid.FromString(opts.UUID)
		if err != nil {
			fmt.Printf("Serial UUID error(%d)", err)
			os.Exit(1)
		}
	} else if len(opts.Serial) > 0 {
		if len(opts.Serial) > 16 {
			fmt.Printf("Serial number string too long, max 16 characters.")
			os.Exit(1)
		}
		copy(serial[:], opts.Serial)
	} else {
		fmt.Printf("ERRPR: No serial number.")
		os.Exit(1)
	}

	if opts.Type == "board" {
		overrideEui := false
		if len(opts.Eui) > 0 {
			if len(opts.Eui) != 16 {
				fmt.Printf("ERROR specified override EUI64 '%s' is not suitable!", opts.Eui)
				os.Exit(1)
			}
			overrideEui = true
			eui, err = parseEui(opts.Eui)
			if err != nil {
				fmt.Printf("ERROR parsing EUI64: %s\n", err)
				os.Exit(1)
			}
		} else {
			eui, err = getEui(opts.Euifile)
			if err != nil {
				fmt.Printf("ERROR getting EUI64: %s\n", err)
				os.Exit(1)
			}
		}

		sigfile := filepath.Join(opts.Sigdir, fmt.Sprintf("EUI-64_%016X.bin", eui))
		if overrideEui == false {
			if _, err := os.Stat(sigfile); err == nil {
				fmt.Printf("ERROR generating sigdata: signature file for %016X exists at %s\n", eui, sigfile)
				os.Exit(1)
			}
		}

		esig, err := gen.ConstructEUISignature(timestamp, eui)
		if err != nil {
			fmt.Printf("ERROR generating sigdata: %s\n", err)
			os.Exit(1)
		}

		csig, err := gen.ConstructComponentSignature(timestamp, opts.Name, opts.Version, component_uuid, manufacturer_uuid, serial, opts.Position, SIGNATURE_TYPE_BOARD)
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

		if overrideEui == false {
			if err := markEui(opts.Euifile, *esig, *csig); err != nil {
				fmt.Printf("ERROR marking %016X in %s: %s\n", eui, opts.Euifile, err)
				os.Exit(1)
			}
		}

		sigdata = append(esigdata, csigdata...)

		if _, err := os.Stat(sigfile); err == nil {
			bakfile := sigfile + ".bak"
			if _, err := os.Stat(bakfile); err == nil {
				fmt.Printf("ERROR generating sigdata: signature file at %s and a backup file at %s exists for %016X\n", sigfile, bakfile, eui)
				os.Exit(1)
			}
			err := os.Rename(sigfile, bakfile)
			if err != nil {
				fmt.Printf("ERROR generating sigdata: creating backup file for %016X at %s failed: %s\n", eui, bakfile, err)
				os.Exit(1)
			}
		}

		if err := ioutil.WriteFile(sigfile, sigdata, 0440); err != nil {
			fmt.Printf("ERROR writing output file: %s\n", err)
			os.Exit(1)
		}

		if err := ioutil.WriteFile(opts.Output, sigdata, 0440); err != nil {
			fmt.Printf("ERROR writing output file: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("EUI-64: %016X\n", eui)

	} else if opts.Type == "platform" || opts.Type == "component" {
		var tp uint8
		if opts.Type == "platform" {
			tp = SIGNATURE_TYPE_PLATFORM
		} else if opts.Type == "component" {
			tp = SIGNATURE_TYPE_COMPONENT
		}

		if _, err := os.Stat(opts.Output); os.IsNotExist(err) {
			fmt.Printf("ERROR initial signature file %s not found!", opts.Output)
			os.Exit(1)
		}

		csig, err := gen.ConstructComponentSignature(timestamp, opts.Name, opts.Version, component_uuid, manufacturer_uuid, serial, opts.Position, tp)
		if err != nil {
			fmt.Printf("ERROR generating sigdata: %s\n", err)
			os.Exit(1)
		}

		csigdata, err := gen.Serialize(csig)
		if err != nil {
			fmt.Printf("ERROR generating sigdata: %s\n", err)
			os.Exit(1)
		}

		f, err := os.OpenFile(opts.Output, os.O_APPEND|os.O_WRONLY, 0440)
		if err != nil {
			fmt.Printf("ERROR opening output file: %s\n", err)
			os.Exit(1)
		}
		if _, err := f.Write(csigdata); err != nil {
			fmt.Printf("ERROR writing output file: %s\n", err)
			os.Exit(1)
		}
		if err := f.Close(); err != nil {
			fmt.Printf("ERROR closing output file: %s\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("%s is not a known signature type, supported types are: board, platform and component.")
		os.Exit(1)
	}

	if opts.Debug {
		printGeneratorVersion()
		fmt.Printf("Timestamp:    %d (%s)\n", timestamp.UTC().Unix(), TimestampString(timestamp.UTC()))
		fmt.Printf("Name:         %s\n", opts.Name)
		fmt.Printf("Version:      %s\n", opts.Version)
		if len(opts.SerialUUID) > 0 {
			uus, _ := uuid.FromBytes(serial[:])
			fmt.Printf("Serial:       %s\n", uus)
		} else {
			fmt.Printf("Serial:       %s\n", serial)
		}
		uuc, _ := uuid.FromBytes(component_uuid[:])
		fmt.Printf("UUID:         %s\n", uuc)
		uum, _ := uuid.FromBytes(manufacturer_uuid[:])
		fmt.Printf("Manufacturer: %s\n", uum)

		fmt.Printf("Output:       %s\n", opts.Output)
		fmt.Printf("Sigdir:       %s\n", opts.Sigdir)
		fmt.Printf("Euifile:      %s\n", opts.Euifile)

		//fmt.Printf("SIG(%d):\n", len(sigdata))
		//fmt.Printf("%X\n", sigdata[0:256])
		//fmt.Printf("%X\n", sigdata[256:512])
		//fmt.Printf("%X\n", sigdata[512:768])
	}

}
