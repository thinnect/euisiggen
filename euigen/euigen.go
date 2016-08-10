// Author  Raido Pahtma
// License MIT

package main

import "os"
import "fmt"
import "strconv"
import "errors"
import "bufio"
import "time"

import "github.com/jessevdk/go-flags"

type Eui64 uint64

func (self Eui64) String() string {
	return fmt.Sprintf("%016X", uint64(self))
}

func (self Eui64) Canonical() string {
	var i uint8
	s := ""
	for i = 7; i > 0; i-- {
		s = fmt.Sprintf("%s%02X-", s, uint8(self>>(8*i)))
	}
	return fmt.Sprintf("%s%02X", s, uint8(self))
}

func (self *Eui64) UnmarshalFlag(s string) error {
	if len(s) != 16 {
		return errors.New(fmt.Sprintf("%s is not a valid EUI-64, length %d != 16", s, len(s)))
	}

	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return errors.New(fmt.Sprintf("%s is not a valid EUI-64", s))
	}

	*self = Eui64(v)

	return nil
}

func (v Eui64) MarshalFlag() (string, error) {
	return fmt.Sprintf("%016X", v), nil
}

func generate(first Eui64, last Eui64, euifile string, lstfile string) error {
	euiout, err := os.OpenFile(euifile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0660)
	if err != nil {
		return err
	}
	defer euiout.Close()

	lstout, err := os.OpenFile(lstfile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0660)
	if err != nil {
		return err
	}
	defer lstout.Close()

	euiwriter := bufio.NewWriter(euiout)
	defer euiwriter.Flush()

	lstwriter := bufio.NewWriter(lstout)
	defer lstwriter.Flush()

	ts := time.Now().UTC().Format("2006-01-02 15:04:05 MST")
	_, err = euiwriter.WriteString(fmt.Sprintf("# EUI-64 range %s - %s, %s\n", first, last, ts))
	if err != nil {
		return err
	}

	_, err = lstwriter.WriteString(fmt.Sprintf("# EUI-64 range %s - %s, %s\n", first.Canonical(), last.Canonical(), ts))
	if err != nil {
		return err
	}

	for current := first; current <= last; current++ {
		short := uint16(current)
		if short == 0 || short == 0xFFFF {
			_, err = euiwriter.WriteString(fmt.Sprintf("%s,RESERVED\n", current))
		} else {
			_, err = euiwriter.WriteString(fmt.Sprintf("%s,\n", current))
		}
		if err != nil {
			return err
		}
		_, err = lstwriter.WriteString(fmt.Sprintf("%s\n", current.Canonical()))
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	var opts struct {
		First      Eui64  `long:"first" required:"true" description:"Start of the EUI64 range."`
		Last       Eui64  `long:"last" required:"true" description:"End of the EUI64 range."`
		EuiOutput  string `long:"euiout" default:"eui.txt" description:"The EUI-64 output file name."`
		ListOutput string `long:"listout" default:"list.txt" description:"The EUI-64 canonical form output file name."`
	}

	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	fmt.Printf("EUI-64 output: %s\n", opts.EuiOutput)
	fmt.Printf("EUI-64 canonical list output: %s\n", opts.ListOutput)
	fmt.Printf("EUI range %s - %s\n", opts.First.Canonical(), opts.Last.Canonical())

	err = generate(opts.First, opts.Last, opts.EuiOutput, opts.ListOutput)
	if err != nil {
		fmt.Println("Error generating EUI files:", err)
		os.Exit(1)
	}

}
