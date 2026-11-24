package persist

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Prepare creates dir (mode 0700) if needed and makes sure it is writable.
func Prepare(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("state_dir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("state_dir %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".writable-*")
	if err != nil {
		return fmt.Errorf("state_dir %s is not writable: %w", dir, err)
	}
	name := f.Name()
	f.Close()
	_ = os.Remove(name)
	return nil
}

// writeAtomic writes data to dir/name (mode 0600) and fsyncs the file and the directory.
func writeAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, name+".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		return err
	}
	cleanup = false
	return syncDir(dir)
}

// appendLine appends line and a newline. It does not fsync: callers
// make it durable with syncFile, so several appends can share one fsync.
func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// syncFile fsyncs the file at path, including data written through
// other handles.
func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// syncDir fsyncs a directory so a rename or a new file survives a crash.
// Windows has no directory fsync (FlushFileBuffers on a directory handle
// fails with "Access is denied"), and NTFS journals renames itself, so it
// is skipped there.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	_ = d.Close()
	return err
}

func fileMode(path string) (os.FileMode, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return st.Mode().Perm(), nil
}

// WriteFile writes data to dir/name (mode 0600) atomically and fsyncs.
func WriteFile(dir, name string, data []byte) error {
	if err := Prepare(dir); err != nil {
		return err
	}
	return writeAtomic(dir, name, data)
}
