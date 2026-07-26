// Command publish-directory atomically publishes a complete release directory
// without replacing an existing destination.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 3 {
		fatal(errors.New("usage: publish-directory STAGED_DIRECTORY NEW_DESTINATION"))
	}
	if err := publishDirectory(os.Args[1], os.Args[2]); err != nil {
		fatal(err)
	}
}

func publishDirectory(source, destination string) error {
	source, destination, err := canonicalPublicationPaths(source, destination)
	if err != nil {
		return err
	}
	sourceInfo, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !sourceInfo.IsDir() || sourceInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("staged release must be a real directory")
	}
	if err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("release content must not contain symbolic links: %s", path)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("release content must contain only directories and regular files: %s", path)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := renameNoReplace(source, destination); err != nil {
		return fmt.Errorf("publish release directory: %w", err)
	}
	return nil
}

func canonicalPublicationPaths(source, destination string) (string, string, error) {
	sourceAbs, err := filepath.Abs(source)
	if err != nil {
		return "", "", err
	}
	destinationAbs, err := filepath.Abs(destination)
	if err != nil {
		return "", "", err
	}
	for label, path := range map[string]string{"source": sourceAbs, "destination": destinationAbs} {
		base := filepath.Base(path)
		if base == "." || base == string(filepath.Separator) {
			return "", "", fmt.Errorf("%s must name a child of its parent", label)
		}
	}
	sourceParent, err := filepath.EvalSymlinks(filepath.Dir(sourceAbs))
	if err != nil {
		return "", "", err
	}
	destinationParent, err := filepath.EvalSymlinks(filepath.Dir(destinationAbs))
	if err != nil {
		return "", "", err
	}
	if sourceParent != destinationParent {
		return "", "", errors.New("staged release and destination must have the same real parent")
	}
	return filepath.Join(sourceParent, filepath.Base(sourceAbs)),
		filepath.Join(destinationParent, filepath.Base(destinationAbs)), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
