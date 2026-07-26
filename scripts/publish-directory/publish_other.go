//go:build !darwin && !linux

package main

import "errors"

func renameNoReplace(_, _ string) error {
	return errors.New("atomic no-replace directory publication is unsupported on this platform")
}
