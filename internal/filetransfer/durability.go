package filetransfer

import (
	"errors"
	"fmt"
	"os"
)

// syncDirectory is a variable so durability failure paths can be tested
// without depending on filesystem-specific fault injection.
var syncDirectory = platformSyncDirectory

func syncRootDir(root *os.Root) error {
	if root == nil {
		return fmt.Errorf("%w: nil directory root", ErrDurability)
	}
	if err := syncDirectory(root); err != nil {
		return errors.Join(ErrDurability, err)
	}
	return nil
}
