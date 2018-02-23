package ban

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
)

// store can load and store PrefixedIPs.
type store struct {
	path string
}

// newStore at path.
func newStore(path string) *store {
	return &store{path: path}
}

// Add PrefixedIP to store.
//
// Return an error if the file can't be written to.
func (s *store) Add(pip *PrefixedIP) error {
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintf(f, "%v\n", pip)
	return nil
}

// PrefixedIPs in store.
//
// Return an error if the file can't be read.
func (s *store) PrefixedIPs() ([]*PrefixedIP, error) {
	bs, err := ioutil.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var pips []*PrefixedIP
	for _, line := range bytes.Split(bs, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		pip, err := ParsePrefixedIP(string(line))
		if err != nil {
			return nil, err
		}
		pips = append(pips, pip)
	}
	return pips, nil
}
