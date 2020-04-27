package file

import (
	"encoding/csv"
	"os"
	"sync"
)

type Htpasswd struct {
	*os.File

	fileInfo os.FileInfo
	mu       sync.Mutex

	users map[string]string
}

func (f *Htpasswd) load() error {
	csvReader := csv.NewReader(f)
	csvReader.Comma = ':'
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true

	records, err := csvReader.ReadAll()
	if err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.users = make(map[string]string)
	for _, record := range records {
		f.users[record[0]] = record[1]
	}

	return nil
}

func (f *Htpasswd) GetUsers() (map[string]string, error) {
	fileInfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if f.fileInfo == nil || f.fileInfo.ModTime() != fileInfo.ModTime() {
		f.fileInfo = fileInfo
		if err := f.load(); err != nil {
			return nil, err
		}
	}
	return f.users, nil
}

func OpenHtpasswd(name string) (*Htpasswd, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	return &Htpasswd{
		File:  file,
		users: map[string]string{},
	}, nil
}
