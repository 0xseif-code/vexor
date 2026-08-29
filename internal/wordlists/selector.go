package wordlists

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
)

type Options struct {
	Category   Category
	Size       Size
	CustomPath string
}

type Selector struct {
	manager *Manager
}

func NewSelector(m *Manager) *Selector {
	return &Selector{manager: m}
}

func (s *Selector) Resolve(ctx context.Context, opts Options) (string, error) {
	if opts.CustomPath != "" {
		f, err := os.Open(opts.CustomPath)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrCustomPathInvalid, err)
		}
		defer f.Close()
		if st, err := f.Stat(); err != nil {
			return "", fmt.Errorf("%w: %v", ErrCustomPathInvalid, err)
		} else if st.IsDir() {
			return "", fmt.Errorf("%w: %s is a directory", ErrCustomPathInvalid, opts.CustomPath)
		}
		return opts.CustomPath, nil
	}

	if opts.Size == "" {
		opts.Size = SizeMedium
	}

	path, err := s.manager.Ensure(ctx, opts.Category, opts.Size)
	if err != nil {
		return "", fmt.Errorf("resolve wordlist %s/%s: %w", opts.Category, opts.Size, err)
	}
	return path, nil
}

func (s *Selector) Load(ctx context.Context, opts Options) ([]string, error) {
	path, err := s.Resolve(ctx, opts)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wordlist %s: %w", path, err)
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var words []string

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		words = append(words, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read wordlist %s: %w", path, err)
	}
	return words, nil
}

func (s *Selector) LoadStream(ctx context.Context, opts Options) (<-chan string, <-chan error, error) {
	path, err := s.Resolve(ctx, opts)
	if err != nil {
		return nil, nil, err
	}

	words := make(chan string, 64)
	errs := make(chan error, 1)

	go func() {
		defer close(words)
		defer close(errs)

		f, err := os.Open(path)
		if err != nil {
			errs <- fmt.Errorf("open wordlist %s: %w", path, err)
			return
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			select {
			case words <- line:
			case <-ctx.Done():
				errs <- ctx.Err()
				return
			}
		}
		if err := sc.Err(); err != nil {
			errs <- fmt.Errorf("read wordlist %s: %w", path, err)
		}
	}()

	return words, errs, nil
}
