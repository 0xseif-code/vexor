package wordlists

import "fmt"

type Category string

const (
	CategoryDirectory Category = "directory"
	CategorySubdomain Category = "subdomain"
	CategoryFuzz      Category = "fuzz"
)

type Size string

const (
	SizeSmall  Size = "small"
	SizeMedium Size = "medium"
	SizeLarge  Size = "large"

	SizeParameters     Size = "parameters"
	SizeExtensions     Size = "extensions"
	SizeUsernames      Size = "usernames"
	SizePasswords      Size = "passwords"
	SizePasswordsLarge Size = "passwords-large"
	SizeEndpoints      Size = "endpoints"
)

type Source struct {
	Category    Category
	Size        Size
	Name        string
	URL         string
	Description string
	Approximate int
}

var Registry = []Source{
	{
		Category:    CategoryDirectory,
		Size:        SizeSmall,
		Name:        "Raft Small Directories",
		URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
		Description: "Common web directory and file names derived from real-world wordlists.",
		Approximate: 17000,
	},
	{
		Category:    CategoryDirectory,
		Size:        SizeMedium,
		Name:        "Raft Medium Directories",
		URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
		Description: "Expanded web content discovery list covering typical webapp paths.",
		Approximate: 30000,
	},
	{
		Category:    CategoryDirectory,
		Size:        SizeLarge,
		Name:        "Raft Large Directories",
		URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt",
		Description: "Large web content discovery list for thorough crawling.",
		Approximate: 62000,
	},
	{
		Category:    CategorySubdomain,
		Size:        SizeSmall,
		Name:        "Top 1M Subdomains Top 5000",
		URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
		Description: "Most common subdomain names from the Alexa top 1 million domains.",
		Approximate: 5000,
	},
	{
		Category:    CategorySubdomain,
		Size:        SizeMedium,
		Name:        "Top 1M Subdomains Top 20000",
		URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
		Description: "Extended set of common subdomain names from the Alexa top 1 million.",
		Approximate: 20000,
	},
	{
		Category:    CategorySubdomain,
		Size:        SizeLarge,
		Name:        "Top 1M Subdomains Top 110000",
		URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
		Description: "Very large subdomain enumeration list for broad coverage.",
		Approximate: 110000,
	},
	{
		Category:    CategoryFuzz,
		Size:        SizeParameters,
		Name:        "Burp Parameter Names",
		URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
		Description: "HTTP parameter names for parameter discovery fuzzing.",
		Approximate: 99000,
	},
	{
		Category:    CategoryFuzz,
		Size:        SizeExtensions,
		Name:        "Web Extensions",
		URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/web-extensions.txt",
		Description: "Common web file extensions for extension-based fuzzing.",
		Approximate: 3000,
	},
	{
		Category:    CategoryFuzz,
		Size:        SizeUsernames,
		Name:        "Usernames",
		URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/xato-net-10-million-usernames.txt",
		Description: "Xato.net 10 million usernames (top common ones) for user enumeration.",
		Approximate: 8300000,
	},
	{
		Category:    CategoryFuzz,
		Size:        SizePasswords,
		Name:        "Common Passwords",
		URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
		Description: "Top 10,000 most common passwords.",
		Approximate: 10000,
	},
	{
		Category:    CategoryFuzz,
		Size:        SizePasswordsLarge,
		Name:        "RockYou Passwords",
		URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz",
		Description: "rockyou.txt full leak (compressed, ~50MB download).",
		Approximate: 14344000,
	},
	{
		Category:    CategoryFuzz,
		Size:        SizeEndpoints,
		Name:        "Web Endpoints",
		URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-words.txt",
		Description: "Common web/API endpoint names.",
		Approximate: 30000,
	},
}

func GetSource(cat Category, size Size) (*Source, error) {
	for i := range Registry {
		s := &Registry[i]
		if s.Category == cat && s.Size == size {
			return s, nil
		}
	}
	return nil, fmt.Errorf("%w: category=%q size=%q", ErrSourceNotFound, cat, size)
}

func ListByCategory(cat Category) []Source {
	var out []Source
	for i := range Registry {
		if Registry[i].Category == cat {
			out = append(out, Registry[i])
		}
	}
	return out
}

func AllSources() []Source {
	out := make([]Source, len(Registry))
	copy(out, Registry)
	return out
}
