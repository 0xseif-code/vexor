package auth

import (
	"strings"

	"golang.org/x/net/html"
)

// htmlDoc is a parsed HTML document that can extract CSRF tokens.
type htmlDoc struct {
	root *html.Node
}

// parseHTML parses an HTML body string into a document. It is lenient and
// returns nil on any parse error so callers can degrade gracefully.
func parseHTML(body string) (*htmlDoc, error) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	return &htmlDoc{root: doc}, nil
}

// token searches the document for a CSRF token named `name`, checking hidden
// form inputs, then meta tags. It returns the token value and whether it was
// found.
func (d *htmlDoc) token(name string) (string, bool) {
	if d == nil || d.root == nil {
		return "", false
	}
	var found string
	walk(d.root, func(n *html.Node) {
		if found != "" {
			return
		}
		if n.Type == html.ElementNode && n.Data == "input" {
			if isHiddenInput(n) && attr(n, "name") == name {
				found = attr(n, "value")
			}
		}
		if n.Type == html.ElementNode && n.Data == "meta" {
			// <meta name="csrf" content="..."> and <meta property="...">
			mn := attr(n, "name")
			mp := attr(n, "property")
			httpEquiv := attr(n, "http-equiv")
			if (mn == name || mp == name || httpEquiv == name) &&
				(mn != "" || mp != "" || httpEquiv != "") {
				content := attr(n, "content")
				value := attr(n, "value")
				if content != "" {
					found = content
				} else if value != "" {
					found = value
				}
			}
		}
	})
	return found, found != ""
}

func walk(n *html.Node, fn func(*html.Node)) {
	if n == nil {
		return
	}
	fn(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, fn)
	}
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func isHiddenInput(n *html.Node) bool {
	t := attr(n, "type")
	return t == "" || strings.EqualFold(t, "hidden")
}
