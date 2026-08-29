package crawler

import (
	"strings"

	"golang.org/x/net/html"
)

// form is an extracted HTML form.
type form struct {
	action string
	fields map[string]string
	method string
}

// extractPage walks an HTML document and returns all links and forms. Links
// come from <a href>, <form action>, <script src>, <link href>, <iframe src>
// and <area href>. It is best-effort: JS-heavy SPAs yield few static links, a
// documented limitation.
func extractPage(body []byte, pageURL string) (links []string, forms []form) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, nil
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a", "area":
				if h := attr(n, "href"); h != "" {
					links = addLink(links, h)
				}
			case "link":
				if h := attr(n, "href"); h != "" {
					links = addLink(links, h)
				}
			case "script":
				if src := attr(n, "src"); src != "" {
					links = addLink(links, src)
				}
			case "iframe":
				if src := attr(n, "src"); src != "" {
					links = addLink(links, src)
				}
			case "form":
				forms = append(forms, extractForm(n))
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return links, forms
}

func addLink(links []string, href string) []string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") ||
		strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") ||
		strings.HasPrefix(href, "tel:") || strings.HasPrefix(href, "data:") {
		return links
	}
	return append(links, href)
}

// extractForm collects a form's action, method and input fields.
func extractForm(n *html.Node) form {
	f := form{
		action: attr(n, "action"),
		method: strings.ToUpper(attr(n, "method")),
		fields: map[string]string{},
	}
	if f.method == "" {
		f.method = "GET"
	}
	collectFields(n, f.fields)
	return f
}

func collectFields(n *html.Node, out map[string]string) {
	if n.Type == html.ElementNode {
		switch n.Data {
		case "input":
			name := attr(n, "name")
			if name == "" {
				break
			}
			typ := strings.ToLower(attr(n, "type"))
			if typ == "submit" || typ == "button" || typ == "image" || typ == "reset" {
				break
			}
			val := attr(n, "value")
			if typ == "password" {
				val = "FUZZ_" + name
			}
			out[name] = val
		case "textarea":
			name := attr(n, "name")
			if name != "" {
				out[name] = attr(n, "value")
			}
		case "select":
			name := attr(n, "name")
			if name == "" {
				break
			}
			if v := firstOptionValue(n); v != "" {
				out[name] = v
			} else {
				out[name] = "FUZZ_" + name
			}
		}
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		collectFields(child, out)
	}
}

func firstOptionValue(n *html.Node) string {
	if n.Type == html.ElementNode && n.Data == "option" {
		if v := attr(n, "value"); v != "" {
			return v
		}
		// Use inner text as fallback.
		if t := textContent(n); t != "" {
			return t
		}
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if v := firstOptionValue(child); v != "" {
			return v
		}
	}
	return ""
}

func textContent(n *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			sb.WriteString(node.Data)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return strings.TrimSpace(sb.String())
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}
