package internal

import (
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
)

type HTMLForm struct {
	Action string
	Method string
	Values url.Values
}

func ParseForms(node *html.Node) (forms []HTMLForm) {
	if node == nil {
		return nil
	}

	doc := goquery.NewDocumentFromNode(node)

	doc.Find("form").Each(func(_ int, s *goquery.Selection) {
		form := HTMLForm{Values: url.Values{}}
		form.Action, _ = s.Attr("action")
		form.Method, _ = s.Attr("method")

		s.Find("input").Each(func(_ int, s *goquery.Selection) {
			name, _ := s.Attr("name")
			if name == "" {
				return
			}

			typ, _ := s.Attr("type")
			typ = strings.ToLower(typ)

			_, checked := s.Attr("checked")
			if (typ == "radio" || typ == "checkbox") && !checked {
				return
			}

			value, _ := s.Attr("value")
			form.Values.Add(name, value)
		})

		s.Find("textarea").Each(func(_ int, s *goquery.Selection) {
			name, _ := s.Attr("name")
			if name == "" {
				return
			}

			value := s.Text()
			form.Values.Add(name, value)
		})

		forms = append(forms, form)
	})

	return forms
}
