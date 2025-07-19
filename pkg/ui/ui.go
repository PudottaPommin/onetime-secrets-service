package ui

import (
	"embed"
	"html/template"
	"io"

	"github.com/pudottapommin/secret-notes/pkg/secrets"
)

//go:embed templates/*.gohtml
var templateFS embed.FS

var tplIndex = template.Must(template.New("").Funcs(template.FuncMap{
	"expirationRanges": func() map[int]string {
		return secrets.ExpirationRanges
	},
}).ParseFS(templateFS, "templates/layout.gohtml", "templates/page_index.gohtml"))

func RenderPageIndex(w io.Writer) error {
	return tplIndex.ExecuteTemplate(w, "page_index.html", nil)
}

var tplSecret = template.Must(template.New("").ParseFS(templateFS, "templates/layout.gohtml", "templates/page_secret.gohtml"))

func RenderPageSecret(w io.Writer, data PageSecret) error {
	return tplSecret.ExecuteTemplate(w, "page_secret.html", data)
}

var tplCardSecretCreated = template.Must(template.New("").ParseFS(templateFS, "templates/card_secret_created.gohtml"))

func RenderCardSecretCreated(w io.Writer, data CardSecretCreated) error {
	return tplCardSecretCreated.ExecuteTemplate(w, "card_secret_created.html", data)
}

var tplCardSecretDecrypted = template.Must(template.New("").ParseFS(templateFS, "templates/card_secret_decrypted.gohtml"))

func RenderCardSecretDecrypted(w io.Writer, data CardSecretDecrypted) error {
	return tplCardSecretDecrypted.ExecuteTemplate(w, "card_secret_decrypted.html", data)
}
