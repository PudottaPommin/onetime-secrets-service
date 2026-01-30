package ui

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"

	"github.com/pudottapommin/onetime-secrets-service/assets"
	"github.com/pudottapommin/onetime-secrets-service/pkg/secrets"
)

//go:embed templates/*.gohtml
var templateFS embed.FS

var templateFn = template.FuncMap{
	"csrfInput": func(csrf FormModel) template.HTML {
		return template.HTML(fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`, csrf.CsrfField, csrf.CsrfToken))
	},
	"base64": func(b []byte) string {
		return base64.StdEncoding.EncodeToString(b)
	},
	"asset": func(path string) string {
		return assets.Url(path)
	},
	"arr": func(els ...any) []any {
		return els
	},
	"expirationRanges": func() map[int]string {
		return secrets.ExpirationRanges
	},
	"json": func(v any) template.JS {
		b, _ := json.Marshal(v)
		return template.JS(b)
	},
}

type templateBase struct {
	template *template.Template
}

type (
	indexTemplates  templateBase
	secretTemplates templateBase
)

var (
	indexPaths = []string{"templates/layout.gohtml", "templates/index*.gohtml"}
	Index      = indexTemplates{
		template: template.Must(
			template.New("index").
				Funcs(templateFn).
				ParseFS(templateFS, indexPaths...)),
	}
)

func (t indexTemplates) ExecutePage(w io.Writer, data PageIndex) error {
	return t.template.ExecuteTemplate(w, "index/page.html", data)
}

func (t indexTemplates) ExecuteHTMXSecretCreatedCard(w io.Writer, data CardSecretCreated) error {
	return t.template.ExecuteTemplate(w, "index/htmx/secret_created_card.html", data)
}
func (t indexTemplates) ExecuteHTMXSecretForm(w io.Writer, csrf FormModel) error {
	return t.template.ExecuteTemplate(w, "index/htmx/secret_form.html", csrf)
}
func (t indexTemplates) ExecuteHTMXSecretError(w io.Writer, err string) error {
	return t.template.ExecuteTemplate(w, "index/htmx/secret_error.html", err)
}
func (t indexTemplates) ExecuteHTMXAuthError(w io.Writer) error {
	return t.template.ExecuteTemplate(w, "index/htmx/auth_error.html", nil)
}

var (
	secretPaths = []string{"templates/layout.gohtml", "templates/secret*.gohtml"}
	Secret      = secretTemplates{
		template: template.Must(
			template.New("secret").
				Funcs(templateFn).
				ParseFS(templateFS, secretPaths...)),
	}
)

func (t secretTemplates) ExecutePage(w io.Writer, data PageSecret) error {
	return t.template.ExecuteTemplate(w, "secret/page.html", data)
}

func (t secretTemplates) ExecuteHTMXSecretDecrypted(w io.Writer, data CardSecretDecrypted) error {
	return t.template.ExecuteTemplate(w, "secret/htmx/secret_decrypted.html", data)
}
func (t secretTemplates) ExecuteHTMXSecretDecryptedFiles(w io.Writer, data CardSecretDecrypted) error {
	return t.template.ExecuteTemplate(w, "secret/htmx/decrypt_files.html", data)
}
func (t secretTemplates) ExecuteHTMXDecryptError(w io.Writer) error {
	return t.template.ExecuteTemplate(w, "secret/htmx/decrypt_error.html", nil)
}

func Recompile() {
	fs := os.DirFS("pkg/ui")

	Index.template = template.Must(
		template.New("index").
			Funcs(templateFn).
			ParseFS(fs, indexPaths...))

	Secret.template = template.Must(
		template.New("index").
			Funcs(templateFn).
			ParseFS(fs, secretPaths...))

}
