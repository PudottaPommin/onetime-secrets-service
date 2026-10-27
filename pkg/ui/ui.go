package ui

import (
	"embed"
	"encoding/json/v2"
	"fmt"
	"html/template"
	"io"
	"os"

	"github.com/pudottapommin/onetime-secrets-service/assets"
	"github.com/pudottapommin/onetime-secrets-service/pkg/secrets"
)

//go:embed templates/*.gohtml
var templateFS embed.FS

var templateFn = template.FuncMap{ //nolint:gochecknoglobals // noop
	"csrfInput": func(csrf FormModel) template.HTML {
		return template.HTML( //nolint:gosec // noop
			fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`, csrf.CsrfField, csrf.CsrfToken),
		)
	},
	"asset": assets.URL,
	"arr": func(els ...any) []any {
		return els
	},
	"expirationRanges": func() map[int]string {
		return secrets.ExpirationRanges
	},
	"json": func(v any) template.JS {
		b, _ := json.Marshal(v)
		return template.JS(b) //nolint:gosec // noop
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
	indexPaths = []string{"templates/layout.gohtml", "templates/index*.gohtml"} //nolint:gochecknoglobals // noop
	Index      = indexTemplates{                                                //nolint:gochecknoglobals // noop
		template: template.Must(
			template.New("index").
				Funcs(templateFn).
				ParseFS(templateFS, indexPaths...)),
	}
)

func (t indexTemplates) ExecutePage(w io.Writer, data PageIndex) error {
	if err := t.template.ExecuteTemplate(w, "index/page.html", data); err != nil {
		return fmt.Errorf("failed to execute index/page.html template: %w", err)
	}
	return nil
}

func (t indexTemplates) ExecuteHTMXSecretCreatedCard(w io.Writer, data CardSecretCreated) error {
	if err := t.template.ExecuteTemplate(w, "index/htmx/secret_created_card.html", data); err != nil {
		return fmt.Errorf("failed to execute index/htmx/secret_created_card.html template: %w", err)
	}
	return nil
}

func (t indexTemplates) ExecuteHTMXSecretForm(w io.Writer, csrf FormModel) error {
	if err := t.template.ExecuteTemplate(w, "index/htmx/secret_form.html", csrf); err != nil {
		return fmt.Errorf("failed to execute index/htmx/secret_form.html template: %w", err)
	}
	return nil
}

func (t indexTemplates) ExecuteHTMXSecretError(w io.Writer, err string) error {
	if execErr := t.template.ExecuteTemplate(w, "index/htmx/secret_error.html", err); execErr != nil {
		return fmt.Errorf("failed to execute index/htmx/secret_error.html template: %w", execErr)
	}
	return nil
}

func (t indexTemplates) ExecuteHTMXAuthError(w io.Writer) error {
	if err := t.template.ExecuteTemplate(w, "index/htmx/auth_error.html", nil); err != nil {
		return fmt.Errorf("failed to execute index/htmx/auth_error.html template: %w", err)
	}
	return nil
}

var (
	secretPaths = []string{"templates/layout.gohtml", "templates/secret*.gohtml"} //nolint:gochecknoglobals // noop
	Secret      = secretTemplates{                                                //nolint:gochecknoglobals // noop
		template: template.Must(
			template.New("secret").
				Funcs(templateFn).
				ParseFS(templateFS, secretPaths...)),
	}
)

func (t secretTemplates) ExecutePage(w io.Writer, data PageSecret) error {
	if err := t.template.ExecuteTemplate(w, "secret/page.html", data); err != nil {
		return fmt.Errorf("failed to execute secret/page.html template: %w", err)
	}
	return nil
}

func (t secretTemplates) ExecuteHTMXSecretDecrypted(w io.Writer, data CardSecretDecrypted) error {
	if err := t.template.ExecuteTemplate(w, "secret/htmx/secret_decrypted.html", data); err != nil {
		return fmt.Errorf("failed to execute secret/htmx/secret_decrypted.html template: %w", err)
	}
	return nil
}

func (t secretTemplates) ExecuteHTMXDecryptError(w io.Writer) error {
	if err := t.template.ExecuteTemplate(w, "secret/htmx/decrypt_error.html", nil); err != nil {
		return fmt.Errorf("failed to execute secret/htmx/decrypt_error.html template: %w", err)
	}
	return nil
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
