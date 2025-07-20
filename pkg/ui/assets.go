package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets/*
var assetsFS embed.FS

func StaticMiddleware() func(http.Handler) http.Handler {
	afs, _ := fs.Sub(assetsFS, "assets")
	fileServer := http.FileServerFS(afs)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := assetsFS.Open("assets" + r.URL.Path)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			fileServer.ServeHTTP(w, r)
		})
	}
}
