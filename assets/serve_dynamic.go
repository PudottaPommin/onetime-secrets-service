//go:build !bindata

package assets

import (
	"github.com/pudottapommin/golib/pkg/assetsfs"
)

func BuiltinAssets() *assetsfs.Layer {
	return assetsfs.Local("builtin(dynamic)", ".", "assets/cdn")
}

func Url(path string) string {
	return "/static/" + path
}
