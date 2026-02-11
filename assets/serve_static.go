//go:build bindata

//go:generate go tool asseter generate -src ./cdn

package assets

import (
	"github.com/pudottapommin/golib/vfs"
)

func BuiltinAssets() *vfs.Layer {
	return vfs.Blobs("builtin(bindata)", Assets)
}

func Url(path string) string {
	return "/static/" + Assets.HashedByPath(path)
}
