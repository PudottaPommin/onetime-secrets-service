package ui

type PageSecret struct {
	NotFound  bool
	Url       string
	Secret    string
	Password  *string
	ViewsLeft uint64
}
