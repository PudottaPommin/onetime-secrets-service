package encryption

type (
	Marshaler interface {
		MarshalEncrypt() ([]byte, error)
	}
	Unmarshaler interface {
		UnmarshalEncrypt([]byte) error
	}
)
