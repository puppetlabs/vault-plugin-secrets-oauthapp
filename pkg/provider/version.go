package provider

var defaultVersion = -1

func selectVersion(in, def int) int {
	if in == defaultVersion {
		return def
	}

	return in
}
