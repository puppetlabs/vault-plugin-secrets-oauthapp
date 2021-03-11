package interop

// JSONToken represents the JSON response of an access token request.
//
// It is different from an oauth2.Token, which is also serializable as JSON, but
// does not correspond to the response data.
type JSONToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int32  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}
