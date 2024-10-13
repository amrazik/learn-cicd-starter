package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Valid API key",
			headers:       http.Header{"Authorization": []string{"ApiKey some-valid-api-key"}},
			expectedKey:   "some-valid-api-key",
			expectedError: nil,
		},
		{
			name:          "No Authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed Authorization header (no ApiKey prefix)",
			headers:       http.Header{"Authorization": []string{"Bearer some-invalid-api-key"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Malformed Authorization header (missing key)",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Empty Authorization header",
			headers:       http.Header{"Authorization": []string{""}},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(test.headers)

			if apiKey != test.expectedKey {
				t.Errorf("expected API key %q, got %q", test.expectedKey, apiKey)
			}

			if err != nil && test.expectedError == nil {
				t.Errorf("unexpected error: %v", err)
			} else if err == nil && test.expectedError != nil {
				t.Errorf("expected error: %v, got no error", test.expectedError)
			} else if err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error() {
				t.Errorf("expected error: %v, got %v", test.expectedError, err)
			}
		})
	}
}
