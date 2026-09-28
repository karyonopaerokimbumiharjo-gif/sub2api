package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestNativePiImagesUseBoundTransportAndExistingAccounting(t *testing.T) {
	for _, endpoint := range []string{"generations", "edits"} {
		for _, streaming := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%v", endpoint, streaming), func(t *testing.T) {
				calls := 0
				runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					require.Equal(t, "/images", r.URL.Path)
					var payload struct {
						OwnerID      int64          `json:"owner_id"`
						CredentialID int64          `json:"credential_id"`
						AccountID    string         `json:"account_id"`
						AccessToken  string         `json:"access_token"`
						Endpoint     string         `json:"endpoint"`
						Request      map[string]any `json:"request"`
					}
					require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
					require.Equal(t, int64(42), payload.OwnerID)
					require.Equal(t, int64(7), payload.CredentialID)
					require.Equal(t, "fixture-account", payload.AccountID)
					require.Equal(t, "fixture-access", payload.AccessToken)
					require.Equal(t, "/images/"+endpoint, payload.Endpoint)
					require.Equal(t, "gpt-image-2.5-sunburst", payload.Request["model"])
					require.Equal(t, "low", payload.Request["quality"])
					if endpoint == "edits" {
						require.Contains(t, payload.Request, "images")
					}
					if streaming {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = io.WriteString(w, "data: {\"type\":\"image_generation.completed\",\"b64_json\":\"aGVsbG8=\",\"output_format\":\"png\",\"usage\":{\"input_tokens\":10,\"output_tokens\":20}}\n\n")
					} else {
						w.Header().Set("Content-Type", "application/json")
						fixture := openAIImagesJSONResponse()
						defer fixture.Body.Close()
						_, _ = io.Copy(w, fixture.Body)
					}
				}))
				defer runtime.Close()
				secret := filepath.Join(t.TempDir(), "secret")
				require.NoError(t, os.WriteFile(secret, []byte(strings.Repeat("s", 40)), 0600))
				t.Setenv("PI_RUNTIME_URL", runtime.URL)
				t.Setenv("PI_RUNTIME_SECRET_FILE", secret)
				account := nativePiAccount()
				account.Credentials["expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
				payload := map[string]any{"model": "gpt-image-2.5-sunburst", "prompt": "A blue circle.", "quality": "low", "size": "1024x1024", "stream": streaming}
				if endpoint == "edits" {
					payload["images"] = []map[string]string{{"image_url": "data:image/png;base64,aGVsbG8="}}
				}
				body, _ := json.Marshal(payload)
				c, rec := newOpenAIImagesTestContext(t, body)
				c.Request.URL.Path = "/v1/images/" + endpoint
				c.Set("api_key", nativePiTestKey(42))
				svc := newOpenAIImagesTestService(&httpUpstreamRecorder{})
				svc.openAITokenProvider = NewOpenAITokenProvider(nil, nil, nil)
				parsed, err := svc.ParseOpenAIImagesRequest(c, body)
				require.NoError(t, err)
				result, err := svc.ForwardImages(context.Background(), c, account, body, parsed, "")
				require.NoError(t, err)
				require.Equal(t, 1, calls)
				require.Equal(t, 1, result.ImageCount)
				require.Equal(t, "gpt-image-2.5-sunburst", result.UpstreamModel)
				require.Equal(t, "/backend-api/codex/images/"+endpoint, result.UpstreamEndpoint)
				require.Equal(t, 20, result.Usage.ImageOutputTokens)
				require.Contains(t, rec.Body.String(), "aGVsbG8=")
			})
		}
	}
}

func TestNativePiAdminImageTestReturnsImageEvent(t *testing.T) {
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/images", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fixture := openAIImagesJSONResponse()
		defer fixture.Body.Close()
		_, _ = io.Copy(w, fixture.Body)
	}))
	defer runtime.Close()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte(strings.Repeat("s", 40)), 0600))
	t.Setenv("PI_RUNTIME_URL", runtime.URL)
	t.Setenv("PI_RUNTIME_SECRET_FILE", secret)
	account := nativePiAccount()
	account.Credentials["expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
	svc := &AccountTestService{openaiGatewayService: &OpenAIGatewayService{cfg: &config.Config{}, openAITokenProvider: NewOpenAITokenProvider(nil, nil, nil)}}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/test", nil)
	require.NoError(t, svc.testNativePiAccount(c, account, "gpt-image-2", "A blue circle.", "default"))
	require.Contains(t, rec.Body.String(), `"type":"image"`)
	require.Contains(t, rec.Body.String(), `"success":true`)
	require.NotContains(t, rec.Body.String(), `"type":"error"`)
}

func TestNativePiImageCapabilitiesMatchImplementedEndpoints(t *testing.T) {
	account := nativePiAccount()
	require.True(t, account.SupportsOpenAIImageCapability(OpenAIImagesCapabilityNative))
	require.True(t, account.SupportsOpenAIImageCapability(OpenAIImagesCapabilityBasic))
	require.False(t, account.SupportsOpenAIImageCapability(OpenAIImagesCapabilityAPIKey))
}

func TestNativePiResponsesImageToolRetainsImageBilling(t *testing.T) {
	for _, tc := range []struct{ streaming, partial bool }{{false, false}, {true, false}, {true, true}} {
		streaming := tc.streaming
		t.Run(fmt.Sprintf("stream=%v/partial=%v", streaming, tc.partial), func(t *testing.T) {
			calls := 0
			runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				require.Equal(t, "/responses", r.URL.Path)
				var payload struct {
					Request map[string]any `json:"request"`
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
				require.Equal(t, openAIImagesResponsesMainModelValue(), payload.Request["model"])
				tool := payload.Request["tools"].([]any)[0].(map[string]any)
				require.Equal(t, "image_generation", tool["type"])
				require.Equal(t, "gpt-image-2", tool["model"])
				w.Header().Set("Content-Type", "text/event-stream")
				if tc.partial {
					_, _ = io.WriteString(w, "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"image_generation_call\",\"id\":\"ig_test\",\"status\":\"completed\",\"result\":\"aGVsbG8=\"}}\n\n")
					return
				}
				_, _ = fmt.Fprintf(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_image\",\"status\":\"completed\",\"model\":%q,\"output\":[{\"type\":\"image_generation_call\",\"id\":\"ig_test\",\"status\":\"completed\",\"result\":\"aGVsbG8=\"}],\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}}\n\n", openAIImagesResponsesMainModelValue())
			}))
			defer runtime.Close()
			secret := filepath.Join(t.TempDir(), "secret")
			require.NoError(t, os.WriteFile(secret, []byte(strings.Repeat("s", 40)), 0600))
			t.Setenv("PI_RUNTIME_URL", runtime.URL)
			t.Setenv("PI_RUNTIME_SECRET_FILE", secret)
			account := nativePiAccount()
			account.Credentials["expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
			svc := &OpenAIGatewayService{cfg: &config.Config{}, toolCorrector: NewCodexToolCorrector(), openAITokenProvider: NewOpenAITokenProvider(nil, nil, nil)}
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
			key := nativePiTestKey(42)
			key.Group.AllowImageGeneration = true
			c.Set("api_key", key)
			body := []byte(fmt.Sprintf(`{"model":"gpt-image-2","input":"Draw a blue circle.","stream":%v}`, streaming))
			result, err := svc.Forward(context.Background(), c, account, body)
			if tc.partial {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.NotNil(t, result)
			require.Equal(t, 1, result.ImageCount)
			require.Equal(t, "gpt-image-2", result.BillingModel)
			require.Contains(t, rec.Body.String(), "aGVsbG8=")
			require.Equal(t, 1, calls)
			blockedRec := httptest.NewRecorder()
			blocked, _ := gin.CreateTestContext(blockedRec)
			blocked.Request = httptest.NewRequest("POST", "/v1/responses", nil)
			key.Group.AllowImageGeneration = false
			blocked.Set("api_key", key)
			_, err = svc.Forward(context.Background(), blocked, account, body)
			require.Error(t, err)
			require.Equal(t, 403, blockedRec.Code)
			require.Equal(t, 1, calls, "disabled group must not reach the runtime")
		})
	}
}
