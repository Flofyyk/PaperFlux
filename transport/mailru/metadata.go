package mailru

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"universal-bypass-tool/utils"
)

func (t *MailruDocsTransport) fetchDocInfo(weblink string) (MailruDocsInfo, error) {
	t.jarMu.RLock()
	jar := t.cookieJar
	t.jarMu.RUnlock()
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second}
	return t.fetchDocInfoFrom(client, "https://cloud.mail.ru/api/v4/r7/edit", weblink)
}

func (t *MailruDocsTransport) fetchDocInfoFrom(client *http.Client, apiURL, weblink string) (MailruDocsInfo, error) {
	t.metadataMu.Lock()
	defer t.metadataMu.Unlock()
	if remaining := time.Until(t.verificationRetryAt); remaining > 0 {
		return MailruDocsInfo{}, &mailruVerificationError{RetryAfter: remaining}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	done := t.Done()
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()

	reqBody := map[string]string{
		"x-email":  "anonym",
		"public":   "/" + weblink,
		"platform": "desktop_web",
	}
	jsonData, _ := json.Marshal(reqBody)

	utils.Debugf("[M-DOCS] fetch document metadata")

	api, err := url.Parse(apiURL)
	if err != nil || api.Host == "" || api.User != nil {
		return MailruDocsInfo{}, fmt.Errorf("invalid Mail.ru API request")
	}
	// Keep the shared cookie jar, but never follow a provider redirect off-origin.
	guarded := *client
	guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != api.Scheme || req.URL.Host != api.Host || req.URL.User != nil {
			return fmt.Errorf("Mail.ru API redirect rejected")
		}
		req.Header.Set("User-Agent", mailruUserAgent)
		if client.CheckRedirect != nil {
			return client.CheckRedirect(req, via)
		}
		return nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		// Recreate the POST from the original data: the challenge's redirect can
		// legitimately finish at the API by GET (405), which is not our retry.
		req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonData))
		if err != nil {
			return MailruDocsInfo{}, fmt.Errorf("invalid Mail.ru API request")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/plain, */*")
		req.Header.Set("User-Agent", mailruUserAgent)
		req.Header.Set("X-Api-Version", "4")
		req.Header.Set("Referer", fmt.Sprintf("https://cloud.mail.ru/public/%s?weblink=%s", weblink, weblink))
		resp, err := guarded.Do(req)
		if err != nil {
			// URL errors can expose document links or signed challenge parameters.
			if ctx.Err() != nil {
				return MailruDocsInfo{}, ctx.Err()
			}
			return MailruDocsInfo{}, fmt.Errorf("Mail.ru API connection failed")
		}
		body, readErr := readMailruMetadataResponse(resp)
		if readErr != nil {
			if resp.StatusCode == http.StatusTooManyRequests {
				return MailruDocsInfo{}, t.deferMailruVerification(resp.Header.Get("Retry-After"))
			}
			return MailruDocsInfo{}, readErr
		}
		if isMailru429Page(body) {
			if attempt == 0 {
				confirmationErr := t.confirmMailru429(ctx, &guarded, resp.Request.URL, body)
				if ctx.Err() != nil {
					return MailruDocsInfo{}, ctx.Err()
				}
				if confirmationErr == nil {
					utils.Infof("[M-DOCS] browser verification completed; retrying document request")
					continue
				}
				utils.Debugf("[M-DOCS] browser verification failed: %v", confirmationErr)
			}
			return MailruDocsInfo{}, t.deferMailruVerification(resp.Header.Get("Retry-After"))
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return MailruDocsInfo{}, t.deferMailruVerification(resp.Header.Get("Retry-After"))
		}
		if resp.StatusCode != http.StatusOK {
			return MailruDocsInfo{}, fmt.Errorf("API returned status %d", resp.StatusCode)
		}
		info, err := parseMailruDocInfo(body)
		if err == nil {
			t.verificationFailures = 0
			t.verificationRetryAt = time.Time{}
		}
		return info, err
	}
	return MailruDocsInfo{}, t.deferMailruVerification("")
}

func readMailruMetadataResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	const maxMetadata = 2 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadata+1))
	if err != nil {
		return nil, fmt.Errorf("Mail.ru API response could not be read")
	}
	if len(body) > maxMetadata {
		return nil, fmt.Errorf("Mail.ru API response too large")
	}
	return body, nil
}

func parseMailruDocInfo(bodyBytes []byte) (MailruDocsInfo, error) {

	var res map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return MailruDocsInfo{}, fmt.Errorf("failed to parse JSON: %w", err)
	}

	apiBase, _ := res["api"].(string)
	token, _ := res["token"].(string)

	document, ok := res["document"].(map[string]interface{})
	if !ok || document == nil {
		return MailruDocsInfo{}, fmt.Errorf("document object missing")
	}

	docKey, _ := document["key"].(string)
	fileType, _ := document["fileType"].(string)
	docURL, _ := document["url"].(string)
	docTitle, _ := document["title"].(string)
	// document.permissions is an object of booleans (comment/edit/download/…),
	// not a number - sending it as anything else makes the editor server
	// reject the auth message with "access deny".
	permissions, _ := document["permissions"].(map[string]interface{})
	if permissions == nil {
		permissions = make(map[string]interface{})
	}

	editorConfig, ok := res["editorConfig"].(map[string]interface{})
	if !ok || editorConfig == nil {
		return MailruDocsInfo{}, fmt.Errorf("editorConfig object missing")
	}
	callbackURL, _ := editorConfig["callbackUrl"].(string)

	userObj, _ := editorConfig["user"].(map[string]interface{})
	var editorUserID string
	if userObj != nil {
		editorUserID, _ = userObj["id"].(string)
	}

	api, err := url.Parse(apiBase)
	if err != nil || api.Scheme != "https" || api.User != nil || api.Port() != "" || api.RawQuery != "" || api.Fragment != "" {
		return MailruDocsInfo{}, fmt.Errorf("Mail.ru API returned an invalid editor endpoint")
	}
	host := strings.ToLower(api.Hostname())
	if host != "datacloudmail.ru" && !strings.HasSuffix(host, ".datacloudmail.ru") {
		return MailruDocsInfo{}, fmt.Errorf("Mail.ru API returned an untrusted editor endpoint")
	}
	if token == "" || docKey == "" || strings.ContainsAny(docKey, "/?#\\") || fileType == "" || docURL == "" || callbackURL == "" || editorUserID == "" {
		return MailruDocsInfo{}, fmt.Errorf("Mail.ru API returned incomplete editor metadata")
	}
	api.Scheme = "wss"
	api.Path = strings.TrimRight(api.Path, "/") + "/doc/" + docKey + "/c/"
	api.RawPath = ""
	api.RawQuery = "EIO=4&transport=websocket"
	wsURL := api.String()

	return MailruDocsInfo{
		Token:        token,
		DocKey:       docKey,
		WsURL:        wsURL,
		FileType:     fileType,
		DocURL:       docURL,
		DocTitle:     docTitle,
		Permissions:  permissions,
		CallbackURL:  callbackURL,
		EditorUserID: editorUserID,
	}, nil
}
