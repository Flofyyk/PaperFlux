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
	ctx, cancel := context.WithCancel(context.Background())
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

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return MailruDocsInfo{}, fmt.Errorf("invalid Mail.ru API request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", mailruUserAgent)
	req.Header.Set("X-Api-Version", "4")
	req.Header.Set("Referer", fmt.Sprintf("https://cloud.mail.ru/public/%s?weblink=%s", weblink, weblink))

	resp, err := client.Do(req)
	if err != nil {
		// URL errors may contain the private document link after redirects.
		if ctx.Err() != nil {
			return MailruDocsInfo{}, ctx.Err()
		}
		return MailruDocsInfo{}, fmt.Errorf("Mail.ru API connection failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return MailruDocsInfo{}, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	const maxMetadata = 2 << 20
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadata+1))
	if err != nil {
		return MailruDocsInfo{}, fmt.Errorf("Mail.ru API response could not be read")
	}
	if len(bodyBytes) > maxMetadata {
		return MailruDocsInfo{}, fmt.Errorf("Mail.ru API response too large")
	}
	return parseMailruDocInfo(bodyBytes)
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
