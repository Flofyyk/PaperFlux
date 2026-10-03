package transport

import "regexp"

// EditorPayloads preserves server entry order, including mixed cursor and
// saveChanges batches. Keepalives are individual records, never whole frames.
var editorPayloadRE = regexp.MustCompile(`"(?:cursor"\s*:\s*"[^;"\\]*;|excelAdditionalInfo"\s*:\s*")([^"\\]+)"`)

func EditorPayloads(text string) []string {
	var payloads []string
	for _, match := range editorPayloadRE.FindAllStringSubmatch(text, -1) {
		if match[1] != "---KA---" {
			payloads = append(payloads, match[1])
		}
	}
	return payloads
}
