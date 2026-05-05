package layer7

import (
	"bytes"
	"fmt"
	"sniffer/internal/model"
)

type HTTP_Request struct {

	Method string
	URI string
	Version string
}

func (h *HTTP_Request) LayerType() string{
	return "Layer 7"
}

func (h *HTTP_Request) ProtocolType() string{
	return "HTTP"
}

func (h *HTTP_Request) View() []string {

	return []string{
		fmt.Sprintf("Method: %s", h.Method),
		fmt.Sprintf("URI: %s", h.URI),
		fmt.Sprintf("Version: %s", h.Version),
	}
}

type HTTP_Response struct {

	Version string
	StatusCode string
	StatusText string
}

func (h *HTTP_Response) LayerType() string{
	return "Layer 7"
}

func (h *HTTP_Response) ProtocolType() string{
	return "HTTP"
}

func (h *HTTP_Response) View() []string {

	return []string{
		fmt.Sprintf("Version: %s", h.Version),
		fmt.Sprintf("Status: %s (%s)", h.StatusText, h.StatusCode),
	}
}

func HandleHTTP(data []byte, parsedPacket *model.ParsedPacket) {

	// Search for the end of the first line
    endOfLine := bytes.Index(data, []byte("\r\n"))
    if endOfLine == -1 {
        return 
    }

    firstLine := data[:endOfLine]

	// Checks for the 3 components of the message
    parts := bytes.SplitN(firstLine, []byte(" "), 3)
    if len(parts) < 3 {
        return
    }

    // Detect response vs request
    if bytes.HasPrefix(firstLine, []byte("HTTP/")) {

		http := &HTTP_Response{
			Version: string(parts[0]),
			StatusCode: string(parts[1]),
			StatusText: string(parts[2]),
		}

		parsedPacket.Layers = append(parsedPacket.Layers, http)

    } else {

		http := &HTTP_Request{
			Method: string(parts[0]),
			URI: string(parts[1]),
			Version: string(parts[2]),
		}

		parsedPacket.Layers = append(parsedPacket.Layers, http)
    }

    return
}
