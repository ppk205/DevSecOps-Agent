package analysis

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"devsecops-agent/internal/bridge"
)

func Serve(input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), bridge.MaxMessageBytes)
	for scanner.Scan() {
		var request struct {
			Version int    `json:"version"`
			ID      string `json:"id"`
			Method  string `json:"method"`
			Params  struct {
				Observations   []Object `json:"observations"`
				RunID          string   `json:"run_id"`
				Timestamp      string   `json:"timestamp"`
				Findings       []Object `json:"findings"`
				Results        []Object `json:"results"`
				Required       []string `json:"required"`
				Threshold      string   `json:"threshold"`
				CoverageErrors []string `json:"coverage_errors"`
				Errors         []string `json:"errors"`
				Cancelled      bool     `json:"cancelled"`
			} `json:"params"`
		}
		err := json.Unmarshal(scanner.Bytes(), &request)
		var result any
		if err == nil && request.Version != bridge.Version {
			err = fmt.Errorf("unsupported protocol version")
		}
		if err == nil {
			switch request.Method {
			case "group":
				result, err = Group(request.Params.Observations, request.Params.RunID, request.Params.Timestamp)
			case "gate":
				result, err = Gate(request.Params.Findings, request.Params.Results, request.Params.Required, request.Params.Threshold, request.Params.CoverageErrors, request.Params.Errors, request.Params.Cancelled)
			default:
				err = fmt.Errorf("unknown native method")
			}
		}
		response := map[string]any{"version": bridge.Version, "id": request.ID, "ok": err == nil, "result": result}
		if err != nil {
			response["error"] = map[string]string{"message": err.Error()}
		}
		data, e := json.Marshal(response)
		if e != nil {
			return e
		}
		if len(data)+1 > bridge.MaxMessageBytes {
			return fmt.Errorf("native response exceeds message limit")
		}
		if _, e = output.Write(append(data, '\n')); e != nil {
			return e
		}
	}
	return scanner.Err()
}
