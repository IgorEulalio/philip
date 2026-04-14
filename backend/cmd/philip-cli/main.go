package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"
)

const defaultServer = "http://localhost:8080"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	server := os.Getenv("PHILIP_SERVER")
	if server == "" {
		server = defaultServer
	}

	switch os.Args[1] {
	case "baselines":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: philip baselines <repository>")
			os.Exit(1)
		}
		cmdBaseline(server, os.Args[2])
	case "findings":
		cmdFindings(server, os.Args[2:])
	case "status":
		cmdStatus(server)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Philip — Supply Chain Attack Detector CLI

Usage:
  philip baselines <repository>    View the behavioral baseline for a repository
  philip findings [--repo <repo>] [--severity <sev>]  List security findings
  philip status                    Check backend and agent status

Environment:
  PHILIP_SERVER    Backend server address (default: http://localhost:8080)`)
}

func cmdBaseline(server, repo string) {
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/baselines?repository=%s", server, repo))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		fmt.Printf("No baseline found for %s\n", repo)
		fmt.Println("A baseline is built after the first CI/CD job runs with Philip enabled.")
		return
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Error (HTTP %d): %s\n", resp.StatusCode, body)
		os.Exit(1)
	}

	var baseline struct {
		Repository        string `json:"repository"`
		TotalJobsObserved int    `json:"total_jobs_observed"`
		Status            string `json:"status"`
		FirstObserved     string `json:"first_observed"`
		LastUpdated       string `json:"last_updated"`
		ProcessProfiles   []struct {
			BinaryPath string  `json:"binary_path"`
			Frequency  float64 `json:"frequency"`
			FirstSeen  string  `json:"first_seen"`
			LastSeen   string  `json:"last_seen"`
		} `json:"process_profiles"`
		NetworkProfiles []struct {
			DestinationCIDRs []string `json:"destination_cidrs"`
			TypicalPorts     []uint32 `json:"typical_ports"`
			Frequency        float64  `json:"frequency"`
		} `json:"network_profiles"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&baseline); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Baseline: %s\n", baseline.Repository)
	fmt.Printf("Status: %s\n", baseline.Status)
	fmt.Printf("Jobs observed: %d\n", baseline.TotalJobsObserved)
	fmt.Printf("Last updated: %s\n", baseline.LastUpdated)
	fmt.Println()

	// Process profiles
	if len(baseline.ProcessProfiles) > 0 {
		fmt.Println("Process Profiles:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  BINARY\tFREQUENCY\tLAST SEEN")
		for _, p := range baseline.ProcessProfiles {
			fmt.Fprintf(w, "  %s\t%.1f%%\t%s\n", p.BinaryPath, p.Frequency*100, p.LastSeen)
		}
		w.Flush()
		fmt.Println()
	}

	// Network profiles
	if len(baseline.NetworkProfiles) > 0 {
		fmt.Println("Network Profiles:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  DESTINATION\tPORTS\tFREQUENCY")
		for _, n := range baseline.NetworkProfiles {
			fmt.Fprintf(w, "  %v\t%v\t%.1f%%\n", n.DestinationCIDRs, n.TypicalPorts, n.Frequency*100)
		}
		w.Flush()
	}
}

func cmdFindings(server string, args []string) {
	repo := ""
	severity := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--repo":
			if i+1 < len(args) {
				repo = args[i+1]
				i++
			}
		case "--severity":
			if i+1 < len(args) {
				severity = args[i+1]
				i++
			}
		}
	}

	url := fmt.Sprintf("%s/api/v1/findings?", server)
	if repo != "" {
		url += fmt.Sprintf("repository=%s&", repo)
	}
	if severity != "" {
		url += fmt.Sprintf("severity=%s&", severity)
	}

	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var findings []struct {
		ID         string  `json:"id"`
		Repository string  `json:"repository"`
		JobID      string  `json:"job_id"`
		Verdict    string  `json:"verdict"`
		Confidence float64 `json:"confidence"`
		Severity   string  `json:"severity"`
		Reasoning  string  `json:"reasoning"`
		Status     string  `json:"status"`
		CreatedAt  string  `json:"created_at"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&findings); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(findings) == 0 {
		fmt.Println("No findings.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tVERDICT\tCONFIDENCE\tREPOSITORY\tSTATUS\tCREATED")
	for _, f := range findings {
		created, _ := time.Parse(time.RFC3339, f.CreatedAt)
		fmt.Fprintf(w, "%s\t%s\t%.0f%%\t%s\t%s\t%s\n",
			f.Severity, f.Verdict, f.Confidence*100,
			f.Repository, f.Status, created.Format("2006-01-02 15:04"))
	}
	w.Flush()

	fmt.Printf("\nTotal: %d findings\n", len(findings))
}

func cmdStatus(server string) {
	resp, err := http.Get(fmt.Sprintf("%s/health", server))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Backend unreachable: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("Backend: online (%s)\n", server)
	} else {
		fmt.Printf("Backend: unhealthy (HTTP %d)\n", resp.StatusCode)
	}
}
