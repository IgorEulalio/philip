package detection

import "strings"

// MITRE ATT&CK technique IDs relevant to CI/CD supply chain attacks.
const (
	// Execution
	MITRECommandScriptingInterpreter = "T1059"
	MITREUnixShell                   = "T1059.004"

	// Persistence
	MITREEventTriggeredExecution = "T1546"

	// Defense Evasion
	MITREDeobfuscateDecode = "T1140"

	// Credential Access
	MITRECredentialsInFiles     = "T1552.001"
	MITREContainerAPI           = "T1552.007"
	MITREUnsecuredCredentials   = "T1552"

	// Discovery
	MITRENetworkServiceDiscovery = "T1046"

	// Lateral Movement / C2
	MITRENonStandardPort = "T1571"

	// Exfiltration
	MITREExfiltrationOverC2 = "T1041"

	// Resource Development
	MITREIngressToolTransfer = "T1105"
)

// MITREForDeviation maps a scored deviation to MITRE ATT&CK technique IDs
// based on the deviation type and event context.
func MITREForDeviation(d ScoredDeviation) []string {
	switch d.DeviationType {
	case DeviationNewProcess:
		return mitreForNewProcess(d)
	case DeviationSuspiciousArgs:
		return mitreForSuspiciousArgs(d)
	case DeviationSensitivePath:
		return mitreForSensitivePath(d)
	case DeviationNewNetwork:
		return mitreForNewNetwork(d)
	case DeviationUnexpectedParent:
		return mitreForUnexpectedParent(d)
	case DeviationNewFile:
		return mitreForNewFile(d)
	case DeviationAnomalousArgs:
		return []string{MITRECommandScriptingInterpreter}
	default:
		return nil
	}
}

func mitreForNewProcess(d ScoredDeviation) []string {
	binary := binaryBasename(d.Event.Binary)
	switch binary {
	case "nc", "ncat", "netcat":
		return []string{MITREUnixShell, MITRENonStandardPort}
	case "nmap":
		return []string{MITRENetworkServiceDiscovery}
	case "socat":
		return []string{MITREUnixShell, MITRENonStandardPort}
	case "base64", "xxd":
		return []string{MITREDeobfuscateDecode}
	case "python", "python3", "perl", "ruby":
		return []string{MITRECommandScriptingInterpreter}
	case "wget":
		return []string{MITREIngressToolTransfer}
	default:
		return []string{MITRECommandScriptingInterpreter}
	}
}

func mitreForSuspiciousArgs(d ScoredDeviation) []string {
	argsJoined := strings.Join(d.Event.Args, " ")
	binary := binaryBasename(d.Event.Binary)

	// Pipe-to-shell
	if strings.Contains(argsJoined, "| bash") || strings.Contains(argsJoined, "| sh") ||
		strings.Contains(argsJoined, "|bash") || strings.Contains(argsJoined, "|sh") {
		return []string{MITREUnixShell, MITREIngressToolTransfer}
	}

	// Download to /tmp
	if (binary == "curl" || binary == "wget") &&
		(strings.Contains(argsJoined, "/tmp") || strings.Contains(argsJoined, "-O")) {
		return []string{MITREIngressToolTransfer}
	}

	// Base64 decode
	if binary == "base64" {
		return []string{MITREDeobfuscateDecode}
	}

	// Reverse shell patterns
	if strings.Contains(argsJoined, "/dev/tcp") || strings.Contains(argsJoined, "/dev/udp") {
		return []string{MITREUnixShell, MITREExfiltrationOverC2}
	}

	// Interactive shell
	if (binary == "bash" || binary == "sh") && strings.Contains(argsJoined, "-i") {
		return []string{MITREUnixShell}
	}

	// Netcat with exec
	if (binary == "nc" || binary == "ncat" || binary == "netcat") &&
		(strings.Contains(argsJoined, "-e") || strings.Contains(argsJoined, "-c")) {
		return []string{MITREUnixShell, MITRENonStandardPort}
	}

	// Python inline execution
	if (binary == "python" || binary == "python3") && strings.Contains(argsJoined, "-c") {
		return []string{MITRECommandScriptingInterpreter}
	}

	// chmod +x /tmp
	if binary == "chmod" && strings.Contains(argsJoined, "+x") && strings.Contains(argsJoined, "/tmp") {
		return []string{MITREIngressToolTransfer}
	}

	return []string{MITRECommandScriptingInterpreter}
}

func mitreForSensitivePath(d ScoredDeviation) []string {
	path := d.Event.FilePath

	if strings.Contains(path, "/proc/self/environ") {
		return []string{MITREContainerAPI}
	}
	if strings.Contains(path, "/.ssh/") {
		return []string{MITRECredentialsInFiles}
	}
	if strings.Contains(path, "/.aws/") || strings.Contains(path, "/.kube/") ||
		strings.Contains(path, "/.docker/") || strings.Contains(path, "/.npmrc") ||
		strings.Contains(path, "/.pypirc") || strings.Contains(path, "/.gnupg/") ||
		strings.Contains(path, "/.netrc") {
		return []string{MITRECredentialsInFiles}
	}
	if strings.Contains(path, "/etc/shadow") || strings.Contains(path, "/etc/passwd") {
		return []string{MITREUnsecuredCredentials}
	}
	return []string{MITREUnsecuredCredentials}
}

func mitreForNewNetwork(d ScoredDeviation) []string {
	if d.Event.DestPort != 80 && d.Event.DestPort != 443 && d.Event.DestPort != 22 && d.Event.DestPort != 53 {
		return []string{MITRENonStandardPort, MITREExfiltrationOverC2}
	}
	return []string{MITREExfiltrationOverC2}
}

func mitreForUnexpectedParent(d ScoredDeviation) []string {
	childBase := binaryBasename(d.Event.Binary)
	networkTools := map[string]bool{
		"nc": true, "ncat": true, "netcat": true, "nmap": true, "socat": true,
	}
	if networkTools[childBase] {
		return []string{MITRECommandScriptingInterpreter, MITRENonStandardPort}
	}
	return []string{MITRECommandScriptingInterpreter}
}

func mitreForNewFile(d ScoredDeviation) []string {
	path := d.Event.FilePath
	if strings.Contains(path, "/etc/") || strings.Contains(path, "/.bashrc") ||
		strings.Contains(path, "/.profile") || strings.Contains(path, "/cron") {
		return []string{MITREEventTriggeredExecution}
	}
	if strings.Contains(path, "/tmp/") && d.Event.AccessType == "create" {
		return []string{MITREIngressToolTransfer}
	}
	return nil
}

// SuggestSeverity computes a suggested severity from a deviation score.
func SuggestSeverity(score float64) string {
	switch {
	case score >= 0.9:
		return "critical"
	case score >= 0.7:
		return "high"
	case score >= 0.4:
		return "medium"
	default:
		return "low"
	}
}
