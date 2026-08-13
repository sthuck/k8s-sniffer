package tlsworker

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func findLibSSLInContainer(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("pid: required")
	}
	lib, err := findLibSSL(pid)
	if err == nil {
		return lib, nil
	}
	firstErr := err
	for _, p := range pidsSharingNS(pid, "mnt") {
		if p == pid {
			continue
		}
		lib, err := findLibSSL(p)
		if err == nil {
			return lib, nil
		}
	}
	return "", firstErr
}

// pidsSharingNS lists PIDs that share /proc/<pid>/ns/<kind> with pid.
// Mount-ns ("mnt") scopes to one container: nginx workers share it, sidecars do not.
func pidsSharingNS(pid int, kind string) []int {
	want, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, kind))
	if err != nil {
		return []int{pid}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []int{pid}
	}
	out := []int{pid}
	seen := map[int]struct{}{pid: {}}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var other int
		if _, err := fmt.Sscanf(e.Name(), "%d", &other); err != nil || other <= 0 {
			continue
		}
		if _, ok := seen[other]; ok {
			continue
		}
		got, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", other, kind))
		if err != nil || got != want {
			continue
		}
		seen[other] = struct{}{}
		out = append(out, other)
	}
	return out
}

func findLibSSL(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("pid: required")
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return "", fmt.Errorf("read maps: %w", err)
	}
	root := fmt.Sprintf("/proc/%d/root", pid)
	seen := map[string]struct{}{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "libssl.so") && !strings.Contains(line, "libssl-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mapped := fields[len(fields)-1]
		if !strings.HasPrefix(mapped, "/") {
			continue
		}
		if _, ok := seen[mapped]; ok {
			continue
		}
		seen[mapped] = struct{}{}
		hostPath := filepath.Join(root, mapped)
		if _, err := os.Stat(hostPath); err == nil {
			return hostPath, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("libssl.so not mapped in pid %d", pid)
}

func cgroupPath(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// cgroup v2: 0::/kubepods.slice/...
		if strings.HasPrefix(line, "0::") {
			p := strings.TrimPrefix(line, "0::")
			if p == "" || p == "/" {
				return ""
			}
			return "/sys/fs/cgroup" + p
		}
	}
	return ""
}

func PIDFromNetnsPath(path string) int {
	// /proc/<pid>/ns/net
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "proc" && parts[2] == "ns" {
		var pid int
		for _, c := range parts[1] {
			if c < '0' || c > '9' {
				return 0
			}
		}
		_, _ = fmt.Sscanf(parts[1], "%d", &pid)
		return pid
	}
	return 0
}
