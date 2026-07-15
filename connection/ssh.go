package connection

import (
	"encoding/json"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

type SSHConfigField struct {
	Name      string `json:"name"`
	Directive string `json:"directive"`
}

func LoadSSHConfigFields(path string) ([]SSHConfigField, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var fields []SSHConfigField

	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}

	return fields, nil
}

type SSHRequest struct {
	IP         string `json:"ip" binding:"required"`
	User       string `json:"user" binding:"required"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

func CreateSSH(req SSHRequest) (*ssh.Client, error) {
	var auth ssh.AuthMethod

	if req.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(req.PrivateKey))
		if err != nil {
			return nil, err
		}
		auth = ssh.PublicKeys(signer)
	} else {
		auth = ssh.Password(req.Password)
	}

	config := &ssh.ClientConfig{
		User:            req.User,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	return ssh.Dial("tcp", req.IP+":22", config)
}

func GetSSHDConfig(client *ssh.Client) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	output, err := session.Output("cat /etc/ssh/sshd_config")
	if err != nil {
		return "", err
	}

	fields, err := LoadSSHConfigFields("config_keys.json")
	if err != nil {
		return "", err
	}

	cfg := parseSSHDConfig(string(output), fields)

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func parseSSHDConfig(content string, fields []SSHConfigField) map[string]string {
	lines := strings.Split(content, "\n")

	// Guarda todas las directivas encontradas
	values := make(map[string]string)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := strings.Join(parts[1:], " ")

		values[key] = value
	}

	// Construye el resultado usando el JSON
	result := make(map[string]string)

	for _, field := range fields {
		result[field.Name] = values[strings.ToLower(field.Directive)]
	}

	return result
}
