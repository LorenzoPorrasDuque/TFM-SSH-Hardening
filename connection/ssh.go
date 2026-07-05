package connection

import (
	"encoding/json"
	"strings"

	"golang.org/x/crypto/ssh"
)

type SSHDConfigSecurity struct {
	PermitRootLogin         string `json:"permit_root_login,omitempty"`
	PasswordAuthentication  string `json:"password_authentication,omitempty"`
	PubkeyAuthentication    string `json:"pubkey_authentication,omitempty"`
	PermitEmptyPasswords    string `json:"permit_empty_passwords,omitempty"`
	ChallengeResponseAuth   string `json:"challenge_response_authentication,omitempty"`
	KbdInteractiveAuth      string `json:"kbd_interactive_authentication,omitempty"`
	UsePAM                  string `json:"use_pam,omitempty"`
	X11Forwarding           string `json:"x11_forwarding,omitempty"`
	AllowTcpForwarding      string `json:"allow_tcp_forwarding,omitempty"`
	PermitTunnel            string `json:"permit_tunnel,omitempty"`
	AllowAgentForwarding    string `json:"allow_agent_forwarding,omitempty"`
	MaxAuthTries            string `json:"max_auth_tries,omitempty"`
	MaxSessions             string `json:"max_sessions,omitempty"`
	ClientAliveInterval     string `json:"client_alive_interval,omitempty"`
	ClientAliveCountMax     string `json:"client_alive_count_max,omitempty"`
	LoginGraceTime          string `json:"login_grace_time,omitempty"`
	IgnoreRhosts            string `json:"ignore_rhosts,omitempty"`
	HostbasedAuthentication string `json:"hostbased_authentication,omitempty"`
	StrictModes             string `json:"strict_modes,omitempty"`
	Protocol                string `json:"protocol,omitempty"`
	Ciphers                 string `json:"ciphers,omitempty"`
	MACs                    string `json:"macs,omitempty"`
	KexAlgorithms           string `json:"kex_algorithms,omitempty"`
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

	cfg := parseSSHDConfig(string(output))

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func parseSSHDConfig(content string) SSHDConfigSecurity {
	cfg := SSHDConfigSecurity{}

	lines := strings.Split(content, "\n")

	values := make(map[string]string)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.ToLower(fields[0])
		value := strings.Join(fields[1:], " ")

		values[key] = value
	}

	cfg.PermitRootLogin = values["permitrootlogin"]
	cfg.PasswordAuthentication = values["passwordauthentication"]
	cfg.PubkeyAuthentication = values["pubkeyauthentication"]
	cfg.PermitEmptyPasswords = values["permitemptypasswords"]
	cfg.ChallengeResponseAuth = values["challengeresponseauthentication"]
	cfg.KbdInteractiveAuth = values["kbdinteractiveauthentication"]
	cfg.UsePAM = values["usepam"]
	cfg.X11Forwarding = values["x11forwarding"]
	cfg.AllowTcpForwarding = values["allowtcpforwarding"]
	cfg.PermitTunnel = values["permittunnel"]
	cfg.AllowAgentForwarding = values["allowagentforwarding"]
	cfg.MaxAuthTries = values["maxauthtries"]
	cfg.MaxSessions = values["maxsessions"]
	cfg.ClientAliveInterval = values["clientaliveinterval"]
	cfg.ClientAliveCountMax = values["clientalivecountmax"]
	cfg.LoginGraceTime = values["logingracetime"]
	cfg.IgnoreRhosts = values["ignorerhosts"]
	cfg.HostbasedAuthentication = values["hostbasedauthentication"]
	cfg.StrictModes = values["strictmodes"]
	cfg.Protocol = values["protocol"]
	cfg.Ciphers = values["ciphers"]
	cfg.MACs = values["macs"]
	cfg.KexAlgorithms = values["kexalgorithms"]

	return cfg
}
