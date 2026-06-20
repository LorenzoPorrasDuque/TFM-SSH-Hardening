package connection

import (
	"golang.org/x/crypto/ssh"
)

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

	return string(output), nil
}
