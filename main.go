package main

import (
	"net/http"
	"ssh/connection"

	"github.com/gin-gonic/gin"
)

var LastSSHRequest connection.SSHRequest

func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		// Return JSON response
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.POST("/ssh-config", func(c *gin.Context) {
		var req connection.SSHRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		LastSSHRequest = req

		if req.Password == "" && req.PrivateKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "either password or PrivateKey must be provided",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "SSH connection data received",
			"ip":      req.IP,
			"user":    req.User,
		})
	})

	r.POST("/ssh-config/get", func(c *gin.Context) {

		var req = LastSSHRequest

		client, err := connection.CreateSSH(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		defer client.Close()

		config, err := connection.GetSSHDConfig(client)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ip":     req.IP,
			"user":   req.User,
			"config": config,
		})
	})

	r.Run(":8080")

}

/*

if strings.EqualFold(cfg.PasswordAuthentication, "yes") {
		audit.Score -= 15
		audit.Findings = append(audit.Findings, Finding{
			Setting: "PasswordAuthentication",
			Value: cfg.PasswordAuthentication,
			Status: "WARN",
			Severity: "HIGH",
			Recommendation: "Deshabilitar la autenticación por contraseña y usar llaves SSH.",
		})
	}
*/
