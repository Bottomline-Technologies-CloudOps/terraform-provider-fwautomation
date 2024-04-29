package fwautomation

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil" // Use ioutil for reading files
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

func resourceFirewallGroup() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceFirewallGroupCreate,
		ReadContext:   resourceFirewallGroupRead,
		DeleteContext: resourceFirewallGroupDelete,
		Schema: map[string]*schema.Schema{
			"group_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v := val.(string)
					if !regexp.MustCompile(`^[A-Z_]+$`).MatchString(v) {
						errs = append(errs, fmt.Errorf("%q only allows uppercase letters and underscores: %s", key, v))
					}
					return warns, errs
				},
			},
			"hostname": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v := val.(string)
					if !regexp.MustCompile(`^[a-z\.-]+$`).MatchString(v) {
						errs = append(errs, fmt.Errorf("%q must be a fully qualified domain name and only contain lowercase letters, periods, and hyphens: %s", key, v))
					}
					return warns, errs
				},
			},
			"ip_address": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v := val.(string)
					if !regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`).MatchString(v) {
						errs = append(errs, fmt.Errorf("%q must be a valid IP address: %s", key, v))
					}
					return warns, errs
				},
			},
		},
		SchemaVersion: 1, // Set the schema version to 1
	}
}

// Adding comments for better visibility
func resourceFirewallGroupCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*ManagementConfig)
	var diags diag.Diagnostics

	client, err := setupSSHConnection(config)
	if err != nil {
		return diag.FromErr(err)
	}
	defer client.Close()

	err = runResourceFirewallGroupsTask(client, d, "add")
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(uuid.NewString()) // Correctly setting the ID after successful creation
	return diags
}

func resourceFirewallGroupRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*ManagementConfig)
	var diags diag.Diagnostics

	client, err := setupSSHConnection(config)
	if err != nil {
		return diag.FromErr(err)
	}
	defer client.Close()

	err = runResourceFirewallGroupsTask(client, d, "read")
	if err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func resourceFirewallGroupDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*ManagementConfig)
	var diags diag.Diagnostics

	client, err := setupSSHConnection(config)
	if err != nil {
		return diag.FromErr(err)
	}
	defer client.Close()

	err = runResourceFirewallGroupsTask(client, d, "remove")
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId("") // Correctly clearing the ID upon successful deletion
	return diags
}

func setupSSHConnection(config *ManagementConfig) (*ssh.Client, error) {
	key, err := ioutil.ReadFile(config.AuthenticationKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %s", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %s", err)
	}

	sshConfig := &ssh.ClientConfig{
		User: "automate",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	// Ensure the server address includes a port
	serverAddress := config.Server
	if !strings.Contains(serverAddress, ":") {
		serverAddress = fmt.Sprintf("%s:22", serverAddress) // Append port if not present
	}

	return ssh.Dial("tcp", serverAddress, sshConfig)
}

func runResourceFirewallGroupsTask(client *ssh.Client, d *schema.ResourceData, method string) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("error creating SSH session: %s", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	cmd, err := generateCommand(d, method)
	if err != nil {
		return fmt.Errorf("error executing command: %s", err)
	}

	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("error starting command: %s, stderr: %s, stdout: %s", err, stderr.String(), stdout.String())
	}

	if err := session.Wait(); err != nil {
		return fmt.Errorf("error waiting for command completion: %s, stderr: %s, stdout: %s", err, stderr.String(), stdout.String())
	}

	return nil
}

func generateCommand(d *schema.ResourceData, method string) (string, error) {
	groupName := d.Get("group_name").(string)
	hostname := d.Get("hostname").(string)
	ipAddress := d.Get("ip_address").(string)

	if method == "add" || method == "remove" {
		return fmt.Sprintf("modify group group=%s hostname=%s ip=%s method=%s", groupName, hostname, ipAddress, method), nil
	} else if method == "read" {
		return fmt.Sprintf("show group group=%s", groupName), nil
	} else {
		return "", fmt.Errorf("method not supported: %s", method)
	}
}
