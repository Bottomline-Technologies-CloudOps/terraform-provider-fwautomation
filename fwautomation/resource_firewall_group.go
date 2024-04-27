package fwautomation

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"regexp"
	"time"

	"github.com/google/uuid" // Ensure you are using google/uuid for uuid.NewString()
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

func resourceFirewallGroup() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceFirewallGroupCreate,
		ReadContext:   resourceFirewallGroupRead,
		UpdateContext: resourceFirewallGroupUpdate,
		DeleteContext: resourceFirewallGroupDelete,
		Schema: map[string]*schema.Schema{
			"group_name": &schema.Schema{
				Type:     schema.TypeString,
				ForceNew: true,
				Required: true,
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v := val.(string)
					if match, _ := regexp.MatchString("[A-Z_]*", v); !match {
						errs = append(errs, fmt.Errorf("%q includes invalid characters. May contain [uppercase letters, underscores].", key))
					}
					return
				},
			},
			"hostname": &schema.Schema{
				Type:     schema.TypeString,
				ForceNew: true,
				Required: true,
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v := val.(string)
					if match, _ := regexp.MatchString("[a-z\\.-]*", v); !match {
						errs = append(errs, fmt.Errorf("%q must be a fully qualified domain name. May contain [letters, hyphens, periods].", key))
					}
					return
				},
			},
			"ip_address": &schema.Schema{
				Type:     schema.TypeString,
				ForceNew: true,
				Required: true,
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v := val.(string)
					if match, _ := regexp.MatchString("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", v); !match {
						errs = append(errs, fmt.Errorf("%q must be an IP address. Format [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", key))
					}
					return
				},
			},
		},
	}
}

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
	d.SetId(uuid.New().String()) // Using UUID for unique ID generation
	return diags
}

func resourceFirewallGroupRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	config := m.(*ManagementConfig)
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

func resourceFirewallGroupUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return resourceFirewallGroupRead(ctx, d, m)
}

func resourceFirewallGroupDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	config := m.(*ManagementConfig)
	client, err := setupSSHConnection(config)
	if err != nil {
		return diag.FromErr(err)
	}
	defer client.Close()

	err = runResourceFirewallGroupsTask(client, d, "remove")
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return diags
}

func setupSSHConnection(config *ManagementConfig) (*ssh.Client, error) {
	key, err := ioutil.ReadFile(config.AuthenticationKeyPath) // Adjusted for the correct field name
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

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", config.Server, 22), sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %s", err)
	}
	return client, nil
}

func runResourceFirewallGroupsTask(c *ssh.Client, d *schema.ResourceData, method string) error {
	session, err := c.NewSession()
	if err != nil {
		return fmt.Errorf("Error creating SSH session: %s", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	cmd, err := generateCommand(d, method)
	if err != nil {
		return fmt.Errorf("Error executing GenerateCommand: %s", err)
	}
	err = session.Start(cmd)
	if err != nil {
		return fmt.Errorf("Error running start command: %s, stderr: %s, stdout: %s", err, stderr.String(), stdout.String())
	}
	err = session.Wait()
	if err != nil {
		return fmt.Errorf("Error running wait command: %s, stderr: %s, stdout: %s", err, stderr.String(), stdout.String())
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
		return "", fmt.Errorf("Method not supported: %s", method)
	}
}
