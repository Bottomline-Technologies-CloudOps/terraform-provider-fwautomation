package fwautomation

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"regexp"
	"time"

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
	return manageFirewallGroup(ctx, d, config, "add")
}

func resourceFirewallGroupRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*ManagementConfig)
	return manageFirewallGroup(ctx, d, config, "read")
}

func resourceFirewallGroupDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*ManagementConfig)
	return manageFirewallGroup(ctx, d, config, "delete")
}

func manageFirewallGroup(ctx context.Context, d *schema.ResourceData, config *ManagementConfig, method string) diag.Diagnostics {
	key, err := ioutil.ReadFile(d.Get("authentication_key_path").(string))
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to load private key: %s", err))
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to parse private key: %s", err))
	}

	authMethod := ssh.PublicKeys(signer)

	firewallGroups, err := getFirewallGroups(d)
	if err != nil {
		return diag.FromErr(err)
	}

	var diags diag.Diagnostics

	for _, group := range firewallGroups {
		sshConfig := &ssh.ClientConfig{
			User:            "automate",
			Auth:            []ssh.AuthMethod{authMethod},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}

		sshClient, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", config.Server, 22), sshConfig)
		if err != nil {
			diags = append(diags, diag.FromErr(fmt.Errorf("failed to connect for group %s: %v", group.GroupName, err)))
			continue
		}

		defer sshClient.Close()

		err = runResourceFirewallGroupsTask(sshClient, d, method, group)
		if err != nil {
			diags = append(diags, diag.FromErr(fmt.Errorf("error processing group %s: %v", group.GroupName, err)))
		}
	}

	if len(diags) == 0 {
		d.SetId(createUniqueId())
	}

	return diags
}

func runResourceFirewallGroupsTask(c *ssh.Client, d *schema.ResourceData, method string, group FirewallGroup) error {
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

func getFirewallGroups(d *schema.ResourceData) ([]FirewallGroup, error) {
	// Implement the logic to extract firewall groups from the resource data
	// Return a slice of FirewallGroup
	return []FirewallGroup{}, nil
}

func generateCommand(d *schema.ResourceData, method string) (string, error) {
	// Implement the command generation logic based on method
	return "", nil
}
