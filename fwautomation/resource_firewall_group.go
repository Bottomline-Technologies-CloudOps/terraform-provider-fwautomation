package fwautomation

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

func resourceFirewallGroup() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceFirewallGroupCreate,
		ReadContext:   resourceFirewallGroupRead,
		//UpdateContext: resourceFirewallGroupUpdate,
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
						errs = append(errs, fmt.Errorf("%q includes invalid characters. May contain [uppercase letters, underscores].", key))
					}
					return
				},
			},
		},
		SchemaVersion: 1,
	}
}

func resourceFirewallGroupCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	client := m.(*ssh.Client)
	err := runResourceFirewallGroupsTask(client, d, "add")
	if err != nil {
		return diag.FromErr(err)
	}
	newUUID, _ := uuid.GenerateUUID()
	d.SetId(newUUID)
	return diags
}

func resourceFirewallGroupRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	client := m.(*ssh.Client)
	err := runResourceFirewallGroupsTask(client, d, "read")
	if err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func resourceFirewallGroupUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return resourceFirewallGroupRead(ctx, d, m)
}

func resourceFirewallGroupDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	client := m.(*ssh.Client)
	err := runResourceFirewallGroupsTask(client, d, "remove")
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")

	return diags
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

func getValue(d *schema.ResourceData, key string, method string) string {
	var val string

	if d.HasChange(key) && method == "remove" {
		valInterface, _ := d.GetChange(key)
		val = valInterface.(string)
	} else {
		val = d.Get(key).(string)
	}

	return val
}

func generateCommand(d *schema.ResourceData, method string) (string, error) {
	groupName := getValue(d, "group_name", method)
	hostname := getValue(d, "hostname", method)
	ipAddress := getValue(d, "ip_address", method)

	if method == "add" || method == "remove" {
		return fmt.Sprintf("modify group group=%s hostname=%s ip=%s method=%s", groupName, hostname, ipAddress, method), nil
	} else if method == "read" {
		return fmt.Sprintf("show group group=%s", groupName), nil
	} else {
		return "", fmt.Errorf("Method not supported.%s", method)
	}
}

func debugLogOutput(id string, output string) {
	// Debug log for development
	f, _ := os.OpenFile("./terraform-provider-fwautomation.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	_, err := f.WriteString(id + ": " + output + "\n")
	if err != nil {
		panic(err)
	}
	f.Sync()
}
