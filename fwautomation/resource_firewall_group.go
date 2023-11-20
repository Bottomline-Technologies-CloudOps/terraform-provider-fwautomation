package fwautomation

import (
	"bytes"
	"context"
	"encoding/json"
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
	output, err := runResourceFirewallGroupsTask(client, d, "add")
	debugLogOutput("create status", output.Status)
	debugLogOutput("create reason", output.Reason)
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
	output, err := runResourceFirewallGroupsTask(client, d, "read")
	debugLogOutput("read status", output.Status)
	debugLogOutput("read reason", output.Reason)
	if err != nil {
		return diag.FromErr(err)
	}

	// Check if the group exists
	if output.Status != "success" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("Failed to read firewall group %s: %s", d.Id(), output.Reason),
		})
		return diags
	}

	// Assuming there is additional data to be populated from the read operation
	// Update the resource data here if needed

	return diags
}

func resourceFirewallGroupUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return resourceFirewallGroupRead(ctx, d, m)
}

func resourceFirewallGroupDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	client := m.(*ssh.Client)
	output, err := runResourceFirewallGroupsTask(client, d, "remove")
	if err != nil {
		return diag.FromErr(err)
	}

	debugLogOutput(d.Id(), output.Status)
	debugLogOutput(d.Id(), output.Reason)
	d.SetId("")

	return diags
}

func runResourceFirewallGroupsTask(c *ssh.Client, d *schema.ResourceData, method string) (FirewallResponse, error) {
	resp := FirewallResponse{}
	session, err := c.NewSession()
	if err != nil {
		return resp, fmt.Errorf("Error creating SSH session: %s", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	cmd := generateCommand(d, method)
	//err = session.Run(cmd)
	err = session.Start(cmd)
	if err != nil {
		return resp, fmt.Errorf("Error running start command: %s, stderr: %s", err, stderr.String())
	}
	err = session.Wait()
	if err != nil {
		return resp, fmt.Errorf("Error running wait command: %s, stderr: %s, stdout: %s", err, stderr.String(), stdout.String())
	}
	//if err != nil {
	//	return resp, fmt.Errorf("Error running command: %s, stderr: %s", err, stderr.String())
	//}

	str := stdout.String()
	if err := json.Unmarshal([]byte(str), &resp); err != nil {
		return resp, fmt.Errorf("Error parsing JSON response: %s, stderr: %s", err, stderr.String())
	}

	// existing switch statement for handling response status

	return resp, nil
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

func generateCommand(d *schema.ResourceData, method string) string {
	groupName := getValue(d, "group_name", method)
	hostname := getValue(d, "hostname", method)
	ipAddress := getValue(d, "ip_address", method)

	return fmt.Sprintf("modify group group=%s hostname=%s ip=%s method=%s", groupName, hostname, ipAddress, method)
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
