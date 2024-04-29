package fwautomation

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type ManagementConfig struct {
	Server                string
	Domain                string
	AuthenticationKeyPath string // Make sure this is correctly added to the struct
}

// Provider -
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"management_server": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("FWGROUPS_SERVER", nil),
			},
			"domain": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("FWGROUPS_DOMAIN", nil),
			},
			"authentication_key_path": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("FWGROUPS_AUTH_KEY_PATH", nil),
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"fwautomation_fwgroup": resourceFirewallGroup(),
		},
		DataSourcesMap:       map[string]*schema.Resource{},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	server := d.Get("management_server").(string)
	domain := d.Get("domain").(string)
	authKeyPath := d.Get("authentication_key_path").(string)

	// Return a configuration object, not an SSH client
	config := &ManagementConfig{
		Server:                server,
		Domain:                domain,
		AuthenticationKeyPath: authKeyPath,
	}

	return config, diags
}
