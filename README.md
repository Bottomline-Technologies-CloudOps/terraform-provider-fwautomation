
# FWAutomation Terraform Provider

## Overview
The FWAutomation Terraform Provider enables users to manage firewall configurations seamlessly through Terraform, facilitating infrastructure as code (IaC) practices to automate the setup and management of firewall rules and groups.

## Features
- Create, update, and delete firewall groups.
- Supports multiple firewall configurations.
- Easily integrates into existing Terraform workflows.

## Version Compatibility
This provider requires Terraform 0.12 or later and supports Terraform protocol version 5.0.

## Installation
To install the FWAutomation provider, include it in your Terraform configuration like so:

```hcl
terraform {
  required_providers {
    fwautomation = {
      source = "hashicorp/fwautomation"
      version = "1.0.0"
    }
  }
}
```

Then run the following command to initialize your Terraform workspace:

```shell
terraform init
```

## Usage
Refer to the examples provided in the `.tf` files within this repository to get started with configuring firewall groups using this provider.