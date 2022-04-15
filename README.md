# Ansible LDAP Inventory Plugin

This plugin was designed to query active directory and get a list of machines to use as an inventory.
Groups are auto generated off of `ou` structure and optionally group membership.
So for example `cn=computer1,ou=servers,ou=windows,dc=mycompany,dc=local` would create the following inventory :

```json
    "all": {
        "children": [
            "windows"
        ]
    },
    "windows": {
        "children": [
            "windows_servers"
        ]
    },
    "windows_servers": {
        "hosts": [
            "computer1"
        ]
    }
```

## Prerequisites

The ldap inventory works with python2 and python3.

**The following package is required :**

* [python-ldap](https://www.python-ldap.org/en/latest/)

It can be installed in one of the following ways:

`*pip install -r requirements.txt*`

or

`*pip install python-ldap*`

## Configuration Example

Place the file `ldap_inventory.py` into your base folder under `.\plugins\inventory\`

Create a file that ends with `ldap_inventory.yaml` in your base directory.
It is recommended you vault the entire file if storing passwords in plaintext(until ansible supports vaulted strings in config files) `ansible-vault edit ldap_inventory.yaml`

>`LDAP_USERNAME`, `LDAP_PASSWORD` and `SEARCH_OU` environmental variables can be used instead of including them in the configuration file. This is helpful if using the plugin in [Ansible Tower/AWX](https://github.com/ansible/awx).

Example `ldap_inventory.yaml` :

```yaml
---
plugin: ldap_inventory
domain: 'ldaps://adserver.domain.local:636'
username: user@domain.local
password: "password"
search_ou: "OU=Servers,OU=Windows,DC=domain,DC=local"
```

## Parameters

### `account_age`

> LDAP attribute filter for the lastLogonTimestamp field. This value is generally updated every 14 days. Timestamps older indicate inactive computer accounts. Setting to 0 disables check. Value is in days.

* default: `0`

### `domain`

> The domain to search in to retrieve inventory. This could either be a Windows domain name visible to the Ansible controller from DNS or a specific domain controller FQDN. Supports either just the domain/host name or an explicit LDAP URI with the domain/host already filled in. If the URI is set, **`port`** and **`scheme`** are ignored.

* required: true

**examples:**

```yaml
domain: "local.com"
```

```yaml
domain: "dc1.local.com"
```

```yaml
domain: "ldaps://dc1.local.com:636"
```

```yaml
domain: "ldap://dc1.local.com"
```

### `group_membership`

>Enables parsing the ldap groups that the computer account is a memberOf. Groups are returned lower case.

* default: `"False"`

**example:**

```yaml
group_membership: True
```

### `group_membership_filter`

>When we query for Group membership of the computer object, this allows you to only include names that match the pattern provided.

* default: `""`

**example:**

```yaml
group_membership: "security-*"
```

### `exclude_groups`

>Exclude a list of groups from being included in the inventory. This will match substrings.

* default: `""`

**example:**

```yaml
exclude_groups: "windows_group1,windows_group2"
```

### `exclude_hosts`

>Exclude a list of hosts from being included in the inventory. This will match substrings.

* default: `""`

**example:**

```yaml
exclude_hosts: "hostname1,hostname2"
```

### `extra_groups`

>Add a list of groups to the inventory under the top-level `all` group and place
>all hosts into these groups.  This is useful in an AWX/Tower scenario where
>hosts need to be put into a named group to pick up variable values specific to
>that.  AWX/Tower performs this variable assignment at inventory sync time and
>not playbook execution time.

* default: []

**example:**

```yaml
extra_groups:
  - foo
  - bar
  - baz
```

### `use_fqdn`

>Specifies if we should use FQDN instead of shortname for hosts.

* Allow Values: `True`, `False`
* Default: `False`

### `ldap_filter`

>LDAP filter used to find objects. You should not usually need to change this.

* Allowed Values: [RFC 4515](https://tools.ietf.org/html/rfc4515.html)
* Default: `"(objectClass=Computer)"`

### `port`

>Port used to connect to Domain Controller. If **`domain`** URI contains ldap or ldaps this is ignored.

* Default: `389` for ldap, `636` for ldaps

### `scheme`

>The ldap scheme to use. When using `ldap`, it is recommended to set `auth=gssapi`, or `start_tls=yes`, otherwise traffic will be in plaintext. This parameter is not required and can be determined from the **`domain`** URI or **`port`**.

* Allowed Values: `ldap`, `ldaps`
* Default: `ldap`

### `search_ou`

>LDAP path to search for computer objects. Can use environmental variable `SEARCH_OU` instead of setting in config.

* required: true

**example:**

```yaml
search_ou: "cn=Computers,dc=local,dc=com"
```

### `validate_certs`

>Controls if verfication is done of SSL certificates for secure (ldaps://) connections.

* Allow Values: `True`, `False`
* Default: `True`

## Testing

`ansible-inventory -i ldap_inventory --list`

`ansible-inventory -i ldap_inventory --list --vault-id=@prompt` (when vaulted)

## Running a playbook

`ansible-playbook -i ldap_inventory.yaml adhoc.yaml --vault-id@prompt`
