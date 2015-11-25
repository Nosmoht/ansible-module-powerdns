PowerDNS Ansible library
==========
- [Usage](#usage)

# Usage

Ensure zone does exist
```yaml
- powerdns_zone:
    name: zone.example.com
    nameservers:
    - ns-01.example.com
    - ns-02.example.com
    kind: master
    state: present
    pdns_host: powerdns.example.com
    pdns_port: 8081
    pdns_prot: http
    pdns_api_key: topsecret
```
