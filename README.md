PowerDNS Ansible library
==========
- [Introduction](#introduction)
- [Usage](#usage)
  - [Zones](#zones)
  - [Records](#records)

# Usage

## Zones
Ensure zone is present

```yaml
- powerdns_zone:
    name: zone01.internal.example.com.
    nameservers:
    - ns-01.example.com.
    - ns-02.example.com.
    kind: master
    state: present
    pdns_host: powerdns.example.com
    pdns_port: 8081
    pdns_api_key: topsecret
```

Ensure zone is absent
```yaml
- powerdns_zone:
    name: zone02.internal.example.com
    state: absent
    pdns_host: powerdns.example.com
    pdns_port: 8081
    pdns_api_key: topsecret
```

## Records

Ensure A record
```yaml
- powerdns_record:
    name: host01.zone01.internal.example.com.
    zone: zone01.internal.example.com
    type: A
    content: 192.168.1.234
    ttl: 1440
    pdns_host: powerdns.example.com
    pdns_port: 8081
    pdns_api_key: topsecret
```

Ensure AAAA record
```yaml
- powerdns_record:
    name: host01.zone01.internal.example.com.
    zone: zone01.internal.example.com
    type: AAAA
    content: 2001:cdba:0000:0000:0000:0000:3257:9652
    ttl: 1440
    pdns_host: powerdns.example.com
    pdns_port: 8081
    pdns_api_key: topsecret
```

Ensure CNAME record
```yaml
- powerdns_record:
    name: database.zone01.internal.example.com.
    zone: zone01.internal.example.com
    type: CNAME
    content: host01.zone01.internal.example.com
    pdns_host: powerdns.example.com
    pdns_port: 8081
    pdns_api_key: topsecret
```

Note the trailing '.' following most records, if not present will result in the error "Domain record is not canonical".