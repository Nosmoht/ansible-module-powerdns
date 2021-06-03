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
    pdns_port: 443
    pdns_api_key: topsecret
    pdns_prot: https
```

Absent all A record: this will delete all A record, even you specified ip in content
```yaml
- powerdns_record:
    name: host01.zone01.internal.example.com.
    state: absent
    zone: zone01.internal.example.com
    type: A
    content: 192.168.1.234
    ttl: 1440
    pdns_host: powerdns.example.com
    pdns_port: 443
    pdns_api_key: topsecret
    pdns_prot: https
```

Absent particular A record: this will remove only one A record for specific ip
```yaml
- powerdns_record:
    name: host01.zone01.internal.example.com.
    state: absent
    exclusive: false
    zone: zone01.internal.example.com
    type: A
    content: 192.168.1.234
    ttl: 1440
    pdns_host: powerdns.example.com
    pdns_port: 443
    pdns_api_key: topsecret
    pdns_prot: https
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
    pdns_port: 8443
    pdns_api_key: topsecret
    pdns_prot: https
```

Do not verify SSL certificate (this is a security risk)

```yaml
- powerdns_record:
    name: host01.zone01.internal.example.com.
    zone: zone01.internal.example.com
    type: AAAA
    content: 2001:cdba:0000:0000:0000:0000:3257:9652
    ttl: 1440
    pdns_host: powerdns.example.com
    pdns_port: 8443
    pdns_api_key: topsecret
    pdns_prot: https
    strict_ssl_checking: false
```

Ensure CNAME record
```yaml
- powerdns_record:
    name: database.zone01.internal.example.com.
    zone: zone01.internal.example.com
    type: CNAME
    content: host01.zone01.internal.example.com
    pdns_host: powerdns.example.com
    pdns_port: 80
    pdns_api_key: topsecret
    pdns_prot: http
```

Ensure multiple MX records
```yaml
- powerdns_record:
    name: zone01.internal.example.com.
    zone: zone01.internal.example.com
    type: MX
    exclusive: no
    content: "{{ item }}"
    pdns_host: powerdns.example.com
    pdns_port: 80
    pdns_api_key: topsecret
    pdns_prot: http
  loop:
    - 10 mx1.zone01.internal.example.com
    - 10 mx2.zone01.internal.example.com
```

Use HTTP Basic Auth instead of API Key
```yaml
- powerdns_record:
    name: database.zone01.internal.example.com.
    zone: zone01.internal.example.com
    type: CNAME
    content: host01.zone01.internal.example.com
    pdns_host: powerdns.example.com
    pdns_port: 80
    pdns_api_username: myuser
    pdns_api_password: mytopsecretpassword
    pdns_prot: http
```

`pdns_api_key` takes preference if both `pdns_api_key` and `pdns_api_username`/`pdns_api_password` are supplied.


Note the trailing '.' following most records, if not present will result in the error "Domain record is not canonical".
