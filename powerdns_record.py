#!/usr/bin/env python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: powerdns_record
short_description: Manage PowerDNS records
description:
- Create, update or delete a PowerDNS records using API
- A record is unique identified by name and type
- Changing a records type is therefore not possible
options:
  content:
    description:
    - Content of the record
    - Could be an ip address or hostname
  name:
    description:
    - Record name
    - If name is not an FQDN, zone will be added at the end to create an FQDN
    required: true
  server:
    description:
    - Server name.
    required: false
    default: localhost
  ttl:
    description:
    - Record TTL
    required: false
    default: 86400
  type:
    description:
    - Record type
    required: false
    choices: ['A', 'AAAA', 'CNAME', 'MX', 'PTR', 'SOA', 'SRV', 'TXT']
    default: None
  zone:
    description:
    - Name of zone where to ensure the record
    required: true
  pdns_host:
    description:
    - Name or ip address of PowerDNS host
    required: false
    default: 127.0.0.1
  pdns_port:
    description:
    - Port used by PowerDNS API
    required: false
    default: 8081
  pdns_prot:
    description:
    - Protocol used by PowerDNS API
    required: false
    default: http
    choices: ['http', 'https']
  pdns_api_key:
    description:
    - API Key to authenticate through PowerDNS API
  strict_ssl_checking:
    description:
    - Disables strict certificate checking
    default: false
author: "Thomas Krahn (@nosmoht)"
'''

EXAMPLES = '''
- powerdns_record:
    name: host01.internal.example.com
    type: A
    content: 192.168.1.234
    state: present
    zone: internal.example.com
    pdns_host: powerdns.example.cm
    pdns_port: 8080
    pdns_prot: http
    pdns_api_key: topsecret
'''

import requests


class PowerDNSError(Exception):
    def __init__(self, url, status_code, message):
        self.url = url
        self.status_code = status_code
        self.message = message
        super(PowerDNSError, self).__init__()


class PowerDNSClient:
    def __init__(self, host, port, prot, api_key, verify):
        self.url = '{prot}://{host}:{port}/api/v1'.format(prot=prot, host=host, port=port)
        self.headers = {'X-API-Key': api_key,
                        'content-type': 'application/json',
                        'accept': 'application/json'
                        }
        self.verify = verify

    def _handle_request(self, req):
        if req.status_code in [200, 201, 204]:
            if req.text:
                try:
                    return json.loads(req.text)
                except Exception as e:
                    print(e) # same as yield
            return dict()
        elif req.status_code == 404:
            error_message = 'Not found'
        else:
            error_message = self._get_request_error_message(data=req)

        raise PowerDNSError(url=req.url,
                            status_code=req.status_code,
                            message=error_message)

    def _get_request_error_message(self, data):
        request_json = data.json()
        if 'error' in request_json:
            request_error = request_json.get('error')
        elif 'errors' in request_json:
            request_error = request_json.get('errors')
        else:
            request_error = 'No error message found'
        return request_error

    def _get_zones_url(self, server):
        return '{url}/servers/{server}/zones'.format(url=self.url, server=server)

    def _get_zone_url(self, server, name):
        return '{url}/{name}'.format(url=self._get_zones_url(server), name=name)

    def get_zone(self, server, name):
        req = requests.get(url=self._get_zone_url(server, name), headers=self.headers, verify=self.verify)
        if req.status_code == 422:  # zone does not exist
            return None
        return self._handle_request(req)

    def get_record(self, server, zone, name):
        # TODO: implementation
        return dict()

    def _get_request_data(self, changetype, server, zone, name, rtype, content=None, disabled=None, ttl=None):
        record_content = list()
        record_content.append(dict(content=content, disabled=disabled))
        record = dict(name=name, type=rtype, changetype=changetype, records=record_content, ttl=ttl)
        rrsets = list()
        rrsets.append(record)
        data = dict(rrsets=rrsets)
        return data

    def create_record(self, server, zone, name, rtype, content, disabled, ttl):
        url = self._get_zone_url(server=server, name=zone)
        data = self._get_request_data(
            changetype='REPLACE',
            server=server,
            zone=zone,
            name=name,
            rtype=rtype,
            content=content if rtype != 'TXT' else '"{}"'.format(content),
            disabled=disabled,
            ttl=ttl
        )
        req = requests.patch(url=url, data=json.dumps(data), headers=self.headers, verify=self.verify)
        return self._handle_request(req)

    def delete_record(self, server, zone, name, rtype):
        url = self._get_zone_url(server=server, name=zone)
        data = self._get_request_data(changetype='DELETE', server=server, zone=zone, name=name, rtype=rtype)
        # module.fail_json(msg=json.dumps(data))
        req = requests.patch(url=url, data=json.dumps(data), headers=self.headers, verify=self.verify)
        return self._handle_request(req)


def ensure(module, pdns_client):
    content = module.params['content']
    disabled = module.params['disabled']
    name = module.params['name']
    rtype = module.params['type']
    ttl = module.params['ttl']
    zone_name = module.params['zone']

    if zone_name not in name:
        name = '{name}.{zone}'.format(name=name, zone=zone_name)
    server = module.params['server']
    state = module.params['state']

    try:
        zone = pdns_client.get_zone(server, zone_name)
    except PowerDNSError as e:
        module.fail_json(
                msg='Could not get zone {name}: HTTP {code}: {err}'.format(name=zone_name, code=e.status_code,
                                                                           err=e.message))

    if not zone:
        module.fail_json(msg='Zone not found: {name}'.format(zone=zone_name))

    # Try to find the record by name and type
    record = next((item for item in zone.get('rrsets') if (item['name'] == name and item['type'] == rtype)), None)

    if state == 'present':
        # Create record if it does not exist
        if not record:
            try:
                pdns_client.create_record(server=server, zone=zone_name, name=name, rtype=rtype, content=content,
                                          ttl=ttl, disabled=disabled)
                return True, pdns_client.get_record(server=server, zone=zone_name, name=name)
            except PowerDNSError as e:
                module.fail_json(
                        msg='Could not create record {name}: HTTP {code}: {err}'.format(name=name, code=e.status_code,
                                                                                        err=e.message))
        # Check if changeable parameters match, else update record.
        if content not in [c.get('content') for c in record["records"]] or record.get('ttl', None) != ttl:
            try:
                pdns_client.create_record(server=server, zone=zone_name, name=name, rtype=rtype, content=content,
                                          ttl=ttl, disabled=disabled)
                return True, pdns_client.get_record(server=server, zone=zone_name, name=name)
            except PowerDNSError as e:
                module.fail_json(
                        msg='Could not update record {name}: HTTP {code}: {err}'.format(name=name, code=e.status_code,
                                                                                        err=e.message))
    elif state == 'absent':
        if record:
            try:
                pdns_client.delete_record(server=server, zone=zone_name, name=name, rtype=rtype)
                return True, None
            except PowerDNSError as e:
                module.fail_json(
                        msg='Could not delete record {name}: HTTP {code}: {err}'.format(name=name, code=e.status_code,
                                                                                        err=e.message))

    return False, record


def main():
    module = AnsibleModule(
            argument_spec=dict(
                    content=dict(type='str', required=False),
                    disabled=dict(type='bool', default=False),
                    name=dict(type='str', required=True),
                    server=dict(type='str', default='localhost'),
                    state=dict(type='str', default='present', choices=['present', 'absent']),
                    ttl=dict(type='int', default=86400),
                    type=dict(type='str', required=False, choices=['A', 'AAAA', 'CNAME', 'MX', 'PTR', 'SOA', 'SRV', 'TXT']),
                    zone=dict(type='str', required=True),
                    pdns_host=dict(type='str', default='127.0.0.1'),
                    pdns_port=dict(type='int', default=8081),
                    pdns_prot=dict(type='str', default='http', choices=['http', 'https']),
                    pdns_api_key=dict(type='str', required=False),
                    strict_ssl_checking=dict(type='bool', default=True),
            ),
            supports_check_mode=True,
    )

    pdns_client = PowerDNSClient(host=module.params['pdns_host'],
                                 port=module.params['pdns_port'],
                                 prot=module.params['pdns_prot'],
                                 api_key=module.params['pdns_api_key'],
                                 verify=module.params['strict_ssl_checking'])

    try:
        changed, record = ensure(module, pdns_client)
        module.exit_json(changed=changed, record=record)
    except Exception as e:
        module.fail_json(msg='Error: {0}'.format(str(e)))


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
