#!/usr/bin/env python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: powerdns_zone
short_description: Manage PowerDNS zones
description:
- Create, update or delete a PowerDNS zone using API
options:
  kind:
    description:
    - Zone kind
    required: False
    default: master
    choices: ['native', 'master', 'slave']
  name:
    description:
    - Zone name
    required: true
  nameservers:
    description:
    - List of nameservers
    required: False
    default: None
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
    - Protocol used to connect to PowerDNS API
    required: false
    default: http
    choices: ['http', 'https']
  pdns_api_key:
    description:
    - API Key to authenticate through PowerDNS API
  strict_ssl_checking:
    description:
    - Disables strict certificate checking
    default: true
author: "Thomas Krahn (@nosmoht)"
'''

EXAMPLES = '''
# Ensure a zone is present
- powerdns_zone:
    name: zone01.internal.example.com
    kind: master
    nameservers:
    - ns-01.internal.example.com
    - ns-02.internal.example.com
    state: present
    pdns_host: powerdns.example.cm
    pdns_port: 8080
    pdns_api_key: topsecret

# Ensure a zone is absent
- powerdns_zone:
    name: old-zone.internal.example.com
    state: absent
    pdns_host: powerdns.example.cm
    pdns_port: 8080
    pdns_api_key: topsecret
'''

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class PowerDNSError(Exception):
    def __init__(self, url, status_code, message):
        self.url = url
        self.status_code = status_code
        self.message = message
        super(PowerDNSError, self).__init__()


class PowerDNSClient:
    def __init__(self, host, port, prot, api_key, verify):
        self.url = '{prot}://{host}:{port}/api/v1'.format(prot=prot, host=host, port=port)
        self.session = requests.Session()
        self.session.headers.update({'X-API-Key': api_key})
        self.session.verify = verify

    def _handle_request(self, req):
        if req.status_code in [200, 201, 204]:
            if req.text:
                try:
                    return req.json()
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
        try:
            request_json = data.json()
            if 'error' in request_json:
                request_error = request_json.get('error')
            elif 'errors' in request_json:
                request_error = request_json.get('errors')
            else:
                request_error = 'No error message found'
            return request_error
        except Exception:
          pass
        return data.text

    def _get_zones_url(self, server):
        return '{url}/servers/{server}/zones'.format(url=self.url, server=server)

    def _get_zone_url(self, server, name):
        return '{url}/{name}'.format(url=self._get_zones_url(server), name=name)

    def get_zone(self, server, name):
        req = self.session.get(url=self._get_zone_url(server, name))
        if req.status_code in [404, 422]:  # zone does not exist
            return None
        return self._handle_request(req)

    def create_zone(self, server, data):
        req = self.session.post(url=self._get_zones_url(server), json=data)
        return self._handle_request(req)

    def delete_zone(self, server, name):
        req = self.session.delete(url=self._get_zone_url(server, name))
        return self._handle_request(req)

    def update_zone(self, server, zone):
        req = self.session.patch(url=self._get_zone_url(server=server, name=zone.get('name')), data=zone)
        return self._handle_request(req)


def diff(list1, list2):
    c = set(list1).union(set(list2))
    d = set(list1).intersection(set(list2))
    return list(c - d)


def ensure(module, pdns_client):
    kind = module.params['kind']
    masters = module.params['masters']
    name = module.params['name']
    nameservers = module.params['nameservers']
    server = module.params['server']
    state = module.params['state']
    try:
        zone = pdns_client.get_zone(server, name)
    except PowerDNSError as e:
        module.fail_json(
            msg='Could not get zone {name}: HTTP {code}: {err}'.format(name=name, code=e.status_code, err=e.message))

    if not zone:
        if state == 'present':
            try:
                zone = dict(name=name, kind=kind, nameservers=nameservers, masters=masters)
                if module.check_mode:
                    module.exit_json(changed=True, zone=zone)
                pdns_client.create_zone(server, zone)
                return True, pdns_client.get_zone(server, name)
            except PowerDNSError as e:
                module.fail_json(
                    msg='Could not create zone {name}: HTTP {code}: {err}'.format(name=name, code=e.status_code,
                                                                                  err=e.message))
    else:
        if state == 'absent':
            try:
                if module.check_mode:
                    module.exit_json(changed=True, zone=zone)
                pdns_client.delete_zone(server, name)  # zone.get('id'))
                return True, None
            except PowerDNSError as e:
                module.fail_json(
                    msg='Could not delete zone {name}: HTTP {code}: {err}'.format(name=name, code=e.status_code,
                                                                                  err=e.message))
                # Compare nameservers
                #        ns_diff = diff(nameservers if nameservers else list(), zone.get('nameservers', list()))
                #        if ns_diff:
                #            try:
                #                if module.check_mode:
                #                    module.exit_json(changed=True, zone=zone)
                #                pdns_client.update_zone(server, zone)
                #                return True, pdns_client.get_zone(name)
                #            except PowerDNSError as e:
                #                module.fail_json(
                #                    msg='Could not update zone {name}: HTTP {code}: {err}'.format(name=name, code=e.status_code,
                #                                                                                  err=e.message))
    return False, zone


def main():
    module = AnsibleModule(
        argument_spec=dict(
            kind=dict(type='str', required=False, default='master', choices=['native', 'master', 'slave']),
            masters=dict(type='list', required=False),
            name=dict(type='str', required=True),
            nameservers=dict(type='list', required=False),
            server=dict(type='str', required=False, default='localhost'),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            pdns_host=dict(type='str', default='127.0.0.1'),
            pdns_port=dict(type='int', default=8081),
            pdns_prot=dict(type='str', default='http', choices=['http', 'https']),
            pdns_api_key=dict(type='str', required=False),
            strict_ssl_checking=dict(type='bool', default=True),
        ),
        supports_check_mode=True,
    )

    if not HAS_REQUESTS:
        module.fail_json(msg="requests must be installed to use this module.")

    pdns_client = PowerDNSClient(host=module.params['pdns_host'],
                                 port=module.params['pdns_port'],
                                 prot=module.params['pdns_prot'],
                                 api_key=module.params['pdns_api_key'],
                                 verify=module.params['strict_ssl_checking'])

    try:
        changed, zone = ensure(module, pdns_client)
        module.exit_json(changed=changed, zone=zone)
    except Exception as e:
        module.fail_json(msg='Error: {0}'.format(str(e)))


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
