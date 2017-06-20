# -*- coding: utf-8 -*-
# license = http://opensource.org/licenses/MIT

import requests
import netaddr
import json

# INFOBLOX v1.2.1

# TODO: full list of fields for other object types
# TODO: change schema to include extra information such as searchable fields
# https://INFOBLOXURL/wapidoc/index.html#objects
OBJECT_TYPES = {
    'fixedaddress': {'return_fields': None},
    'grid': {'return_fields': None},
    'ipv4address': {'return_fields': None},
    'ipv6address': {'return_fields': None},
    'ipv6fixedaddress': {'return_fields': None},
    'ipv6network': {'return_fields': None},
    'ipv6networkcontainer': {'return_fields': None},
    'ipv6range': {'return_fields': None},
    'lease': {'return_fields': None},
    'macfilteraddress': {'return_fields': None},
    'member': {'return_fields': None},
    'namedacl': {'return_fields': None},
    'network': {'return_fields': [
        'authority',
        'bootfile',
        'bootserver',
        'comment',
        'ddns_domainname',
        'ddns_generate_hostname',
        'ddns_server_always_updates',
        'ddns_ttl',
        'ddns_update_fixed_addresses',
        'ddns_use_option81',
        'deny_bootp',
        'disable',
        'email_list',
        'enable_ddns',
        'enable_dhcp_thresholds',
        'enable_email_warnings',
        'enable_ifmap_publishing',
        'enable_snmp_warnings',
        'extattrs',
        'high_water_mark',
        'high_water_mark_reset',
        'ignore_dhcp_option_list_request',
        'ipv4addr',
        'lease_scavenge_time',
        'low_water_mark',
        'low_water_mark_reset',
        'members',
        'netmask',
        'network',
        'network_container',
        'network_view',
        'nextserver',
        'options',
        'pxe_lease_time',
        'recycle_leases',
        'update_dns_on_lease_renewal',
        'use_authority',
        'use_bootfile',
        'use_bootserver',
        'use_ddns_domainname',
        'use_ddns_generate_hostname',
        'use_ddns_ttl',
        'use_ddns_update_fixed_addresses',
        'use_ddns_use_option81',
        'use_deny_bootp',
        'use_email_list',
        'use_enable_ddns',
        'use_enable_dhcp_thresholds',
        'use_enable_ifmap_publishing',
        'use_ignore_dhcp_option_list_request',
        'use_lease_scavenge_time',
        'use_nextserver',
        'use_options',
        'use_recycle_leases',
        'use_update_dns_on_lease_renewal',
        'use_zone_associations',
        'zone_associations']},
    'networkcontainer': {'return_fields': None},
    'networkview': {'return_fields': None},
    'range': {'return_fields': [ 
        'always_update_dns',
        'authority',
        'bootfile',
        'bootserver',
        'comment',
        'ddns_domainname',
        'ddns_generate_hostname',
        'deny_all_clients',
        'deny_bootp',
        'disable',
        'email_list',
        'enable_ddns',
        'enable_dhcp_thresholds',
        'enable_email_warnings',
        'enable_ifmap_publishing',
        'enable_snmp_warnings',
        'end_addr',
        'exclude',
        'extattrs',
        'failover_association',
        'fingerprint_filter_rules',
        'high_water_mark',
        'high_water_mark_reset',
        'ignore_dhcp_option_list_request',
        'is_split_scope',
        'known_clients',
        'lease_scavenge_time',
        'logic_filter_rules',
        'low_water_mark',
        'low_water_mark_reset',
        'mac_filter_rules',
        'member',
        'ms_options',
        'ms_server',
        'nac_filter_rules',
        'name',
        'network',
        'network_view',
        'nextserver',
        'option_filter_rules',
        'options',
        'pxe_lease_time',
        'recycle_leases',
        'relay_agent_filter_rules',
        'server_association_type',
#        'split_member',
#        'split_scope_exclusion_percent',
        'start_addr',
#        'template',
        'unknown_clients',
        'update_dns_on_lease_renewal',
        'use_authority',
        'use_bootfile',
        'use_bootserver',
        'use_ddns_domainname',
        'use_ddns_generate_hostname',
        'use_deny_bootp',
        'use_email_list',
        'use_enable_ddns',
        'use_enable_dhcp_thresholds',
        'use_enable_ifmap_publishing',
        'use_ignore_dhcp_option_list_request',
        'use_known_clients',
        'use_lease_scavenge_time',
        'use_nextserver',
        'use_options',
        'use_recycle_leases',
        'use_unknown_clients',
        'use_update_dns_on_lease_renewal',
        ] },
    'record:a': {'return_fields': None},
    'record:aaaa': {'return_fields': None},
    'record:cname': {'return_fields': [
            'canonical',
            'comment',
            'disable',
            'dns_canonical',
            'dns_name',
            'extattrs',
            'name',
            'ttl',
            'use_ttl',
            'view',
            'zone' ]},
    'record:host': {'return_fields': ['aliases',
        'comment',
        'configure_for_dns',
        'disable',
        'dns_aliases',
        'dns_name',
        'extattrs',
        'ipv4addrs',
        'ipv6addrs',
        'name',
        'rrset_order',
        'ttl',
        'use_ttl',
        'view',
        'zone']},
    'record:host_ipv4addr': {'return_fields': ['bootfile',
        'bootserver',
        'configure_for_dhcp',
        'deny_bootp',
        'discovered_data',
        'enable_pxe_lease_time',
        'host',
        'ignore_client_requested_options',
        'ipv4addr',
        'last_queried',
        'mac',
        'match_client',
        'network',
        'nextserver',
        'options',
        'pxe_lease_time',
        'use_bootfile',
        'use_bootserver',
        'use_deny_bootp',
        'use_for_ea_inheritance',
        'use_ignore_client_requested_options',
        'use_nextserver',
        'use_options',
        'use_pxe_lease_time']},
    'record:host_ipv6addr': {'return_fields': ['address_type',
        'configure_for_dhcp',
        'discovered_data struct',
        'domain_name',
        'domain_name_servers',
        'duid',
        'host',
        'ipv6addr',
        'ipv6prefix',
        'ipv6prefix_bits',
        'match_client',
        'options',
        'preferred_lifetime',
        'use_domain_name',
        'use_domain_name_servers',
        'use_for_ea_inheritance',
        'use_options',
        'use_preferred_lifetime',
        'use_valid_lifetime',
        'valid_lifetime']},
    'record:mx': {'return_fields': [
        'comment',
        'disable',
        'dns_mail_exchanger',
        'dns_name',
        'extattrs',
        'mail_exchanger',
        'name',
        'preference',
        'ttl',
        'use_ttl',
        'view',
        'zone', ]},
    'record:ptr': {'return_fields': None},
    'record:srv': {'return_fields': None},
    'record:txt': {'return_fields': None},
    'restartservicestatus': {'return_fields': None},
    'scheduledtask': {'return_fields': None},
    'search': {'return_fields': None},
    'view': {'return_fields': None},
    'zone_auth': {'return_fields': None},
    'zone_delegated': {'return_fields': None},
    'zone_forward': {'return_fields': None},
    'zone_stub': {'return_fields': None}
}


def diff_obj(a, b, parent=None):
    '''
    diff infoblox data

    does 'a' have a value/record thats not found in 'b'

    Note that func:nextavailableip will not cause a diff if the ipaddress is in it's range
    '''
    if isinstance(a, list):
        if isinstance(b, list):
            for i in a:
                diff = {'new':i, 'old':b, '_note':'(new) has one or more mismatch items in (old). More diffs could still exist!'}
                for ii in b:
                    if not diff_obj(i, ii):
                        diff = None
                        break
                if diff:
                    return diff
            return None
        else:
            return {'new':a, 'old':b, '_note':'(new) is list, (old) is not list'}
    elif isinstance(a, dict):
        if isinstance(b, dict):
            diffkeys = set(a.keys()) - set(b.keys())
            if diffkeys:
                return {'new':a.keys(), 'old':b.keys(), '_note': '{0}'.format(diffkeys)}
            for i in a:
                diff = diff_obj(a[i], b[i], parent=i)
                if diff:
                    return diff
            return None
        else:
            return {'new':a, 'old':b, '_note':'(new) is dict, (old) is not dict'}

    if isinstance(a, str):
        # TODO: this could break if the key belonging to the value is not ipv4addr or ipv6addr.
        if a.startswith('func:nextavailableip:'):
            if not is_ipaddr_in_ipfunc_range(b, a):
                return {'new':a, 'old':b, '_note':'ip is not in range or is different network'}
            return None

    if a != b:
        if parent:
            return {'new': { parent: a }, 'old': { parent: b }, '_note': 'More diffs could still exist!' }
        return {'new':a, 'old':b, '_note': 'More diffs could still exist!' }
    return None


def is_ipaddr_in_ipfunc_range(ipaddr, ipfunc):
    '''
    return true if the ipaddress is in the range of the nextavailableip function
    '''
    arg = ipfunc.replace('func:nextavailableip:','')
    arg = arg.replace(',external','')
    #TODO: support complex func:nextavailableip:network/ZG54dfgsrDFEFfsfsLzA:10.0.0.0/8/default
    if '-' in arg:
        r = arg.split('-')
        if netaddr.IPAddress(ipaddr) in netaddr.IPRange(r[0],r[1]):
            return True
    if '/' in arg:
        if netaddr.IPAddress(ipaddr) in netaddr.IPNetwork(arg):
            return True
    return False





class Session:

    config = None

    def __init__(self, api_sslverify=True, api_url='https://127.0.0.1/wapi/v1.2.1', api_user='', api_key=''):
        self.config = { 
            'api_sslverify': api_sslverify,
            'api_url': api_url,
            'api_user': api_user, 
            'api_key': api_key,
        }


    def _call(self, method, path='', data=None, headers=None):
        url = '{0}/{1}'.format(self.config['api_url'], path)
        auth = (self.config['api_user'], self.config['api_key'])
        robj = getattr(requests, method)
        try:
            r = robj(url, data=data, auth=auth, headers=None, verify=self.config['api_sslverify'])
        except Exception as e:
            raise Exception({'execption': e, 'url': url, 'api_user': self.config['api_user'],
                             'api_sslverify':self.config['api_sslverify'] })
        if r.status_code > 201:
            raise Exception(r.content, data)
        try:
            rjson = r.json()
        except Exception:
            raise Exception(r.content)
        return rjson


    def create_object(self, object_type, data):
        '''
        create object
        '''
        try:
            data=json.dumps(data)
        except Exception as e:
            raise Exception({'Execption': e, 'data': data})
        headers={'content-type': 'application/json'}
        return self._call('post', object_type, data=data, headers=headers)


    def update_object(self, objref, data):
        '''
        update object
        '''
        try:
            data=json.dumps(data)
        except Exception as e:
            raise Exception({'Execption': e, 'data': data})
        headers={'content-type': 'application/json'}
        return self._call('put', objref, data, headers=headers)


    def delete_object(self, objref):
        '''
        delete object
        '''
        return self._call('delete', objref)


    def get_object(self, objref, data={}, return_fields=None, max_results=None, ensure_none_or_one_result=False):
        '''
        Get object information

        max_results = number of matching objects to return
        '''
        if not return_fields:
            for objtype in OBJECT_TYPES:
                if objref == objtype or objref.startswith('{0}/'.format(objtype)):
                    if OBJECT_TYPES[objtype].has_key('return_fields'):
                        if OBJECT_TYPES[objtype]['return_fields']:
                            return_fields = ','.join(OBJECT_TYPES[objtype]['return_fields'])

        if return_fields:
            data.update( { '_return_fields': return_fields } )

        if max_results:
            data.update( { '_max_results': max_results } )

        if ensure_none_or_one_result:
            data.update( { '_max_results': 2 } )

        #obj = self._read(objref, data=data)
        obj = self._call('get', objref, data)

        if ensure_none_or_one_result:
            if len(obj) > 1:
                raise Exception('multiple matchs, when limiting to one', data)
            if len(obj) == 1:
                return obj[0]
            return None

        return obj


    def get_host_advanced(self, name=None,
                            mac=None, ipv4addr=None ):
        '''
        Get host and fill extra objects in host with full details
        '''
        host = self.get_host(name, mac, ipv4addr)

        if host.has_key('ipv4addrs'):
            extra_info = []
            for r in host['ipv4addrs']:
                extra_info.append(self.get_object(r['_ref']))
            host['ipv4addrs'] = extra_info

        if host.has_key('ipv6addrs'):
            extra_info = []
            for r in host['ipv6addrs']:
                extra_info.append(self.get_object(r['_ref']))
            host['ipv6addrs'] = extra_info
        return host


    def get_host(self, name=None,
                            mac=None,
                            ipv4addr=None, 
                            return_fields=None):
        '''
        Get host information
        '''
        data = { }
        if name: data.update( {'name': name} )
        if mac: data.update( {'mac': mac} )
        if ipv4addr: data.update( {'ipv4addr': ipv4addr} )
        return self.get_object('record:host', data, return_fields, ensure_none_or_one_result=True)



    def get_host_ipv4addr_object(self, ipv4addr=None, 
                                            mac=None,
                                            discovered_data=None,
                                            return_fields=None):
        '''
        Get host ipv4addr information 
        '''
        data = { }
        if ipv4addr: data.update( { 'ipv4addr': ipv4addr} )
        if mac: data.update( { 'mac': mac} )
        if discovered_data: data.update( { 'discovered_data': discovered_data} )
        return self.get_object('record:host_ipv4addr', data, return_fields)


    def get_host_ipv6addr_object(self, ipv6addr=None, 
                                            mac=None,
                                            discovered_data=None,
                                            return_fields=None):
        '''
        Get host ipv6addr information
        '''
        data = { }
        if ipv6addr: data.update( { 'ipv6addr': ipv6addr} )
        if mac: data.update( { 'mac': mac} )
        if discovered_data: data.update( { 'discovered_data': discovered_data} )
        return self.get_object('record:host_ipv6addr', data, return_fields)


    def get_network(self, ipv4addr=None, network=None, return_fields=None):
        '''
        Get list of all networks.
        This is most helpfull when looking up subnets to
        use with func:nextavailableip        
        This call is offen slow and not cached!
        '''
        data = { }
        if ipv4addr: data.update({ 'ipv4addr': ipv4addr })
        if network: data.update({ 'network~': network })
        return self.get_object('network', data, return_fields)


    def delete_host(self, name=None, mac=None, ipv4addr=None):
        host = self.get_host(name=name,mac=mac,ipv4addr=ipv4addr)
        if host:
            return self.delete_object(host['_ref'])
        return True


    def create_host(self, data):
        '''
        Add host

        Example: 

        data: = {'aliases': ['hostname.math.uwaterloo.ca'],
            'extattrs': [{'Business Contact': {'value': 'EXAMPLE@uwaterloo.ca'}},
                {'Pol8 Classification': {'value': 'Restricted'}},
                {'Primary OU': {'value': 'CS'}},
                {'Technical Contact': {'value': 'EXAMPLE@uwaterloo.ca'}}],
            'ipv4addrs': [{'configure_for_dhcp': True,
                'ipv4addr': 'func:nextavailableip:129.97.139.0/24',
                'mac': '00:50:56:84:6e:ae'}],
            'ipv6addrs': [],
            'name': 'hostname.uwaterloo.ca'}

        - func:nextavailableip:network/ZG54dfgsrDFEFfsfsLzA:10.0.0.0/8/default
        - func:nextavailableip:10.0.0.0/8
        - func:nextavailableip:10.0.0.0/8,external
        - func:nextavailableip:10.0.0.3-10.0.0.10
        '''
        return self.create_object('record:host', data)


    def get_range(self, start_addr=None, end_addr=None, return_fields=None):
        '''
        get range
        '''
        data = {}
        if start_addr: data.update({ 'start_addr': start_addr })
        if end_addr: data.update({ 'end_addr': end_addr })
        return self.get_object('range', data, return_fields, ensure_none_or_one_result=True)


    def create_cname(self, data):
        return self.create_object('record:cname', data)


    def get_cname(self, name=None, canonical=None, return_fields=None, return_one_result=True):
        '''
        Get cname
        '''
        data = { }
        if name: data.update({ 'name': name })
        if canonical: data.update({ 'canonical': canonical })
        return self.get_object('record:cname', data, return_fields, ensure_none_or_one_result=True)



