install
--------------

```
pip install libinfoblox
# or
python3 setup.py install
# or
python3 setup.py sdist
python3 -m pip install -I dist/libinfoblox-1.0.tar.gz
```


code examples
--------------

API documents can be found on your infoblox server at:

    https://INFOBLOX/wapidoc


```
import libinfoblox

s = libinfoblox.Session(api_url='https://INFOBLOX/wapi/v1.2.1', api_user='username', api_key='GDA$qt3455hg')

data = {'name': 'hostname.example.ca',
        'aliases': ['hostname.math.example.ca'],
        'extattrs': [{'Business Contact': {'value': 'example@example.ca'}},
        {'Pol8 Classification': {'value': 'Restricted'}},
        {'Primary OU': {'value': 'CS'}},
        {'Technical Contact': {'value': 'example@example.ca'}}],
        'ipv4addrs': [{'configure_for_dhcp': True,
        'ipv4addr': 'func:nextavailableip:129.97.139.0/24',
        'mac': '00:50:56:84:6e:ae'}],
        'ipv6addrs': [], }

s.create_object('record:host', data, **kwargs)
host = s.get_host('hostname.math.example.ca')
s.delete_host('hostname.math.example.ca')
```



developer notes
--------------
```
cat > ~/.pypirc <<EOF
[distutils]
index-servers =
  pypi
  testpypi

[pypi]
repository=https://pypi.python.org/pypi
username=your_username
password=your_password

[testpypi]
repository=https://testpypi.python.org/pypi
username=your_username
password=your_password
EOF
chmod 600 ~/.pypirc

git tag 2.1 -m "Adds a tag so that we can put this on PyPI."
git push --tags origin master
# Github creates tarballs for download at https://github.com/{username}/{module_name}/archive/{tag}.tar.gz
python setup.py register --repository testpypi
python setup.py sdist upload --repository testpypi
# python setup.py register --repository pypi
# python setup.py sdist upload --repository pypi
```
