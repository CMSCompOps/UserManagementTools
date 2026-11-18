import requests
import os
import json
import argparse
from datetime import datetime
from dateutil.relativedelta import relativedelta

parser = argparse.ArgumentParser()
parser.add_argument("--update-users", action='store_true', help="Update ssl certificates and create new users coming from CRIC", required=False)
args = parser.parse_args()

token = os.environ.get("OIDC_AT", "")
try:
    with open('./token') as fp:
        token = fp.read().splitlines()[0]
except Exception as e:
    if not token:
        print('Token was not set as env variable and reading from file failed.')
        print(e)
        exit()
    
user_map = {}
messages = []
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json;charset=UTF-8"}
base_iam_url = os.environ.get("BASE_IAM_URL", "https://cms-auth-dev.web.cern.ch/")
base_cric_url = os.environ.get("BASE_CRIC_URL", "https://cms-cric.cern.ch")

def make_api_request(url='', headers=headers, type='get', data=''):
    try:
        if type == 'get':
            response = requests.get(url, headers=headers)
        if type == 'post':
            response = requests.post(url, data=data, headers=headers)
        if type == 'patch':
            response = requests.patch(url, data=data, headers=headers)
        if type == 'put':
            response = requests.put(url, data=data, headers=headers)    
        if not response.ok:
            warning_message = {
                'type': 'failed_http_response',
                'iam_server': base_iam_url,
                'cric_server': base_cric_url,
                'url': url,
                'response_code': response.status_code,
                'raw_text': response.text,
                'request_data': data
            }
            messages.append(warning_message)
        return response if type != 'get' else response.json()
    except requests.exceptions.HTTPError as errh:
        print ("Http Error:",errh)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:",errc)
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:",errt)
    except requests.exceptions.RequestException as err:
        print ("OOps: Something Else",err)
    

# Get map of CERN username and IAM id
startIndex=1
totalResults=2
while(startIndex < totalResults):
    users_url = base_iam_url + "scim/Users?attributes=displayName,urn:indigo-dc:scim:schemas:IndigoUser&startIndex=%d" % startIndex
    response = make_api_request(users_url, headers, type='get')
    totalResults = response.get('totalResults')
    startIndex += response.get('itemsPerPage')
    for user in response['Resources']:
        for profile in user.get('urn:indigo-dc:scim:schemas:IndigoUser', {}).get('oidcIds', []):
            if profile['issuer'] == 'https://auth.cern.ch/auth/realms/cern':
                user_map.setdefault(user['id'] ,profile['subject'])
                
# Get map of group name and IAM id
iam_group_map = {}
startIndex=1
totalResults=2
while(startIndex < totalResults):
    groups_url = base_iam_url + "scim/Groups?startIndex=%d" % startIndex
    response = make_api_request(groups_url, headers, type='get')
    totalResults = response.get('totalResults')
    startIndex += response.get('itemsPerPage')
    for group in response['Resources']:
        iam_group_map.setdefault(group['displayName'], group['id'])

inv_user_map = {v: k for k, v in user_map.items()}
cric_cert = '/src/certs/criciam.crt.pem'
cric_cert_key = '/src/certs/criciam.key.pem'

# CERN Grid CA rollover: IAM resolves an account by the (subjectDn, issuerDn) pair, so a
# certificate issued by the new CERN Grid CA does not match an entry registered under the old one
# although the subject DN is identical. While certificates from both CAs are in circulation every
# CERN Grid DN is pushed once per CA, whatever CA CRIC itself stores. Once the old CA is retired
# remove it from this list and drop its entries from IAM.
CERN_GRID_CAS = ['CN=CERN Grid Certification Authority,DC=cern,DC=ch',
                 'CN=CERN Grid Certification Authority 2,DC=cern,DC=ch']

# GEANT TCS replaced its CAs in 2025 keeping the subject DNs. The old ones no longer issue and
# are out of the IGTF distribution, but CRIC still stores them for those DNs.
GEANT_TCS_RETIRED_CAS = ['CN=GEANT eScience Personal CA 4,O=GEANT Vereniging,C=NL',
                         'CN=GEANT TCS Authentication RSA CA 4B,O=GEANT Vereniging,C=NL']
GEANT_TCS_CA = 'CN=GEANT TCS Authentication RSA CA 5,O=GEANT Vereniging,C=NL'


def to_rfc2253(name, sep):
    """
        CRIC stores DNs slash-separated, root first ('/DC=ch/DC=cern/OU=.../CN=...') and CAs
        comma-separated, root first ('DC=ch,DC=cern,CN=...'). IAM wants both leaf first and
        comma-separated ('CN=...,DC=cern,DC=ch').
    """
    return ','.join(reversed(name.strip(sep).split(sep)))


def iam_certificates(sslprofiles):
    """
        Translate the CRIC sslprofiles of a user into the IAM certificate list.
        :return: list of {subjectDn, issuerDn, display}, without duplicates, CRIC order kept
    """
    certificates = []
    seen = set()
    for cert in sslprofiles:
        dn = to_rfc2253(cert['dn'], '/')
        ca = cert.get('ca') or ''
        # a few CRIC profiles carry the CA slash-separated, like the DN
        ca = to_rfc2253(ca, '/' if ca.startswith('/') else ',')
        if not ca:
            ca = CERN_GRID_CAS[-1] if 'DC=cern' in cert['dn'] else 'unnknown'
        if ca in GEANT_TCS_RETIRED_CAS:
            ca = GEANT_TCS_CA
        issuers = CERN_GRID_CAS if ca in CERN_GRID_CAS else [ca]
        for issuer in issuers:
            if (dn, issuer) in seen:
                continue
            seen.add((dn, issuer))
            certificates.append({"subjectDn": dn, "issuerDn": issuer, "display": 'cric-cert'})
    return certificates


if args.update_users:
    # Sync users from cric
    cric_url = base_cric_url + '/api/accounts/group/query/?json&preset=full&name=CMS_USERS_autosynced'
    response = requests.get(cric_url, cert=(cric_cert, cric_cert_key), verify='/etc/ssl/certs/CERN-bundle.pem').json()

    # Format timestamp to set user endDate 6 days from now:
    now = datetime.now()

    for group_name, group in response.items():
        for user in group['users']:
            if user['login'] in inv_user_map:
                certificates = iam_certificates(user['sslprofiles'])
                patch_body = {
                    "schemas": [
                        "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                    ],
                    "operations": [
                        {
                            "op": "add",
                            "value": {
                                "urn:indigo-dc:scim:schemas:IndigoUser": {
                                    "certificates": certificates
                                }
                            }
                        }
                    ]
                }
                iam_id = inv_user_map[user['login']]
                user_url = base_iam_url + "scim/Users/%s" % iam_id
                make_api_request(user_url, headers, data=json.dumps(patch_body), type='patch')
            else:
                certificates = iam_certificates(user['sslprofiles'])
                body = {
                        "schemas": [
                            "urn:ietf:params:scim:schemas:core:2.0:User",
                            "urn:indigo-dc:scim:schemas:IndigoUser"
                        ],
                        "name": {
                            "familyName": user['first_name'],
                            "formatted": user['name'],
                            "givenName": user['last_name'],
                        },
                        "displayName": user['login'],
                        "userName": user['login'],
                        "active": True,
                        "emails": [
                            {
                                "type": "work",
                                "value": user['email'],
                                "primary": True
                            }
                        ],
                        "urn:indigo-dc:scim:schemas:IndigoUser": {
                            "oidcIds": [
                                {
                                    "issuer": "https://auth.cern.ch/auth/realms/cern",
                                    "subject": user['login']
                                }
                            ],
                            "certificates": certificates
                        }
                    }
                users_url = base_iam_url + "scim/Users"
                response = make_api_request(users_url, headers, data=json.dumps(body), type='post')
                iam_id = response.json().get('id')
                # Add user to the default cms group
                body = {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "operations": [{
                    "op": "add",
                    "path": "members",
                    "value": [{"value": iam_id}]
                }]
                }
                patch_url = base_iam_url + "scim/Groups/%s" % iam_group_map.get('cms')
                make_api_request(patch_url, headers, data=json.dumps(body), type='patch')
                # Attach CERN person ID to user
                if user['personid']:
                    body = {
                        'prefix': 'hr.cern',
                        'name': 'cern_person_id',
                        'value': str(user['personid'])}
                    patch_url = base_iam_url + "/iam/account/%s/labels" % iam_id
                    make_api_request(patch_url, headers, data=json.dumps(body), type='put')
                else:
                    warning_message = {
                        'type': 'user_has_no_personid',
                        'iam_server': base_iam_url,
                        'cric_server': base_cric_url,
                        'user_name': user['login'],
                    }
                    messages.append(warning_message)

# Get list of existing members to flash groups empty
iam_group_existing_users_map = {}
startIndex=1
totalResults=2
for group_name, group_id in iam_group_map.items():
    members = []
    while(startIndex < totalResults):
        groups_url = base_iam_url + "scim/Groups/%s/members?startIndex=%d" % (group_id ,startIndex)
        response = make_api_request(groups_url, headers, type='get')
        totalResults = response.get('totalResults')
        startIndex += response.get('itemsPerPage')
        members.extend(response['Resources'])
    iam_group_existing_users_map.setdefault(group_id, members)
cric_url = base_cric_url + '/api/accounts/group/query/?json&tag_relation=iam_group'

response = requests.get(cric_url, cert=(cric_cert, cric_cert_key), verify='/etc/ssl/certs/CERN-bundle.pem').json()

cric_group_map = {}
for group, details in response.items():
    iam_group_name = 'cms/%s/%s' % (details['role'], details['tag_name'])
    if details['role'] == 'NULL':
        iam_group_name = 'cms/%s' % (details['tag_name'])
    if iam_group_name not in iam_group_map:
        warning_message = {
            'type': 'group_not_found',
            'iam_server': base_iam_url,
            'cric_server': base_cric_url,
            'group_name': iam_group_name,
        }
        messages.append(warning_message)
        continue
    group_name = iam_group_map[iam_group_name]
    for user in details['users']:
        if user['login'] in inv_user_map:
            cric_group_map.setdefault(group_name, []).append(inv_user_map.get(user['login']))
        else:
            warning_message = {
                'type': 'user_not_found',
                'iam_server': base_iam_url,
                'cric_server': base_cric_url,
                'user_name': user['login'],
            }
            messages.append(warning_message)


# Give cms/compute/scope membership to siteadmins
cric_url = base_cric_url + '/api/accounts/group/query/?json&role=site-admin&tag_relation=facility'
response = requests.get(cric_url, cert=(cric_cert, cric_cert_key), verify='/etc/ssl/certs/CERN-bundle.pem').json()
iam_group = 'cms/compute/scope'
if iam_group not in iam_group_map:
        warning_message = {
            'type': 'group_not_found',
            'iam_server': base_iam_url,
            'cric_server': base_cric_url,
            'group_name': iam_group_name,
        }
        messages.append(warning_message)
else:
    group_name = iam_group_map[iam_group]
    for group, details in response.items():
        for user in details['users']:
            if user['login'] in inv_user_map:
                cric_group_map.setdefault(group_name, []).append(inv_user_map.get(user['login']))
            else:
                warning_message = {
                    'type': 'user_not_found',
                    'iam_server': base_iam_url,
                    'cric_server': base_cric_url,
                    'user_name': user['login'],
                }
                messages.append(warning_message)

# Empty existing groups
for group_id, members in iam_group_existing_users_map.items():
    body = {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "operations": [{
                    "op": "remove",
                    "path": "members",
                    "value": members
                }]
              }
    if group_id in cric_group_map:
        patch_url = base_iam_url + "scim/Groups/%s" % group_id
        make_api_request(patch_url, headers, data=json.dumps(body), type='patch')


# Sync users membership from CRIC
for group_id, users in cric_group_map.items():
    body = {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "operations": [{
                    "op": "add",
                    "path": "members",
                    "value": [{"value": user_id} for user_id in users]
                }]
              }
    patch_url = base_iam_url + "scim/Groups/%s" % group_id
    make_api_request(patch_url, headers, data=json.dumps(body), type='patch')

print(json.dumps(messages))