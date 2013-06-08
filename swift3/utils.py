# Copyright (c) 2010 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import urlparse
from urllib import unquote, quote
from xml.dom.minidom import parseString
from xml.sax.saxutils import escape as xml_escape

from swift.common.swob import Response
from swift.common.middleware.s3acl import AUTHENTICATED_USERNAME
from swift.common.middleware.acl import parse_acl
from swift.common.http import HTTP_BAD_REQUEST, HTTP_FORBIDDEN, \
    HTTP_NOT_FOUND, HTTP_CONFLICT, HTTP_NOT_IMPLEMENTED, \
    HTTP_LENGTH_REQUIRED, HTTP_SERVICE_UNAVAILABLE


MAX_BUCKET_LISTING = 1000
AMZ_ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers'
AMZ_AUTHENTICATED_USERS = \
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
REPLACE_USERNAMES = {
    AMZ_ALL_USERS: '.r:*',
    AMZ_AUTHENTICATED_USERS: AUTHENTICATED_USERNAME
}
# List of  sub-resources that must be maintained as part of the HMAC
# signature string.
ALLOWED_SUB_RESOURCES = sorted([
    'acl', 'delete', 'lifecycle', 'location', 'logging', 'notification',
    'partNumber', 'policy', 'requestPayment', 'torrent', 'uploads', 'uploadId',
    'versionId', 'versioning', 'versions', 'website'
])


def get_err_response(code):
    """
    Given an HTTP response code, create a properly formatted xml error response

    :param code: error code
    :returns: webob.response object
    """
    error_table = {
        'AccessDenied':
        (HTTP_FORBIDDEN, 'Access denied'),
        'BucketAlreadyExists':
        (HTTP_CONFLICT, 'The requested bucket name is not available'),
        'BucketNotEmpty':
        (HTTP_CONFLICT, 'The bucket you tried to delete is not empty'),
        'InvalidArgument':
        (HTTP_BAD_REQUEST, 'Invalid Argument'),
        'InvalidBucketName':
        (HTTP_BAD_REQUEST, 'The specified bucket is not valid'),
        'InvalidURI':
        (HTTP_BAD_REQUEST, 'Could not parse the specified URI'),
        'InvalidDigest':
        (HTTP_BAD_REQUEST, 'The Content-MD5 you specified was invalid'),
        'BadDigest':
        (HTTP_BAD_REQUEST, 'The Content-Length you specified was invalid'),
        'NoSuchBucket':
        (HTTP_NOT_FOUND, 'The specified bucket does not exist'),
        'SignatureDoesNotMatch':
        (HTTP_FORBIDDEN, 'The calculated request signature does not '
            'match your provided one'),
        'RequestTimeTooSkewed':
        (HTTP_FORBIDDEN, 'The difference between the request time and the'
        ' current time is too large'),
        'NoSuchKey':
        (HTTP_NOT_FOUND, 'The resource you requested does not exist'),
        'Unsupported':
        (HTTP_NOT_IMPLEMENTED, 'The feature you requested is not yet'
        ' implemented'),
        'MissingContentLength':
        (HTTP_LENGTH_REQUIRED, 'Length Required'),
        'ServiceUnavailable':
        (HTTP_SERVICE_UNAVAILABLE, 'Please reduce your request rate'),
        'IllegalVersioningConfigurationException':
        (HTTP_BAD_REQUEST, 'The specified versioning configuration invalid'),
        'MalformedACLError':
        (HTTP_BAD_REQUEST, 'The XML you provided was not well-formed or did '
                           'not validate against our published schema')
    }

    resp = Response(content_type='text/xml')
    resp.status = error_table[code][0]
    resp.body = '<?xml version="1.0" encoding="UTF-8"?>\r\n<Error>\r\n  ' \
                '<Code>%s</Code>\r\n  <Message>%s</Message>\r\n</Error>\r\n' \
                % (code, error_table[code][1])
    return resp


def get_acl(account_name, headers):
    """
    Attempts to construct an S3 ACL based on what is found in the swift headers
    """

    acl = 'private'  # default to private

    if 'x-container-read' in headers:
        if headers['x-container-read'] == ".r:*" or\
            ".r:*," in headers['x-container-read'] or \
                ",*," in headers['x-container-read']:
            acl = 'public-read'
    if 'x-container-write' in headers:
        if headers['x-container-write'] == ".r:*" or\
            ".r:*," in headers['x-container-write'] or \
                ",*," in headers['x-container-write']:
            if acl == 'public-read':
                acl = 'public-read-write'
            else:
                acl = 'public-write'

    if acl == 'private':
        body = ('<AccessControlPolicy>'
                '<Owner>'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Owner>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="CanonicalUser">'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Grantee>'
                '<Permission>FULL_CONTROL</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '</AccessControlPolicy>' %
                (account_name, account_name, account_name, account_name))
    elif acl == 'public-read':
        body = ('<AccessControlPolicy>'
                '<Owner>'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Owner>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="CanonicalUser">'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Grantee>'
                '<Permission>FULL_CONTROL</Permission>'
                '</Grant>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="Group">'
                '<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>'
                '</Grantee>'
                '<Permission>READ</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '</AccessControlPolicy>' %
                (account_name, account_name, account_name, account_name))
    elif acl == 'public-read-write':
        body = ('<AccessControlPolicy>'
                '<Owner>'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Owner>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="CanonicalUser">'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Grantee>'
                '<Permission>FULL_CONTROL</Permission>'
                '</Grant>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="Group">'
                '<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>'
                '</Grantee>'
                '<Permission>READ</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="Group">'
                '<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>'
                '</Grantee>'
                '<Permission>WRITE</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '</AccessControlPolicy>' %
                (account_name, account_name, account_name, account_name))
    else:
        body = ('<AccessControlPolicy>'
                '<Owner>'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Owner>'
                '<AccessControlList>'
                '<Grant>'
                '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                'XMLSchema-instance" xsi:type="CanonicalUser">'
                '<ID>%s</ID>'
                '<DisplayName>%s</DisplayName>'
                '</Grantee>'
                '<Permission>FULL_CONTROL</Permission>'
                '</Grant>'
                '</AccessControlList>'
                '</AccessControlPolicy>' %
                (account_name, account_name, account_name, account_name))
    return Response(body=body, content_type="text/plain")


def amz_group_grant(uri, permission):
    """
    Returns XML Grant for group with URI.

    :param uri: group URI
    :param permission: permission value
    """
    grant = (
        '<Grant>'
        '<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xsi:type="Group">'
        '<URI>%s</URI>'
        '</Grantee>'
        '<Permission>%s</Permission>'
        '</Grant>' % (uri, permission))
    return grant


def amz_user_grant(user_id, name, permission):
    """
    Returns XML Grant for user.

    :param user_id: user id
    :param name: user name
    :param permission: permission value
    """
    grant = (
        '<Grant>'
        '<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xsi:type="CanonicalUser">'
        '<ID>%s</ID>'
        '<DisplayName>%s</DisplayName>'
        '</Grantee>'
        '<Permission>%s</Permission>'
        '</Grant>' % (user_id, name, permission))
    return grant


def get_s3_acl(headers, acl_headers, resource='container'):
    out = ['<AccessControlPolicy>']
    owner_header = 'x-%s-owner' % resource
    headers = dict([(k.lower(), v) for k, v in headers.iteritems()])
    if owner_header in headers:
        owner = xml_escape(headers[owner_header])
        out.append('<Owner><ID>%s</ID><DisplayName>%s</DisplayName></Owner>' %
                   (owner, owner))
    out.append('<AccessControlList>')
    for header in acl_headers:
        if header in headers:
            permission = None
            if resource == 'container':
                # len(x-container-acl-) = 16; len(x-container-) = 12
                frm = 16 if header.startswith('x-container-acl-') else 12
                permission = header[frm:].upper().replace('-', '_')
            elif resource == 'object':
                # len(x-object-acl-) = 13
                permission = header[13:].upper().replace('-', '_')
            if permission:
                referrers, groups = parse_acl(headers[header])
                for ref in referrers:
                    uri = AMZ_ALL_USERS if ref == '*' else ref
                    grant = amz_group_grant(uri, permission)
                    out.append(grant)
                for group in groups:
                    grant = amz_user_grant(group, group, permission)
                    out.append(grant)
    out.append('</AccessControlList></AccessControlPolicy>')
    body = ''.join(out)
    return Response(body=body, content_type='application/xml',
                    headers={'Content-Length': str(len(body))})


def parse_access_control_policy(xml):
    """
    Parse given access control policy XML. Sample ACP XML

    <AccessControlPolicy>
      <Owner>
        <ID>ID</ID>
        <DisplayName>EmailAddress</DisplayName>
      </Owner>
      <AccessControlList>
        <Grant>
          <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xsi:type="CanonicalUser">
            <ID>ID</ID>
            <DisplayName>EmailAddress</DisplayName>
          </Grantee>
          <Permission>Permission</Permission>
        </Grant>
      </AccessControlList>
    </AccessControlPolicy>

    :param xml: XML string with ACP
    :returns : dict with ACL 'owner':<owner>, 'acl': [{'user':<username>,
               'permissions':[<permission>,...]},...]}
    """
    out = {'owner': '', 'acl': []}
    dom = parseString(xml)
    if len(dom.childNodes) and \
            dom.childNodes[0].nodeName == 'AccessControlPolicy':
        acp = dom.childNodes[0]
        acl = None
        for node in acp.childNodes:
            if node.nodeName == 'Owner':
                for n in node.childNodes:
                    if n.nodeName == 'ID':
                        out['owner'] = n.childNodes[0].nodeValue
            elif node.nodeName == 'AccessControlList':
                acl = node
        if acl:
            for grant in acl.childNodes:
                user = {'user': '', 'permissions': []}
                if grant.nodeName != 'Grant':
                    continue
                for node in grant.childNodes:
                    if node.nodeName == 'Grantee':
                        for n in node.childNodes:
                            if n.nodeName == 'ID':
                                user['user'] = n.childNodes[0].nodeValue
                            elif n.nodeName == 'URI':
                                user['user'] = n.childNodes[0].nodeValue
                            elif n.nodeName == 'EmailAddress':
                                user['user'] = n.childNodes[0].nodeValue
                    elif node.nodeName == 'Permission':
                        if node.childNodes[0].nodeValue:
                            v = node.childNodes[0].nodeValue
                            user['permissions'].append(v)
                out['acl'].append(user)
    return out


def acp_to_headers(env, resource):
    """
    Update env, add Swift ACL headers based on request body (wsgi.input).

    :param env: WSGI enviroment dict
    :param resource: resource type object or container
    :returns : if any error occur return webob.Response object, else None
    """
    if 'wsgi.input' not in env:
        return get_err_response('MalformedACLError')
    try:
        acp = parse_access_control_policy(env['wsgi.input'].read())
    except:
        return get_err_response('MalformedACLError')
    if resource == 'object':
        permissions = {'HTTP_X_OBJECT_ACL_READ': [],
                       'HTTP_X_OBJECT_ACL_WRITE': [],
                       'HTTP_X_OBJECT_ACL_READ_ACP': [],
                       'HTTP_X_OBJECT_ACL_WRITE_ACP': []}
    elif resource == 'container':
        permissions = {'HTTP_X_CONTAINER_READ': [],
                       'HTTP_X_CONTAINER_ACL_READ': [],
                       'HTTP_X_CONTAINER_WRITE': [],
                       'HTTP_X_CONTAINER_ACL_READ_ACP': [],
                       'HTTP_X_CONTAINER_ACL_WRITE_ACP': []}
    for user in acp.get('acl', []):
        username = user.get('user')
        if username:
            perms = user.get('permissions', [])
            if 'FULL_CONTROL' in perms:
                perms = ['READ', 'WRITE', 'READ_ACP', 'WRITE_ACP']
            for permission in perms:
                if resource == 'object':
                    key = 'HTTP_X_OBJECT_ACL_' + permission
                elif resource == 'container':
                    if permission == 'WRITE':
                        key = 'HTTP_X_CONTAINER_' + permission
                    else:
                        key = 'HTTP_X_CONTAINER_ACL_' + permission
                if key not in permissions:
                    permissions[key] = []
                if username in REPLACE_USERNAMES:
                    username = REPLACE_USERNAMES[username]
                if username not in permissions[key]:
                    permissions[key].append(username)
    for key, value in permissions.iteritems():
        env[key] = ','.join(value)


def canonical_string(req):
    """
    Canonicalize a request to a token that can be signed.
    """
    amz_headers = {}

    buf = "%s\n%s\n%s\n" % (req.method, req.headers.get('Content-MD5', ''),
                            req.headers.get('Content-Type') or '')

    for amz_header in sorted((key.lower() for key in req.headers
                              if key.lower().startswith('x-amz-'))):
        amz_headers[amz_header] = req.headers[amz_header]

    if 'x-amz-date' in amz_headers:
        buf += "\n"
    elif 'Date' in req.headers:
        buf += "%s\n" % req.headers['Date']

    for k in sorted(key.lower() for key in amz_headers):
        buf += "%s:%s\n" % (k, amz_headers[k])

    # RAW_PATH_INFO is enabled in later version than eventlet 0.9.17.
    # When using older version, swift3 uses req.path of swob instead
    # of it.
    path = req.environ.get('RAW_PATH_INFO', req.path)
    if req.query_string:
        path += '?' + req.query_string

    if '?' in path:
        path, args = path.split('?', 1)
        params = []
        for key, value in urlparse.parse_qsl(args, keep_blank_values=True):
            if key in ALLOWED_SUB_RESOURCES:
                params.append('%s=%s' % (key, value) if value else key)
        if params:
            return "%s%s?%s" % (buf, path, '&'.join(params))
    return buf + path


def swift_acl_translate(acl, group='', user='', xml=False):
    """
    Takes an S3 style ACL and returns a list of header/value pairs that
    implement that ACL in Swift, or "Unsupported" if there isn't a way to do
    that yet.
    """
    swift_acl = {}
    swift_acl['public-read'] = [['HTTP_X_CONTAINER_READ', '.r:*,.rlistings']]
    # Swift does not support public write:
    # https://answers.launchpad.net/swift/+question/169541
    swift_acl['public-read-write'] = [['HTTP_X_CONTAINER_WRITE', '.r:*'],
                                      ['HTTP_X_CONTAINER_READ',
                                       '.r:*,.rlistings']]

    #TODO: if there's a way to get group and user, this should work for
    # private:
    #swift_acl['private'] = [['HTTP_X_CONTAINER_WRITE',  group + ':' + user], \
    #                  ['HTTP_X_CONTAINER_READ', group + ':' + user]]
    swift_acl['private'] = [['HTTP_X_CONTAINER_WRITE', '.'],
                            ['HTTP_X_CONTAINER_READ', '.']]
    if xml:
        # We are working with XML and need to parse it
        dom = parseString(acl)
        acl = 'unknown'
        for grant in dom.getElementsByTagName('Grant'):
            permission = grant.getElementsByTagName('Permission')[0]\
                .firstChild.data
            grantee = grant.getElementsByTagName('Grantee')[0]\
                .getAttributeNode('xsi:type').nodeValue
            if permission == "FULL_CONTROL" and grantee == 'CanonicalUser' and\
                    acl != 'public-read' and acl != 'public-read-write':
                acl = 'private'
            elif permission == "READ" and grantee == 'Group' and\
                    acl != 'public-read-write':
                acl = 'public-read'
            elif permission == "WRITE" and grantee == 'Group':
                acl = 'public-read-write'
            else:
                acl = 'unsupported'

    if acl == 'authenticated-read':
        return "Unsupported"
    elif acl not in swift_acl:
        return "InvalidArgument"

    return swift_acl[acl]


def validate_bucket_name(name):
    """
    Validates the name of the bucket against S3 criteria,
    http://docs.amazonwebservices.com/AmazonS3/latest/BucketRestrictions.html
    True if valid, False otherwise
    """

    if '_' in name or len(name) < 3 or len(name) > 63 or \
       not name[-1].isalnum():
        # Bucket names should not contain underscores (_)
        # Bucket names must end with a lowercase letter or number
        # Bucket names should be between 3 and 63 characters long
        return False
    elif '.-' in name or '-.' in name or '..' in name or not name[0].isalnum():
        # Bucket names cannot contain dashes next to periods
        # Bucket names cannot contain two adjacent periods
        # Bucket names Must start with a lowercase letter or a number
        return False
    elif re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
                  "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", name):
        # Bucket names cannot be formatted as an IP Address
        return False
    else:
        return True
