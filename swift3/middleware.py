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

"""
The swift3 middleware will emulate the S3 REST api on top of swift.

The following opperations are currently supported:

    * GET Service
    * DELETE Bucket
    * GET Bucket (List Objects)
    * PUT Bucket
    * DELETE Object
    * GET Object
    * HEAD Object
    * PUT Object
    * PUT Object (Copy)

To add this middleware to your configuration, add the swift3 middleware
in front of the auth middleware, and before any other middleware that
look at swift requests (like rate limiting).

To set up your client, the access key will be the concatenation of the
account and user strings that should look like test:tester, and the
secret access key is the account password.  The host should also point
to the swift storage hostname.  It also will have to use the old style
calling format, and not the hostname based container format.

An example client using the python boto library might look like the
following for an SAIO setup::

    from boto.s3.connection import S3Connection
    connection = S3Connection(
        aws_access_key_id='test:tester',
        aws_secret_access_key='testing',
        port=8080,
        host='127.0.0.1',
        is_secure=False,
        calling_format=boto.s3.connection.OrdinaryCallingFormat())
"""

from urllib import unquote, quote
import base64
from xml.sax.saxutils import escape as xml_escape
import urlparse

from simplejson import loads
import email.utils
import datetime

from swift.common.utils import split_path
from swift.common.utils import get_logger
from swift.common.wsgi import WSGIContext
from swift.common.swob import Request, Response
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, HTTP_NOT_FOUND, \
    HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, is_success
from swift.obj import server as obj_server
from swift.container import server as container_server

from utils import get_err_response, MAX_BUCKET_LISTING, get_s3_acl, \
    acp_to_headers, swift_acl_translate, canonical_string


class ServiceController(WSGIContext):
    """
    Handles account level requests.
    """
    def __init__(self, env, app, account_name, token, **kwargs):
        WSGIContext.__init__(self, app)
        env['HTTP_X_AUTH_TOKEN'] = token
        env['PATH_INFO'] = '/v1/%s' % account_name

    def GET(self, env, start_response):
        """
        Handle GET Service request
        """
        env['QUERY_STRING'] = 'format=json'
        body_iter = self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_OK:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            else:
                return get_err_response('InvalidURI')

        containers = loads(''.join(list(body_iter)))
        # we don't keep the creation time of a backet (s3cmd doesn't
        # work without that) so we use something bogus.
        if containers:
            owner = containers[0].get('owner', '')
        else:
            owner = ''
        body = '<?xml version="1.0" encoding="UTF-8"?>' \
               '<ListAllMyBucketsResult ' \
               'xmlns="http://doc.s3.amazonaws.com/2006-03-01">'\
               '<Owner><ID>%s</ID><DisplayName>%s</DisplayName></Owner>'\
               '<Buckets>%s</Buckets>' \
               '</ListAllMyBucketsResult>' \
               % (xml_escape(owner), xml_escape(owner),
                  "".join(['<Bucket><Name>%s</Name><CreationDate>'
                           '2009-02-03T16:45:09.000Z</CreationDate></Bucket>'
                           % xml_escape(i['name']) for i in containers]))
        resp = Response(status=HTTP_OK, content_type='application/xml',
                        body=body)
        return resp


class BucketController(WSGIContext):
    """
    Handles bucket request.
    """
    def __init__(self, env, app, account_name, token, container_name,
                 **kwargs):
        WSGIContext.__init__(self, app)
        self.container_name = unquote(container_name)
        self.account_name = unquote(account_name)
        env['HTTP_X_AUTH_TOKEN'] = token
        env['PATH_INFO'] = '/v1/%s/%s' % (account_name, container_name)
        conf = kwargs.get('conf', {})
        self.location = conf.get('location', 'US')

    def GET(self, env, start_response):
        """
        Handle GET Bucket (List Objects) request
        """
        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
        else:
            args = {}

        if 'max-keys' in args:
            if args.get('max-keys').isdigit() is False:
                return get_err_response('InvalidArgument')

        max_keys = min(int(args.get('max-keys', MAX_BUCKET_LISTING)),
                       MAX_BUCKET_LISTING)

        if 'acl' not in args:
            # acl request sent with format=json etc confuses swift
            env['QUERY_STRING'] = 'format=json&limit=%s' % (max_keys + 1)
        else:
            env['REQUEST_METHOD'] = 'HEAD'
        if 'versions' in args:
            env['QUERY_STRING'] += '&versions'
        if 'marker' in args:
            env['QUERY_STRING'] += '&marker=%s' % quote(args['marker'])
        if 'prefix' in args:
            env['QUERY_STRING'] += '&prefix=%s' % quote(args['prefix'])
        if 'delimiter' in args:
            env['QUERY_STRING'] += '&delimiter=%s' % quote(args['delimiter'])

        body_iter = self._app_call(env)
        status = self._get_status_int()
        headers = dict(self._response_headers)

        if 'acl' in args:
            return get_s3_acl(headers, container_server.ACL_HEADERS,
                              'container')

        if status != HTTP_OK:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            else:
                return get_err_response('InvalidURI')

        if 'location' in args:
            body = ('<?xml version="1.0" encoding="UTF-8"?>'
                    '<LocationConstraint '
                    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"')
            if self.location == 'US':
                body += '/>'
            else:
                body += ('>%s</LocationConstraint>' % self.location)
            return Response(body=body, content_type='application/xml')

        if 'versioning' in args:
            vers = self._response_header_value('x-container-versioning') or ''
            body = (
                '<VersioningConfiguration '
                        'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                '<Status>%s</Status></VersioningConfiguration>' %
                vers.capitalize())
            return Response(body=body, content_type='application/xml')

        if 'logging' in args:
            # logging disabled
            body = ('<?xml version="1.0" encoding="UTF-8"?>'
                    '<BucketLoggingStatus '
                    'xmlns="http://doc.s3.amazonaws.com/2006-03-01" />')
            return Response(body=body, content_type='application/xml')

        objects = loads(''.join(list(body_iter)))
        if 'versions' in args:
            obj_list = []
            for obj in objects:
                if 'subdir' not in obj:
                    if obj['deleted']:
                        name = xml_escape(unquote(obj['name'].encode('utf-8')))
                        obj_list.append(
                            '<DeleteMarker>'
                                '<Key>%s</Key>'
                                '<VersionId>%s</VersionId>'
                                '<IsLatest>%s</IsLatest>'
                                '<LastModified>%s</LastModified>'
                            '</DeleteMarker>' % (
                                name, obj['version_id'],
                                'true' if obj['is_latest'] else 'false',
                                obj['last_modified']
                        ))
                    else:
                        name = xml_escape(unquote(obj['name'].encode('utf-8')))
                        obj_list.append(
                            '<Version>'
                                '<Key>%s</Key>'
                                '<VersionId>%s</VersionId>'
                                '<IsLatest>%s</IsLatest>'
                                '<LastModified>%s</LastModified>'
                                '<ETag>&quot;%s&quot;</ETag>'
                                '<Size>%s</Size>'
                                '<StorageClass>STANDARD</StorageClass>'
                                '<Owner>'
                                    '<ID>%s</ID>'
                                    '<DisplayName>%s</DisplayName>'
                                '</Owner>'
                            '</Version>' % (
                                name, obj['version_id'],
                                'true' if obj['is_latest'] else 'false',
                                obj['last_modified'], obj['hash'],
                                obj['bytes'], obj['owner'], obj['owner']
                        ))
            body = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<ListVersionsResult '
                        'xmlns="http://s3.amazonaws.com/doc/2006-03-01">'
                    '<Prefix>%s</Prefix>'
                    '<KeyMarker>%s</KeyMarker>'
                    '<VersionIdMarker>%s</VersionIdMarker>'
                    '<Delimiter>%s</Delimiter>'
                    '<IsTruncated>%s</IsTruncated>'
                    '<MaxKeys>%s</MaxKeys>'
                    '<Name>%s</Name>'
                    '%s'
                    '%s'
                '</ListVersionsResult>' % (
                xml_escape(args.get('prefix', '')),
                xml_escape(args.get('key-marker', '')),
                xml_escape(args.get('version-id-marker', '')),
                xml_escape(args.get('delimiter', '')),
                'true' if len(objects) == (max_keys + 1) else 'false',
                max_keys,
                xml_escape(self.container_name),
                "".join(obj_list),
                "".join(['<CommonPrefixes><Prefix>%s</Prefix></CommonPrefixes>'
                         % xml_escape(i['subdir'])
                         for i in objects[:max_keys] if 'subdir' in i])))
        else:
            obj_list = []
            prefixes = []
            for i in objects:
                if 'subdir' in i:
                    name = xml_escape(unquote(i['subdir'].encode('utf-8')))
                    prefixes.append('<CommonPrefixes>'
                                    '<Prefix>%s</Prefix>'
                                    '</CommonPrefixes>' % name)
                else:
                    name = xml_escape(unquote(i['name'].encode('utf-8')))
                    owner = i.get('owner', self.account_name)
                    obj_list.append(
                        '<Contents>'
                            '<Key>%s</Key>'
                            '<LastModified>%sZ</LastModified>'
                            '<ETag>%s</ETag>'
                            '<Size>%s</Size>'
                            '<StorageClass>STANDARD</StorageClass>'
                            '<Owner>'
                                '<ID>%s</ID>'
                                '<DisplayName>%s</DisplayName>'
                            '</Owner>'
                        '</Contents>' %
                        (name, i['last_modified'], i['hash'], i['bytes'],
                         owner, owner))
            body = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<ListBucketResult '
                    'xmlns="http://s3.amazonaws.com/doc/2006-03-01">'
                    '<Prefix>%s</Prefix>'
                    '<Marker>%s</Marker>'
                    '<Delimiter>%s</Delimiter>'
                    '<IsTruncated>%s</IsTruncated>'
                    '<MaxKeys>%s</MaxKeys>'
                    '<Name>%s</Name>'
                    '%s'
                    '%s'
                '</ListBucketResult>' % (
                xml_escape(args.get('prefix', '')),
                xml_escape(args.get('marker', '')),
                xml_escape(args.get('delimiter', '')),
                'true' if max_keys > 0 and
                          len(objects) == (max_keys + 1) else 'false',
                max_keys,
                xml_escape(self.container_name),
                ''.join(obj_list),
                ''.join(prefixes)))
        return Response(body=body, content_type='application/xml')

    def PUT(self, env, start_response):
        """
        Handle PUT Bucket request
        """
        if 'CONTENT_LENGTH' in env:
            try:
                content_length = int(env['CONTENT_LENGTH'])
            except (ValueError, TypeError):
                return get_err_response('InvalidArgument')
            if content_length < 0:
                return get_err_response('InvalidArgument')

        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
        else:
            args = {}

        acl = 'acl' in args
        if acl:
            res = acp_to_headers(env, 'container')
            if res:
                return res
            env['REQUEST_METHOD'] = 'POST'

        versioning = 'versioning' in args
        if versioning:
            if 'wsgi.input' not in env:
                return get_err_response(
                    'IllegalVersioningConfigurationException')
            versioning_conf = env['wsgi.input'].read()
            if 'Enabled' in versioning_conf:
                env['HTTP_X_CONTAINER_VERSIONING'] = 'enabled'
            elif 'Suspended' in versioning_conf:
                env['HTTP_X_CONTAINER_VERSIONING'] = 'suspended'
            else:
                return get_err_response(
                    'IllegalVersioningConfigurationException')
            env['REQUEST_METHOD'] = 'POST'

        if not acl and not versioning:
            # Translate the Amazon ACL to something that can be
            # implemented in Swift, 501 otherwise. Swift uses POST
            # for ACLs, whereas S3 uses PUT.
            if 'HTTP_X_AMZ_ACL' in env:
                amz_acl = env['HTTP_X_AMZ_ACL']
                del env['HTTP_X_AMZ_ACL']
                translated_acl = swift_acl_translate(amz_acl)
                if translated_acl == 'Unsupported':
                    return get_err_response('Unsupported')
                elif translated_acl == 'InvalidArgument':
                    return get_err_response('InvalidArgument')
                for header, acl in translated_acl:
                    env[header] = acl

        body_iter = self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_CREATED and status != HTTP_NO_CONTENT:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_ACCEPTED:
                return get_err_response('BucketAlreadyExists')
            else:
                return get_err_response('InvalidURI')

        resp = Response()
        if not versioning:
            resp.headers['Location'] = self.container_name
        resp.status = HTTP_OK
        return resp

    def DELETE(self, env, start_response):
        """
        Handle DELETE Bucket request
        """
        body_iter = self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_NO_CONTENT:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            elif status == HTTP_CONFLICT:
                return get_err_response('BucketNotEmpty')
            else:
                return get_err_response('InvalidURI')

        resp = Response()
        resp.status = HTTP_NO_CONTENT
        return resp

    def POST(self, env, start_response):
        """
        Handle POST Bucket request
        """

        return get_err_response('Unsupported')


class ObjectController(WSGIContext):
    """
    Handles requests on objects
    """
    def __init__(self, env, app, account_name, token, container_name,
                 object_name, **kwargs):
        WSGIContext.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        env['HTTP_X_AUTH_TOKEN'] = token
        env['PATH_INFO'] = '/v1/%s/%s/%s' % (account_name, container_name,
                                             object_name)

    def GETorHEAD(self, env, start_response):
        if env['REQUEST_METHOD'] == 'HEAD':
            head = True
            env['REQUEST_METHOD'] = 'GET'
        else:
            head = False
        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
        else:
            args = {}

        env['QUERY_STRING'] = ''
        if 'acl' in args:
            env['QUERY_STRING'] += 'acl'
            env['REQUEST_METHOD'] = 'HEAD'
        if 'versionId' in args:
            env['QUERY_STRING'] += 'versionId=%s' % args['versionId']

        app_iter = self._app_call(env)

        if head:
            app_iter = None

        status = self._get_status_int()
        headers = dict(self._response_headers)

        if is_success(status):
            if 'QUERY_STRING' in env:
                args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
            else:
                args = {}
            if 'acl' in args:
                resp = get_s3_acl(headers, obj_server.ACL_HEADERS, 'object')
                return resp

            new_hdrs = {}
            for key, val in headers.iteritems():
                _key = key.lower()
                if _key.startswith('x-object-meta-'):
                    new_hdrs['x-amz-meta-' + key[14:]] = val
                elif _key in ('content-length', 'content-type',
                              'content-range', 'content-encoding',
                              'etag', 'last-modified'):
                    new_hdrs[key] = val
            return Response(status=status, headers=new_hdrs, app_iter=app_iter)
        elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
            return get_err_response('AccessDenied')
        elif status == HTTP_NOT_FOUND:
            return get_err_response('NoSuchKey')
        else:
            return get_err_response('InvalidURI')

    def HEAD(self, env, start_response):
        """
        Handle HEAD Object request
        """
        return self.GETorHEAD(env, start_response)

    def GET(self, env, start_response):
        """
        Handle GET Object request
        """
        return self.GETorHEAD(env, start_response)

    def PUT(self, env, start_response):
        """
        Handle PUT Object and PUT Object (Copy) request
        """
        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], True))
        else:
            args = {}

        acl = 'acl' in args
        if acl:
            res = acp_to_headers(env, 'object')
            if res:
                return res
            env['QUERY_STRING'] = 'acl'
            env['REQUEST_METHOD'] = 'POST'
        else:
            for key, value in env.items():
                if key.startswith('HTTP_X_AMZ_META_'):
                    del env[key]
                    env['HTTP_X_OBJECT_META_' + key[16:]] = value
                elif key == 'HTTP_CONTENT_MD5':
                    if value == '':
                        return get_err_response('InvalidDigest')
                    try:
                        env['HTTP_ETAG'] = value.decode('base64').encode('hex')
                    except:
                        return get_err_response('InvalidDigest')
                    if env['HTTP_ETAG'] == '':
                        return get_err_response('SignatureDoesNotMatch')
                elif key == 'HTTP_X_AMZ_COPY_SOURCE':
                    env['HTTP_X_COPY_FROM'] = value

        body_iter = self._app_call(env)
        status = self._get_status_int()

        success_status = HTTP_ACCEPTED if acl else HTTP_CREATED

        if status != success_status:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchBucket')
            elif status == HTTP_UNPROCESSABLE_ENTITY:
                return get_err_response('InvalidDigest')
            else:
                return get_err_response('InvalidURI')

        if not acl and 'HTTP_X_COPY_FROM' in env:
            body = '<CopyObjectResult>' \
                   '<ETag>"%s"</ETag>' \
                   '</CopyObjectResult>' % self._response_header_value('etag')
            return Response(status=HTTP_OK, body=body)

        kwargs = {'status': HTTP_OK}
        if not acl:
            kwargs['etag'] = self._response_header_value('etag')

        return Response(**kwargs)

    def DELETE(self, env, start_response):
        """
        Handle DELETE Object request
        """
        body_iter = self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_NO_CONTENT:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return get_err_response('NoSuchKey')
            else:
                return get_err_response('InvalidURI')

        resp = Response()
        resp.status = HTTP_NO_CONTENT
        return resp


class Swift3Middleware(object):
    """Swift3 S3 compatibility midleware"""
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='swift3')
        self.location = conf.get('location', 'US').upper()

    def get_controller(self, path):
        container, obj = split_path(path, 0, 2, True)
        d = dict(container_name=container, object_name=obj)

        if container and obj:
            return ObjectController, d
        elif container:
            return BucketController, d
        return ServiceController, d

    def __call__(self, env, start_response):
        try:
            return self.handle_request(env, start_response)
        except Exception, e:
            self.logger.exception(e)

    def handle_request(self, env, start_response):
        req = Request(env)
        self.logger.debug('Calling Swift3 Middleware')
        self.logger.debug(req.__dict__)

        if 'AWSAccessKeyId' in req.params:
            try:
                req.headers['Date'] = req.params['Expires']
                req.headers['Authorization'] = \
                    'AWS %(AWSAccessKeyId)s:%(Signature)s' % req.params
            except KeyError:
                return get_err_response('InvalidArgument')(env, start_response)

        if 'Authorization' not in req.headers:
            return self.app(env, start_response)

        try:
            keyword, info = req.headers['Authorization'].split(' ')
        except:
            return get_err_response('AccessDenied')(env, start_response)

        if keyword != 'AWS':
            return get_err_response('AccessDenied')(env, start_response)

        try:
            account, signature = info.rsplit(':', 1)
        except:
            return get_err_response('InvalidArgument')(env, start_response)

        try:
            controller, path_parts = self.get_controller(env['PATH_INFO'])
        except ValueError:
            return get_err_response('InvalidURI')(env, start_response)

        if 'Date' in req.headers:
            date = email.utils.parsedate(req.headers['Date'])
            if date is None:
                return get_err_response('AccessDenied')(env, start_response)

            d1 = datetime.datetime(*date[0:6])
            d2 = datetime.datetime.utcnow()
            epoch = datetime.datetime(1970, 1, 1, 0, 0, 0, 0)

            if d1 < epoch:
                return get_err_response('AccessDenied')(env, start_response)

            delta = datetime.timedelta(seconds=60 * 10)
            if d1 - d2 > delta or d2 - d1 > delta:
                return get_err_response('RequestTimeTooSkewed')(env,
                                                                start_response)

        token = base64.urlsafe_b64encode(canonical_string(req))

        controller = controller(env, self.app, account, token, conf=self.conf,
                                **path_parts)

        if hasattr(controller, req.method):
            res = getattr(controller, req.method)(env, start_response)
        else:
            return get_err_response('InvalidURI')(env, start_response)

        return res(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def swift3_filter(app):
        return Swift3Middleware(app, conf)

    return swift3_filter
