import requests
import os
from urllib.parse import quote
from urllib.parse import unquote
from urllib.parse import urlparse
from xml.etree import ElementTree
from requests_ntlm import HttpNtlmAuth # third party install
from requests.auth import HTTPBasicAuth
from getpass import getpass
import logging


logger = logging.getLogger('spLite.auth')

class UnsupportedError(Exception):
    ''' Exception used as an error when an unsupported authentication context is chosen '''
    pass

class SamlFailure(Exception):
    '''' Exception used in the case of a SAML failure '''

class AuthContext:

    def __init__(self, site, username, password=None, context='saml'):
        ''' Authentication context for the SharePoint session.'''

        self.logger = logging.getLogger('spLite.sharepoint.SpSession')
        self.site = site
        self.username = username
        self.__password = password if password else getpass()

        self.auth = None
        self.header = None

        if context == "saml":
            self.header = SamlTokenProvider(self.site, self.username, self.__password).get_cookies()
        elif context == "ntlm":
            self.auth = HttpNtlmAuth(self.username, self.__password)
        elif context == "basic":
            self.auth = HTTPBasicAuth(self.username, self.__password)
        else:
            raise UnsupportedError(f'Authentication context {context} is not currently supported')

    def get_auth(self):
        ''' Returns a dictionary to unpack into a session object. For example:
            requests.Session(**dict)'''

        return {
            'auth': self.auth,
            'headers': self.header
        }

class SamlTokenProvider:
    ''' Basically a reconstruction of the code in the repository
                https://github.com/vgrem/Office365-REST-Python-Client
        They were gracious enough to use an MIT license. 
        Their library is much more extensive and supports a lot more features, whereas
        the purpose of this library is meant to be a great simplication. Please refer
        to their library for more in depth and robust code. The specific file I'm referencing is here:
            https://github.com/vgrem/Office365-REST-Python-Client/blob/master/office365/runtime/auth/saml_token_provider.py
        
        I'm primarily rewriting this to try to limit to my needs for this library, and make flow of the
        program more intuitive to follow for a beginner or a programmer who doesn't work much
        at all with authentication. 

        This process is just using your microsoft account as a single sign-on by authenticating
        against the microsoft login page. 

        Cookie process (from a very high level):
            1. Hit the microsoft webpage and get a service token
            2. Use that token to hit a login page and authenticate there
            3. Grab the cookies out of that package
            4. Use those cookies in your request header to authenticate moving forward
    '''
    def __init__(self, site, username, password):
        
        self.logger = logging.getLogger('spLite.sharepoint.SamlTokenProvider')
        self.site = site
        self.url = urlparse(self.site)
        self.username = username
        self.__password = password

        # External Security Token Service for SPO
        self.sts = {
            'host': 'login.microsoftonline.com',
            'path': '/extSTS.srf'
        }

        # Sign in page url
        self.login = '/_forms/default.aspx?wa=wsignin1.0'
        self.FedAuth = None
        self.rtFa = None

    def get_cookies(self):
        ''' Prepare and return cookies to make authenticated requests '''
        # Step 1: Hit the microsoft webpage and get a service token
        self.token = self.acquire_service_token()
        
        # Step 2: Use that token to hit a login page and authenticate there
        s = requests.session()
        s.post(f'{self.url.scheme}://{self.url.hostname}{self.login}',
                data=self.token,
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        
        # Step 3: Grab the cookies out of the cookie jar
        cookies = requests.utils.dict_from_cookiejar(s.cookies)

        # build the authorization cookie
        auth_cookie = f"FedAuth={cookies['FedAuth']}; rtFa={cookies['rtFa']}"

        # Step 4: Feed back the cookies to use in a request
        return {'Cookie': auth_cookie}

    def acquire_service_token(self):
        ''' Prepare and submit request and get back service token'''
        # Prepare params to correct in token request body
        params = {
            'username': self.username,
            'password': self.__password,
            'endpoint': self.site 
        }

        # Build the URL to hit for the token
        sts_url = "https://" + self.sts['host'] + self.sts['path']

        # Update params in the SAML.xml file (located with this file)
        request_body = self.prepare_token_request(params)

        # Make the request
        response = requests.post(sts_url,
                        data=request_body,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'})

        # Give some feedback in the request failed
        if response.status_code != 200:
            self.logger.error('Failure while authenticating using SAML.')
            self.logger.error(f'Request response: {response.text}')
            raise SamlFailure('Failed to collect service token')

        return self.process_token_request(response)

    def process_token_request(self, response):
        ''' The content of what's returned is cumbersome so separate this out.
            Again - stealing this from vgrem's repository. 
        '''
        # If you don't know much about XML, look into XML namespaces to understand the purpose of this
        ns_prefixes = {'S': '{http://www.w3.org/2003/05/soap-envelope}',
               'psf': '{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}',
               'wst': '{http://schemas.xmlsoap.org/ws/2005/02/trust}',
               'wsse': '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}'}

        xml = ElementTree.fromstring(response.content)

        # check for errors
        if xml.find('{0}Body/{0}Fault'.format(ns_prefixes['S'])) is not None:
            error = xml.find('{0}Body/{0}Fault/{0}Detail/{1}error/{1}internalerror/{1}text'.format(ns_prefixes['S'],
                                                                                                   ns_prefixes['psf']))
            logger.error(f'An error occurred while retrieving token: {error.text}')
            raise SamlFailure('Failed to collect service token')

        # Query the XML to get out the actual token text. These are XPath expressions. 
        # https://www.w3schools.com/xml/xml_xpath.asp
        token = xml.find('{0}Body/{1}RequestSecurityTokenResponse/{1}RequestedSecurityToken/{2}BinarySecurityToken'\
            .format(ns_prefixes['S'], ns_prefixes['wst'], ns_prefixes['wsse'])).text

        return token
        
    @staticmethod
    def prepare_token_request(params):
        ''' Construct the request body to acquire security token from STS endpoint.
            Taken from:
            https://github.com/vgrem/Office365-REST-Python-Client/blob/master/office365/runtime/auth/saml_token_provider.py
        '''
        fpath = os.path.join(os.path.dirname(__file__), 'SAML.xml')

        try:
            with open(fpath, 'r') as f:
                data = f.read()
                for key in params:
                    data = data.replace('[' + key + ']', params[key])
                return data
        except Exception as e:
            logging.error(f'Could not read {fpath}:\n\t{e}')

