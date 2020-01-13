import requests
import os
from urllib.parse import quote
from urllib.parse import unquote
from urllib.parse import urlparse
from xml.etree import ElementTree
from getpass import getpass
import io
import time
from spLite import auth
import logging
import json

class FailedConnection(Exception):
    ''' Exception used to pass into the retry loop.
        Used to raise an error if the maximum retury attempts were hit'''
    pass

class SpSession:

    def __init__(self, site, username, password=None, context_type='saml', custom_context=None):
        ''' Initialization of a SharePoint session. Creates an authenticated
            session for use throughout interaction

            Default authentication context is SAML Security Token Service for Office 365
            but NTLM and Basic HTTP authentication are also supported. A custom authentication
            context may also be used, provided that it's a dictionary with 'auth' and 'headers' keys
            that will be updated in the session settings
        '''

        self.logger = logging.getLogger('spLite.sharepoint.SpSession')
        self.site = site
        self.username = username
        self.__password = password if password else getpass()
        self.context_type = context_type
        self.custom_context = custom_context
        self.digest = None

        # Create session
        self.make_session()

    def make_session(self):

        # Override default context of saml if custom is provided
        if self.custom_context:
            if not isinstance(self.custom_context, dict):
                raise ValueError('Custom context must be provided as a dictionary whose parameters' +\
                                 'will be unpacked into a requests call')
            self.context = self.custom_context
        else:
            # If not a custom context then use the spLite.AuthContext to authenticate
            self.context = auth.AuthContext(
                self.site, 
                self.username, 
                self.__password, 
                self.context_type
            ).get_auth()
        
        # Unpack authorization context for authentication
        self.session = requests.Session()
        self.session.headers.update(
            {'Content-Type': 'application/json; odata=verbose', 
             'accept': 'application/json;odata=verbose'}
        )

        # Update using context
        if self.context.get('auth', None):
            self.session.auth = self.context.get('auth')
        if self.context.get('headers', None):
            self.session.headers.update(self.context.get('headers'))

    def retry_loop(self, req, max_tries = 5,  data=None, headers=None):
        ''' Takes in a request object and will retry the request
            upon failure up the the specified number of maximum 
            retries.
            
            Used because error codes occasionally surface even though the 
            REST API call is formatted correctly. Exception returns status code 
            and text. Success returns request object. 

            Default method is get - can retry post methods as well
            
            Default max_tries = 5
        '''
         
         
        # Call fails sometimes - allow 5 retries
        counter = 0
        
        # Initialize loop
        while True:
            
            # Return request object on success
            if req.status_code == 200:
                return req

            # If limit reached then raise exception
            counter += 1
            if counter == max_tries:
                raise FailedConnection(f"Failed to connect. \nError code = {req.status_code}\nError text: {req.text}")

            # Message for failed retry
            if req.status_code == 403:
                self.logger.warning(f'Error code: {req.status_code}: Authentication failed - re-authenticating')
                self.make_session()

            else:
                self.logger.warning(f'Failed request. Error code: {req.status_code}. Trying again...')

            # Spacing out the requests in case of a connection problem
            time.sleep(1)
            
            # Repeat request
            try:
                if req.request.method == 'GET':
                    req = self.session.get(req.url)
                if req.request.method == 'POST':
                    req = self.session.post(req.url, data=data, headers=headers)
            except ConnectionError:
                self.logger.warning('Connection error - Trying again...')

    def get_file(self, folder, file, output_location=None):
        ''' Extract a file from a sharepoint folder and 
            output the contents
            Returns a tuple:
                (Return code, File - None if output location is provided)
        '''
        # Build REST call
        rest_call = f"{self.site}/_api/web/GetFolderByServerRelativeUrl('{quote(folder)}')/Files('{quote(file)}')/$value"
            
        # Make the call
        try:
            
            r = self.retry_loop(self.session.get(rest_call))
                
            # If output location was provided then 
            if r.status_code == 200:
                self.logger.info(f'Downloaded file {folder}/{file}')
                # If output location is none, then return the string as a file like object
                if not output_location:
                    return io.BytesIO(r.content)

                # Otherwise write the file out - catch write issues
                try:
                    with open(output_location + file, 'wb') as f:
                        f.write(r.content)
                    self.logger.info('Write successful.')
                    return r
                except Exception as e:
                    self.logger.error(f'Failed to write file: {e}')
                    return 
                
        # Catch connections issues
        except FailedConnection as e:
            self.logger.error(e)
            return 

    def list_and_get_files(self, folder, output_location=None, files=None, extensions=None):
        ''' Generator expression to gather the file list from SharePoint. 
            Each of the files are downloaded and output to the output folder
            If no file list or extension provided, all are downloaded. 
            Cannot specifyh both files and extension
            
            Yield the return value of GetFile
            Error raised for failed connection
        '''

        if isinstance(extensions, str):
            extensions = [extensions]
        elif extensions and not isinstance(extensions, (list, tuple, set, None)):
            raise ValueError('extensions option must be either a string, list, tuple, or set')

        if files and not isinstance(files, (list, tuple, set)):
            raise ValueError('files option must be either a list, tuple, or set')

        # Can only choose files or extension, not both
        assert not all([files, extensions]), "Files and extension cannot simultaneously be provided"

        # Build REST call
        rest_call = f"{self.site}/_api/web/GetFolderByServerRelativeUrl('{quote(folder)}')/Files"
        
        # Make the rest call
        try:
            r = self.retry_loop(self.session.get(rest_call))
        except FailedConnection as e:
            self.logger.error(e)
            return
        
        # Gather the file list
        file_list = [file['Name'] for file in r.json()['d']['results']]

        # If a list of files was provided then filter it. 
        if files:
            file_list = list(set(file_list) & set(files))
 
        # If extensions were provided then filter it
        if extensions:
            # Create a new container for the filtered list
            filtered_list = []

            # For each extension, append the files
            for ext in extensions:

                # Pick off files with the specified extension and append
                filtered_list += [x for x in file_list if x[-len(ext):] == ext]
            
            # Reset the file list
            file_list = filtered_list
        
        # Yield the result to capture in result tuple
        self.logger.info(f'File list to download: {file_list}')
        yield file_list
        
        # Iterate the returned list and write the files
        for file in file_list:
            self.logger.warning(file)
            yield self.get_file(folder,file, output_location=output_location)

    def upload_file(self, file, folder, overwrite=True):
        ''' Upload a file to a specified sharepoint folder. 
            Default behaivor is to overwrite, but overwrite protection can
            be turned off by switching overwrite to false
        '''

        # Check if overwrite is boolean or string
        if not isinstance(overwrite, (bool, str)):
            raise ValueError('overwrite must be instance of bool')

        # Check if the file to post exists, raise error if it doesn't
        if os.path.exists(file):
            filepath, filename = os.path.split(file)
            with open(file, 'rb') as f:
                data = f.read()
        else:
            raise FileNotFoundError(f'File {filepath} does not exist')

        # build the rest call
        rest_call = f"{self.site}/_api/web/GetFolderByServerRelativeUrl('{quote(folder)}')" +\
                    f"/Files/add(url='{quote(filename)}', overwrite={str(overwrite).lower()})"

        # Send a post request to the API contextinfo to get the digest back
        if not self.digest:
            r = self.session.post(self.site + "/_api/contextinfo", data="")

            # Extract the digest value from the return content
            self.digest = r.json()['d']['GetContextWebInformation']['FormDigestValue']

        # Update the header with the digest
        opts = {'data': data, 'headers': {'x-requestdigest' :self.digest}}

        r = self.retry_loop(self.session.post(rest_call, **opts), **opts)

        return r

