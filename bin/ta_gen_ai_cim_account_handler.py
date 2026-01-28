#!/usr/bin/env python
# encoding=utf-8
"""
ta_gen_ai_cim_account_handler.py
REST handler for ServiceNow account management
"""

import os
import sys
import json

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

import splunk.admin as admin
import splunk.entity as entity


class ServiceNowAccountHandler(admin.MConfigHandler):
    """REST handler for ServiceNow account configuration"""
    
    def setup(self):
        """Define supported arguments"""
        if self.requestedAction == admin.ACTION_CREATE:
            # Required fields for create
            self.supportedArgs.addReqArg('url')
            self.supportedArgs.addReqArg('auth_type')
            
        if self.requestedAction in [admin.ACTION_CREATE, admin.ACTION_EDIT]:
            # Optional fields
            self.supportedArgs.addOptArg('url')
            self.supportedArgs.addOptArg('auth_type')
            self.supportedArgs.addOptArg('username')
            self.supportedArgs.addOptArg('password')
            self.supportedArgs.addOptArg('client_id')
            self.supportedArgs.addOptArg('client_secret')
            self.supportedArgs.addOptArg('redirect_url')
            self.supportedArgs.addOptArg('access_token')
            self.supportedArgs.addOptArg('refresh_token')
    
    def handleList(self, confInfo):
        """List all configured accounts"""
        conf_name = 'ta_gen_ai_cim_account'
        
        try:
            entities = entity.getEntities(
                ['admin', 'conf-' + conf_name],
                sessionKey=self.getSessionKey(),
                owner='nobody',
                namespace='TA-gen_ai_cim',
                count=-1
            )
            
            for name, ent in entities.items():
                if name.startswith('_'):
                    continue
                    
                confInfo[name].append('url', ent.get('url', ''))
                confInfo[name].append('auth_type', ent.get('auth_type', 'basic'))
                confInfo[name].append('username', ent.get('username', ''))
                confInfo[name].append('client_id', ent.get('client_id', ''))
                # Don't return sensitive fields
                confInfo[name].append('password', '********' if ent.get('password') else '')
                confInfo[name].append('client_secret', '********' if ent.get('client_secret') else '')
                
        except Exception as e:
            raise admin.InternalException('Error listing accounts: %s' % str(e))
    
    def handleCreate(self, confInfo):
        """Create a new account"""
        name = self.callerArgs.id
        args = self.callerArgs.data
        
        # Validate required fields
        url = args.get('url', [None])[0]
        auth_type = args.get('auth_type', ['basic'])[0]
        
        if not url:
            raise admin.ArgValidationException('URL is required')
        
        # Create the conf entry
        try:
            new_entity = entity.Entity(
                ['admin', 'conf-ta_gen_ai_cim_account'],
                name,
                namespace='TA-gen_ai_cim',
                owner='nobody'
            )
            
            new_entity['url'] = url
            new_entity['auth_type'] = auth_type
            
            # Handle credentials based on auth type
            if auth_type == 'basic':
                username = args.get('username', [None])[0]
                password = args.get('password', [None])[0]
                
                if username:
                    new_entity['username'] = username
                if password:
                    # Store password in storage/passwords
                    self._store_password(name, 'password', password)
                    
            elif auth_type in ['oauth_auth_code', 'oauth_client_creds']:
                client_id = args.get('client_id', [None])[0]
                client_secret = args.get('client_secret', [None])[0]
                username = args.get('username', [None])[0]
                password = args.get('password', [None])[0]
                
                if client_id:
                    new_entity['client_id'] = client_id
                if client_secret:
                    self._store_password(name, 'client_secret', client_secret)
                if username:
                    new_entity['username'] = username
                if password:
                    self._store_password(name, 'password', password)
            
            entity.setEntity(new_entity, sessionKey=self.getSessionKey())
            
            # Return the created entry
            confInfo[name].append('url', url)
            confInfo[name].append('auth_type', auth_type)
            
        except Exception as e:
            raise admin.InternalException('Error creating account: %s' % str(e))
    
    def handleEdit(self, confInfo):
        """Edit an existing account"""
        name = self.callerArgs.id
        args = self.callerArgs.data
        
        try:
            # Get existing entity
            existing = entity.getEntity(
                ['admin', 'conf-ta_gen_ai_cim_account'],
                name,
                sessionKey=self.getSessionKey(),
                owner='nobody',
                namespace='TA-gen_ai_cim'
            )
            
            # Update fields
            for field in ['url', 'auth_type', 'username', 'client_id']:
                value = args.get(field, [None])[0]
                if value is not None:
                    existing[field] = value
            
            # Handle password updates
            password = args.get('password', [None])[0]
            if password and password != '********':
                self._store_password(name, 'password', password)
            
            client_secret = args.get('client_secret', [None])[0]
            if client_secret and client_secret != '********':
                self._store_password(name, 'client_secret', client_secret)
            
            entity.setEntity(existing, sessionKey=self.getSessionKey())
            
        except Exception as e:
            raise admin.InternalException('Error updating account: %s' % str(e))
    
    def handleRemove(self, confInfo):
        """Remove an account"""
        name = self.callerArgs.id
        
        try:
            entity.deleteEntity(
                ['admin', 'conf-ta_gen_ai_cim_account'],
                name,
                sessionKey=self.getSessionKey(),
                owner='nobody',
                namespace='TA-gen_ai_cim'
            )
            
            # Also remove stored passwords
            self._remove_password(name, 'password')
            self._remove_password(name, 'client_secret')
            
        except Exception as e:
            raise admin.InternalException('Error removing account: %s' % str(e))
    
    def _store_password(self, account_name, field_name, password):
        """Store a password in Splunk's secure storage"""
        try:
            realm = 'ta_gen_ai_cim_account__' + account_name
            
            # Try to delete existing first
            try:
                entity.deleteEntity(
                    ['storage', 'passwords'],
                    '%s:%s:' % (realm, field_name),
                    sessionKey=self.getSessionKey(),
                    owner='nobody',
                    namespace='TA-gen_ai_cim'
                )
            except Exception:
                pass
            
            # Create new password entry
            new_pw = entity.Entity(
                ['storage', 'passwords'],
                '_new',
                namespace='TA-gen_ai_cim',
                owner='nobody'
            )
            new_pw['name'] = field_name
            new_pw['password'] = password
            new_pw['realm'] = realm
            
            entity.setEntity(new_pw, sessionKey=self.getSessionKey())
            
        except Exception as e:
            raise admin.InternalException('Error storing password: %s' % str(e))
    
    def _remove_password(self, account_name, field_name):
        """Remove a password from Splunk's secure storage"""
        try:
            realm = 'ta_gen_ai_cim_account__' + account_name
            entity.deleteEntity(
                ['storage', 'passwords'],
                '%s:%s:' % (realm, field_name),
                sessionKey=self.getSessionKey(),
                owner='nobody',
                namespace='TA-gen_ai_cim'
            )
        except Exception:
            pass  # Ignore errors if password doesn't exist


admin.init(ServiceNowAccountHandler, admin.CONTEXT_APP_ONLY)
