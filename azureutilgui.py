from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from flask_oauthlib.client import OAuth, OAuthException, log
from flask_sslify import SSLify
import sys
from pprint import pprint
import base64
import traceback
import jwt
import json
# from flask_sslify import SSLify

import uuid

app = Flask(__name__)
#sslify = SSLify(app)
app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)

from logging import basicConfig, getLogger, DEBUG
logger = getLogger(__name__)
basicConfig(level=DEBUG)

import configparser
config = configparser.SafeConfigParser()
config.read('config')


# Put your consumer key and consumer secret into a config file
# and don't check it into github!!
#---- for v2 endpoint(not supported now)
#---- setting by https://identity.microsoft.com/
# microsoft = oauth.remote_app(
# 	'microsoft',
# 	consumer_key='cf7bde76-f454-4c32-9d79-25f3524b3d38',
# 	consumer_secret='2ooeBs1NzeucxavPrA2hUHz',
# 	request_token_params={'scope': 'open_id profile'},
# 	base_url='https://graph.microsoft.com/beta/',
# 	request_token_url=None,
# 	access_token_method='POST',
# 	access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
# 	authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
# )
#-----------

#---- for v1 endpoint(not supported now)
microsoft = oauth.remote_app(
	'microsoft',
	consumer_key='5ca7d032-9ad5-46e1-9398-65242d4488c5',
        consumer_secret=config.get('setting', 'CONSUMER_SECRET'),
        base_url='https://management.azure.com/',
	request_token_url=None,
	access_token_method='POST',
	access_token_url='https://login.microsoftonline.com/common/oauth2/token',
	authorize_url='https://login.microsoftonline.com/common/oauth2/authorize?resource=https://management.azure.com/'
)


@app.route('/')
def index():
	return render_template('hello.html')

@app.route('/login', methods = ['POST', 'GET'])
def login():

	if 'microsoft_token' in session:
		return redirect(url_for('subscriptions'))

	# Generate the guid to only accept initiated logins
	guid = uuid.uuid4()
	session['state'] = guid

	return microsoft.authorize(callback=url_for('authorized', _external=True), state=guid)
	
@app.route('/logout', methods = ['POST', 'GET'])
def logout():
        session_clear()

        logger.debug(config.get('setting', 'SITE_URL'))
#        return redirect('https://login.microsoftonline.com/common/oauth2/logout')
        return redirect('https://login.microsoftonline.com/common/oauth2/logout?post_logout_redirect_uri=' + str(config.get('setting', 'SITE_URL')))

@app.route('/login/authorized')
def authorized():
        response = microsoft.authorized_response()
        
        if response is None:
                return "Access Denied: Reason=%s\nError=%s" % (
                        response.get('error'),
                        request.get('error_description')
                )

	# Check response for state
        logger.debug("Response: " + str(response))
        if str(session['state']) != str(request.args['state']):
                raise Exception('State has been messed with, end authentication')

	# Okay to store this in a local variable, encrypt if it's going to client
        # machine or database. Treat as a password. 
        session['microsoft_token'] = (response['access_token'], '')
        access_token = session['microsoft_token'][0]
        session['decoded_access_token'] = jwt.decode(access_token, verify=False)

        # ToDo : サブスクリプションがない場合の例外処理
        try:
                subscription_list = (microsoft.get('subscriptions?api-version=2014-04-01').data)['value']
        except:
                pass
        else:
                session['subscription_list'] = subscription_list
                session['selected_subscription'] = subscription_list[0]

        logger.debug(session)
        logger.debug(access_token)
        logger.debug(session['decoded_access_token'])

        return redirect(url_for('subscriptions', subscription_id=session['selected_subscription']['subscriptionId']))

@app.route('/subscriptions/')
@app.route('/subscriptions/<uuid:subscription_id>')
def subscriptions(subscription_id=None):
        try:
                #me = microsoft.get('subscriptions?api-version=2014-04-01')
                # サブスクリプションIDがパラメーターにない時はセッションから取得する
                if subscription_id == None:
                        return redirect(url_for('subscriptions', subscription_id=session['selected_subscription']['subscriptionId']))

                # パラメーターのサブスクリプションIDを、セッションに保存
                session['selected_subscription'] = [s for s in session['subscription_list'] if s['subscriptionId'] == str(subscription_id)][0]

                logger.debug("================")
                logger.debug(session['selected_subscription'])
                logger.debug(subscription_id)
                logger.debug("================")

                vm_list = microsoft.get('subscriptions/{}/providers/Microsoft.Compute/virtualMachines?api-version=2017-03-30'.format(subscription_id)).data
                #logger.debug(vm_list)
                vm_num = len(vm_list['value'])

#                vmnum = microsoft.get()
#                from urllib2 import Request, urlopen, URLError

#                headers = {'Authorization': 'OAuth '+access_token}
#                req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
#                                        None, headers)
#                res = urlopen(req)
#                me = res.read()
                                                    
        except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
                logger.debug(''.join('!! ' + line for line in lines) )
                session_clear()
                return redirect(url_for('index')) 
        else:
                logger.debug(session['decoded_access_token'])
                logger.debug(vm_list)
                #logger.debug(microsoft.get('subscriptions?api-version=2014-04-01').data)
                logger.debug(session['subscription_list'])
                return render_template('dashboard.html', vm_num=vm_num)

#@app.route('/subscriptions/')
@app.route('/subscriptions/<uuid:subscription_id>/resourcegroup')
def resourcegroup(subscription_id=None):
        return render_template('resourcegroup.html')


# If library is having trouble with refresh, uncomment below and implement refresh handler
# see https://github.com/lepture/flask-oauthlib/issues/160 for instructions on how to do this

# Implements refresh token logic
# @app.route('/refresh', methods=['POST'])
# def refresh():
@microsoft.tokengetter
def get_microsoft_oauth_token():
	return session.get('microsoft_token')

def session_clear():
        session.pop('microsoft_token', None)
        session.pop('state', None)
        session.pop('decoded_access_token', None)


if __name__ == '__main__':
	app.run(port=80, host='0.0.0.0')
