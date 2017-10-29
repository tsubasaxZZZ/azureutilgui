import sys
import traceback
import uuid
import jwt
from flask import Flask, redirect, url_for, session, request, render_template
from flask_oauthlib.client import OAuth, OAuthException, log
from applicationinsights.requests import WSGIApplication
from applicationinsights import TelemetryClient

# from flask_sslify import SSLify


import configparser
CONFIG = configparser.SafeConfigParser()
CONFIG.read('config')

app = Flask(__name__)
#sslify = SSLify(app)
app.wsgi_app = WSGIApplication(CONFIG.get('setting', 'APPLICATION_INSIGHTS_KEY'), app.wsgi_app)
app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)

tc = TelemetryClient(CONFIG.get('setting', 'APPLICATION_INSIGHTS_KEY'))


from logging import basicConfig, getLogger
logger = getLogger(__name__)
debug_level = CONFIG.get('setting', 'LOGLEVEL')
basicConfig(level=debug_level,
            format='* %(asctime)s:%(levelname)s:%(name)s:%(lineno)s:%(message)s')


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
    consumer_secret=CONFIG.get('setting', 'CONSUMER_SECRET'),
    base_url='https://management.azure.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://login.microsoftonline.com/common/oauth2/token',
    authorize_url='https://login.microsoftonline.com/common/oauth2/authorize?resource=https://management.azure.com/'
)


@app.route('/')
def index():
    return render_template('hello.html')


@app.route('/login', methods=['POST', 'GET'])
def login():

    if 'microsoft_token' in session:
        logger.info("Already loggined.")
        return redirect(url_for('subscriptions'))

        # Generate the guid to only accept initiated logins
    guid = uuid.uuid4()
    session['state'] = guid

    logger.info("Redirect to authorized")
    return microsoft.authorize(callback=url_for('authorized', _external=True), state=guid)


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session_clear()

#    return redirect('https://login.microsoftonline.com/common/oauth2/logout')
    logger.info("Logout")
    return redirect('https://login.microsoftonline.com/common/oauth2/logout?post_logout_redirect_uri=' + str(CONFIG.get('setting', 'SITE_URL')))


@app.route('/login/authorized')
def authorized():
    response = microsoft.authorized_response()

    if response is None:
        tc.track_exception()
        tc.flush()
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
        subscription_list = (microsoft.get(
            'subscriptions?api-version=2014-04-01').data)['value']
    except:
        pass
    else:
        session['subscription_list'] = subscription_list
        session['selected_subscription'] = subscription_list[0]

    tc.context.user.id = session['decoded_access_token']['unique_name']

    logger.debug(session)
    logger.debug(access_token)
    logger.debug(session['decoded_access_token'])
    logger.info("Authorized successful")
    return redirect(url_for('subscriptions', subscription_id=session['selected_subscription']['subscriptionId']))


@app.route('/subscriptions/')
@app.route('/subscriptions/<uuid:subscription_id>')
def subscriptions(subscription_id=None):
    logger.info("Start subscriptions")

    try:
        #me = microsoft.get('subscriptions?api-version=2014-04-01')
        # サブスクリプションIDがパラメーターにない時はセッションから取得する
        if subscription_id is None:
            return redirect(url_for('subscriptions', subscription_id=session['selected_subscription']['subscriptionId']))

        # パラメーターのサブスクリプションIDを、セッションに保存
        session['selected_subscription'] = [s for s in session['subscription_list']
                                            if s['subscriptionId'] == str(subscription_id)][0]

        logger.debug("================")
        logger.debug(session['selected_subscription'])
        logger.debug(subscription_id)
        logger.debug("================")

        # --------------------------------------------
        # TOP 画面に表示する内容を取得
        # --------------------------------------------
        
        # 仮想マシン情報を取得
        vm_list = get_subscription_data(
            'subscriptions/{}/providers/Microsoft.Compute/virtualMachines/?api-version=2017-03-30'.format(subscription_id))
        # 仮想マシンがある場合は仮想マシン台数を取得
        if vm_list.get('value') != None:
            vm_num = len(vm_list['value'])

        # リソースグループ数を取得
        rg_list = get_subscription_data(
            'subscriptions/{}/resourcegroups?api-version=2017-05-10'.format(subscription_id))
        if rg_list.get('value') != None:
            rg_num = len(rg_list['value'])

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
        logger.critical(''.join('!! ' + line for line in lines))
        session_clear()
        tc.track_exception()
        tc.flush()
        return redirect(url_for('index'))

    logger.debug(session['decoded_access_token'])
    logger.debug(session['subscription_list'])
    logger.info("End subscriptions")
    return render_template('dashboard.html', vm_num=vm_num, rg_num=rg_num)

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


def get_subscription_data(resource_id):
    data = microsoft.get(resource_id).data
    if data.get('error'):
        raise Exception(data.get('error'))
    return data


if __name__ == '__main__':
    app.run(port=10080, host='0.0.0.0')
