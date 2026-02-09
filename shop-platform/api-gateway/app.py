from flask import Flask, request, jsonify, render_template_string, redirect, session, url_for
from functools import wraps
import requests
import jwt
import os
import secrets
import hashlib
import base64
from datetime import datetime
from urllib.parse import urlencode

app = Flask(__name__)


KEYCLOAK_URL = os.environ['KEYCLOAK_URL']  # URL intern pentru backend communication
KEYCLOAK_PUBLIC_URL = os.environ.get('KEYCLOAK_PUBLIC_URL', 'http://localhost:8080')  # URL public pentru browser
PRODUCT_SERVICE_URL = os.environ.get('PRODUCT_SERVICE_URL', 'http://product-service:5001')
ORDER_SERVICE_URL = os.environ.get('ORDER_SERVICE_URL', 'http://order-service:5002')
GATEWAY_URL = os.environ.get('GATEWAY_URL', 'http://localhost:5000')

# config keycloak
KEYCLOAK_REALM = os.environ['KEYCLOAK_REALM']
KEYCLOAK_CLIENT_ID = os.environ['KEYCLOAK_CLIENT_ID']
KEYCLOAK_CLIENT_SECRET = os.environ['KEYCLOAK_CLIENT_SECRET']

def get_keycloak_public_key():
    try:
        url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"
        response = requests.get(url, timeout=5)
        key_data = response.json()
        return key_data.get('public_key')
    except Exception as e:
        app.logger.error(f"Error fetching Keycloak public key: {e}")
        return None

def verify_token(token):
    try:
        public_key = get_keycloak_public_key()
        if not public_key:
            return None
        
        # format public key for pyjwt
        public_key_formatted = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
        
        decoded = jwt.decode(
            token,
            public_key_formatted,
            algorithms=['RS256'],
            options={
                'verify_exp': True,
                'verify_aud': False,
                'verify_iss': False,
                'require': ['exp', 'iat', 'sub']
            }
        )
        
        expected_iss = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"
        if decoded.get('iss') != expected_iss:
            app.logger.warning(f"Issuer mismatch: {decoded.get('iss')} != {expected_iss}")
        
        return decoded
    except jwt.ExpiredSignatureError:
        app.logger.error("Token expired")
        return None
    except Exception as e:
        app.logger.error(f"Token verification error: {e}")
        return None

def get_user_roles(token_data):
    if not token_data:
        return ['visitor']
    
    roles = []
    if 'realm_access' in token_data and 'roles' in token_data['realm_access']:
        roles.extend(token_data['realm_access']['roles'])
    
    if 'resource_access' in token_data and KEYCLOAK_CLIENT_ID in token_data['resource_access']:
        client_roles = token_data['resource_access'][KEYCLOAK_CLIENT_ID].get('roles', [])
        roles.extend(client_roles)
    
    if not roles or all(role in ['offline_access', 'uma_authorization'] for role in roles):
        roles.append('visitor')
    
    return roles

def require_auth(required_roles=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = None
            
            # get token
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            
            # get toke from sess
            if not token:
                token = session.get('access_token')
            
            if not token:
                return jsonify({'error': 'No token provided', 'message': 'Authentication required'}), 401
            
            token_data = verify_token(token)
            if not token_data:
                return jsonify({'error': 'Invalid token', 'message': 'Authentication failed'}), 401
            
            # check roles
            user_roles = get_user_roles(token_data)
            if required_roles:
                if not any(role in user_roles for role in required_roles):
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'message': f'Requires one of: {required_roles}',
                        'your_roles': user_roles
                    }), 403
            
            # add user info
            request.user_info = {
                'user_id': token_data.get('sub'),
                'username': token_data.get('preferred_username'),
                'email': token_data.get('email'),
                'roles': user_roles
            }
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/')
def home():
    return jsonify({
        'message': 'Online Shopping Platform API',
        'version': '3.0',
        'auth_type': 'SSO with PKCE',
        'features': [
            'Elasticsearch Advanced Search',
            'Auto-indexing',
            'Fuzzy Matching',
            'Stripe Async Payments',
            'Webhook Processing'
        ],
        'endpoints': {
            'auth': {
                'login': 'GET /auth/login - Initiate SSO login',
                'callback': 'GET /auth/callback - OAuth callback',
                'logout': 'POST /auth/logout - Logout and revoke tokens',
                'refresh': 'POST /auth/refresh - Refresh access token',
                'me': 'GET /auth/me - Get current user info'
            },
            'products': {
                'list': 'GET /products - List all products',
                'get': 'GET /products/{id} - Get product details',
                'search': 'GET /products/search - Basic search',
                'advanced_search': 'GET /products/search/advanced - Elasticsearch powered search',
            },
            'orders': {
                'create': 'POST /orders - Create order with payment',
                'list': 'GET /orders - List orders',
                'get': 'GET /orders/{id} - Get order details'
            },
            'payments': {
                'webhook': 'POST /webhooks/stripe - Stripe webhook handler',
                'status': 'GET /payments/{order_id}/status - Check payment status'
            },
            'admin': {
                'products': 'POST/PUT/DELETE /admin/products',
                'reindex': 'POST /admin/products/reindex - Reindex all products',
                'orders': 'GET /admin/orders'
            }
        }
    })

def generate_pkce_pair():
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    return code_verifier, code_challenge

@app.route('/auth/login', methods=['GET'])
def login():
    """SSO login with authorization code flow + PKCE"""
    code_verifier, code_challenge = generate_pkce_pair()
    
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    session['code_verifier'] = code_verifier
    
    auth_params = {
        'client_id': KEYCLOAK_CLIENT_ID,
        'response_type': 'code',
        'scope': 'openid profile email',
        'redirect_uri': f"{GATEWAY_URL}/auth/callback",
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    
    auth_url = f"{KEYCLOAK_PUBLIC_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
    redirect_url = f"{auth_url}?{urlencode(auth_params)}"
    
    return jsonify({
        'message': 'Redirect to SSO login',
        'redirect_url': redirect_url
    })

@app.route('/auth/callback', methods=['GET'])
def auth_callback():
    state = request.args.get('state')
    if not state or state != session.get('oauth_state'):
        return jsonify({'error': 'Invalid state parameter'}), 400
    
    code = request.args.get('code')
    if not code:
        error = request.args.get('error', 'Unknown error')
        return jsonify({'error': f'Authorization failed: {error}'}), 400
    
    code_verifier = session.get('code_verifier')
    if not code_verifier:
        return jsonify({'error': 'Code verifier not found in session'}), 400
    
    token_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    token_data = {
        'client_id': KEYCLOAK_CLIENT_ID,
        'client_secret': KEYCLOAK_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': f"{GATEWAY_URL}/auth/callback",
        'code_verifier': code_verifier
    }
    
    try:
        response = requests.post(token_url, data=token_data, timeout=5)
        if response.status_code == 200:
            token_response = response.json()
            
            session['access_token'] = token_response['access_token']
            session['refresh_token'] = token_response.get('refresh_token')
            session['id_token'] = token_response.get('id_token')
            
            session.pop('oauth_state', None)
            session.pop('code_verifier', None)
            
            return jsonify({
                'message': 'Login successful',
                'access_token': token_response['access_token'],
                'refresh_token': token_response.get('refresh_token'),
                'expires_in': token_response.get('expires_in')
            })
        else:
            app.logger.error(f"Token exchange failed: {response.text}")
            return jsonify({'error': 'Token exchange failed'}), 401
    except Exception as e:
        app.logger.error(f"Login error: {e}")
        return jsonify({'error': 'Authentication service unavailable'}), 503

@app.route('/auth/refresh', methods=['POST'])
def refresh_token():
    refresh_token = session.get('refresh_token')
    if not refresh_token:
        return jsonify({'error': 'No refresh token available'}), 401
    
    token_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    token_data = {
        'client_id': KEYCLOAK_CLIENT_ID,
        'client_secret': KEYCLOAK_CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }
    
    try:
        response = requests.post(token_url, data=token_data, timeout=5)
        if response.status_code == 200:
            token_response = response.json()
            
            session['access_token'] = token_response['access_token']
            session['refresh_token'] = token_response.get('refresh_token')
            
            return jsonify({
                'message': 'Token refreshed successfully',
                'access_token': token_response['access_token'],
                'expires_in': token_response.get('expires_in')
            })
        else:
            return jsonify({'error': 'Token refresh failed'}), 401
    except Exception as e:
        app.logger.error(f"Refresh token error: {e}")
        return jsonify({'error': 'Authentication service unavailable'}), 503

@app.route('/auth/logout', methods=['POST'])
def logout():
    access_token = session.get('access_token')
    refresh_token = session.get('refresh_token')
    
    if refresh_token:
        logout_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout"
        logout_data = {
            'client_id': KEYCLOAK_CLIENT_ID,
            'client_secret': KEYCLOAK_CLIENT_SECRET,
            'refresh_token': refresh_token
        }
        
        try:
            requests.post(logout_url, data=logout_data, timeout=5)
        except Exception as e:
            app.logger.error(f"Error revoking token: {e}")
    
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/auth/me')
@require_auth()
def me():
    return jsonify(request.user_info)


@app.route('/products', methods=['GET'])
def get_products():
    try:
        response = requests.get(f"{PRODUCT_SERVICE_URL}/products", timeout=5)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error fetching products: {e}")
        return jsonify({'error': 'Product service unavailable'}), 503

@app.route('/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    try:
        response = requests.get(f"{PRODUCT_SERVICE_URL}/products/{product_id}", timeout=5)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error fetching product: {e}")
        return jsonify({'error': 'Product service unavailable'}), 503

@app.route('/products/search', methods=['GET'])
def search_products():
    query = request.args.get('query', '')
    category = request.args.get('category', '')
    min_price = request.args.get('minPrice', '')
    max_price = request.args.get('maxPrice', '')
    
    params = {
        'query': query,
        'category': category,
        'minPrice': min_price,
        'maxPrice': max_price
    }
    
    try:
        response = requests.get(f"{PRODUCT_SERVICE_URL}/products/search", params=params, timeout=5)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error searching products: {e}")
        return jsonify({'error': 'Product service unavailable'}), 503

@app.route('/products/search/advanced', methods=['GET'])
def advanced_search():
    try:
        params = request.args.to_dict()
        response = requests.get(
            f"{PRODUCT_SERVICE_URL}/products/search/advanced",
            params=params,
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error in advanced search: {e}")
        return jsonify({'error': 'Product service unavailable'}), 503

@app.route('/products/search/suggest', methods=['GET'])
def search_suggestions():
    try:
        query = request.args.get('q', '')
        response = requests.get(
            f"{PRODUCT_SERVICE_URL}/products/search/suggest",
            params={'q': query},
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error getting suggestions: {e}")
        return jsonify({'suggestions': []})


@app.route('/admin/products', methods=['POST'])
@require_auth(required_roles=['admin'])
def create_product():
    try:
        response = requests.post(
            f"{PRODUCT_SERVICE_URL}/products",
            json=request.get_json(),
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error creating product: {e}")
        return jsonify({'error': 'Product service unavailable'}), 503

@app.route('/admin/products/<int:product_id>/price', methods=['PUT'])
@require_auth(required_roles=['admin'])
def update_price(product_id):
    try:
        response = requests.put(
            f"{PRODUCT_SERVICE_URL}/products/{product_id}/price",
            json=request.get_json(),
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error updating price: {e}")
        return jsonify({'error': 'Product service unavailable'}), 503

@app.route('/admin/products/<int:product_id>/stock', methods=['PUT'])
@require_auth(required_roles=['admin'])
def update_stock(product_id):
    try:
        response = requests.put(
            f"{PRODUCT_SERVICE_URL}/products/{product_id}/stock",
            json=request.get_json(),
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error updating stock: {e}")
        return jsonify({'error': 'Product service unavailable'}), 503

@app.route('/admin/products/<int:product_id>', methods=['DELETE'])
@require_auth(required_roles=['admin'])
def delete_product(product_id):
    try:
        response = requests.delete(f"{PRODUCT_SERVICE_URL}/products/{product_id}", timeout=5)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error deleting product: {e}")
        return jsonify({'error': 'Product service unavailable'}), 503

@app.route('/admin/products/reindex', methods=['POST'])
@require_auth(required_roles=['admin'])
def reindex_products():
    """ admin only"""
    try:
        response = requests.post(f"{PRODUCT_SERVICE_URL}/products/reindex", timeout=30)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error reindexing products: {e}")
        return jsonify({'error': 'Product service unavailable'}), 503


@app.route('/orders', methods=['GET', 'POST'])
@require_auth()
def orders():
    try:
        headers = {'X-User-Info': str(request.user_info)}
        
        if request.method == 'GET':
            if 'admin' in request.user_info['roles']:
                params = request.args.to_dict()
                response = requests.get(f"{ORDER_SERVICE_URL}/orders", params=params, headers=headers, timeout=5)
            else:
                response = requests.get(f"{ORDER_SERVICE_URL}/orders/user/{request.user_info['user_id']}", headers=headers, timeout=5)
        else: 
            response = requests.post(
                f"{ORDER_SERVICE_URL}/orders",
                json=request.get_json(),
                headers=headers,
                timeout=5
            )
        
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error with orders: {e}")
        return jsonify({'error': 'Order service unavailable'}), 503

@app.route('/orders/<int:order_id>', methods=['GET'])
@require_auth()
def get_order(order_id):
    try:
        headers = {'X-User-Info': str(request.user_info)}
        response = requests.get(f"{ORDER_SERVICE_URL}/orders/{order_id}", headers=headers, timeout=5)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error fetching order: {e}")
        return jsonify({'error': 'Order service unavailable'}), 503

@app.route('/sell', methods=['POST'])
@require_auth()
def sell_product():
    try:
        headers = {'X-User-Info': str(request.user_info)}
        response = requests.post(
            f"{ORDER_SERVICE_URL}/sell",
            json=request.get_json(),
            headers=headers,
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error selling product: {e}")
        return jsonify({'error': 'Order service unavailable'}), 503

## endpoint payment
@app.route('/webhooks/stripe', methods=['POST'])
def stripe_webhook_proxy():

    try:
        headers = {
            'Content-Type': request.headers.get('Content-Type'),
            'Stripe-Signature': request.headers.get('Stripe-Signature')
        }
        
        response = requests.post(
            f"{ORDER_SERVICE_URL}/webhooks/stripe",
            data=request.data,
            headers=headers,
            timeout=30 
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error forwarding Stripe webhook: {e}")
        return jsonify({'error': 'Webhook processing failed'}), 500

@app.route('/payments/<int:order_id>/status', methods=['GET'])
@require_auth()
def check_payment_status(order_id):
    try:
        headers = {'X-User-Info': str(request.user_info)}
        response = requests.get(
            f"{ORDER_SERVICE_URL}/payments/{order_id}/status",
            headers=headers,
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        app.logger.error(f"Error checking payment status: {e}")
        return jsonify({'error': 'Order service unavailable'}), 503

@app.route('/payment/success')
def payment_success():
    order_id = request.args.get('order_id')
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Payment Complete</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                text-align: center; 
                background: #f0f9ff; 
                padding: 80px; 
            }
            .big-payment {
                font-size: 60px;
                color: #16a34a;
                font-weight: bold;
                margin-top: 100px;
            }
        </style>
    </head>
    <body>
        <div class="big-payment">PAYMENT COMPLETE</div>
    </body>
    </html>
    '''

@app.route('/payment/cancel')
def payment_cancel():
    order_id = request.args.get('order_id')
    return "payment cancelled"

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'api-gateway'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

