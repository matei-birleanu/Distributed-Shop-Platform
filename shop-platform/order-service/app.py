
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Enum as SQLEnum, ForeignKey, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session, relationship
from datetime import datetime
from enum import Enum
import os
import requests
import ast
import stripe
import hmac
import hashlib

app = Flask(__name__)


DATABASE_URL = os.environ['DATABASE_URL']
PRODUCT_SERVICE_URL = os.environ.get('PRODUCT_SERVICE_URL', 'http://product-service:5001')

# stripe config
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')


# sqlalchkemy setup
engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)
SessionLocal = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()


class OrderType(str, Enum):
    BUY = "buy"
    SELL = "sell"

class OrderStatus(str, Enum):
    PENDING = "pending"
    PENDING_PAYMENT = "pending_payment"
    PAYMENT_PROCESSING = "payment_processing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    REFUNDED = "refunded"

class PaymentStatus(str, Enum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"


class User(Base):

    __tablename__ = 'users'
    
    id = Column(String(255), primary_key=True)
    username = Column(String(255), nullable=False, index=True)
    email = Column(String(255), unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # relation with orders 
    orders = relationship("Order", back_populates="user", cascade="all, delete-orphan")
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class Order(Base):
    __tablename__ = 'orders'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(String(255), ForeignKey('users.id', ondelete='CASCADE', onupdate='CASCADE'), nullable=False, index=True)
    product_id = Column(Integer, nullable=False, index=True)
    product_name = Column(String(255))
    quantity = Column(Integer, nullable=False)
    price_per_unit = Column(Float, nullable=False)
    total_price = Column(Float, nullable=False)
    order_type = Column(SQLEnum(OrderType), default=OrderType.BUY, index=True)
    status = Column(SQLEnum(OrderStatus), default=OrderStatus.PENDING, index=True)
    
    # payment info
    payment_intent_id = Column(String(255), unique=True, index=True)  # stripe payment id
    payment_status = Column(SQLEnum(PaymentStatus), default=PaymentStatus.NOT_REQUIRED, index=True)
    payment_method = Column(String(50))
    currency = Column(String(3), default='RON')
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = relationship("User", back_populates="orders")
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'product_id': self.product_id,
            'product_name': self.product_name,
            'quantity': self.quantity,
            'price_per_unit': self.price_per_unit,
            'total_price': self.total_price,
            'order_type': self.order_type.value if isinstance(self.order_type, Enum) else self.order_type,
            'status': self.status.value if isinstance(self.status, Enum) else self.status,
            'payment_intent_id': self.payment_intent_id,
            'payment_status': self.payment_status.value if isinstance(self.payment_status, Enum) else self.payment_status,
            'payment_method': self.payment_method,
            'currency': self.currency,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

try:
    Base.metadata.create_all(engine)
except Exception as e:
    if "already exists" in str(e):
        app.logger.warning(f"Some database types already exist: {e}")
    else:
        raise


def get_db():
    db = SessionLocal()
    try:
        return db
    finally:
        pass

@app.teardown_appcontext
def remove_session(exception=None):
    SessionLocal.remove()

def get_user_info():
    user_info_str = request.headers.get('X-User-Info', '{}')
    try:
        user_info = ast.literal_eval(user_info_str)
        return user_info
    except:
        return {}

def get_or_create_user(db, user_info):
    user_id = user_info.get('user_id')
    username = user_info.get('username', 'unknown')
    email = user_info.get('email', '')
    
    if not user_id:
        raise ValueError("User ID is required")
    
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        user = User(
            id=user_id,
            username=username,
            email=email
        )
        db.add(user)
        db.flush()
    else:
        if user.username != username or user.email != email:
            user.username = username
            user.email = email
            user.updated_at = datetime.utcnow()
            db.flush()
    
    return user

def get_product_info(product_id):
    try:
        response = requests.get(f"{PRODUCT_SERVICE_URL}/products/{product_id}", timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        app.logger.error(f"Error fetching product: {e}")
        return None

def adjust_product_stock(product_id, adjustment):
    try:
        response = requests.post(
            f"{PRODUCT_SERVICE_URL}/products/{product_id}/stock/adjust",
            json={'adjustment': adjustment},
            timeout=5
        )
        return response.status_code == 200, response.json()
    except Exception as e:
        app.logger.error(f"Error adjusting stock: {e}")
        return False, {'error': str(e)}

def create_checkout_session(order_id, product_name, amount, currency='ron', metadata=None):
    if not STRIPE_SECRET_KEY:
        raise ValueError("Stripe not configured")
    
    try:
        amount_cents = int(amount * 100)
        
        # url for succes cancel
        gateway_url = os.getenv('GATEWAY_URL', 'http://localhost:5000')
        success_url = f"{gateway_url}/payment/success?order_id={order_id}"
        cancel_url = f"{gateway_url}/payment/cancel?order_id={order_id}"
        
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': currency.lower(),
                    'unit_amount': amount_cents,
                    'product_data': {
                        'name': product_name,
                        'description': f'Order #{order_id}',
                    },
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=success_url,
            cancel_url=cancel_url,
            metadata=metadata or {},
            client_reference_id=str(order_id),
        )
        
        return checkout_session
    except stripe.error.StripeError as e:
        app.logger.error(f"Stripe error creating Checkout Session: {e}")
        raise

def verify_webhook_signature(payload, signature):
    if not STRIPE_WEBHOOK_SECRET:
        app.logger.warning("Webhook secret not configured")
        return None
    
    try:
        event = stripe.Webhook.construct_event(
            payload, signature, STRIPE_WEBHOOK_SECRET
        )
        return event
    except ValueError as e:
        app.logger.error(f"Invalid payload: {e}")
        return None
    except stripe.error.SignatureVerificationError as e:
        app.logger.error(f"Invalid signature: {e}")
        return None

def update_order_payment_status(db, order_id, payment_intent_id, new_status):
    """apelat din webhook"""
    try:
        order = db.query(Order).filter(Order.id == order_id).first()
        if not order:
            app.logger.error(f"Order {order_id} not found")
            return False
        
        order.payment_intent_id = payment_intent_id
        order.payment_status = new_status
        order.updated_at = datetime.utcnow()
        
        if new_status == PaymentStatus.SUCCEEDED:
            order.status = OrderStatus.COMPLETED
        elif new_status == PaymentStatus.FAILED:
            order.status = OrderStatus.FAILED
        elif new_status == PaymentStatus.CANCELLED:
            order.status = OrderStatus.CANCELLED
        
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error updating payment status: {e}")
        return False


@app.route('/orders', methods=['POST'])
def create_order():
    db = get_db()
    try:
        data = request.get_json()
        user_info = get_user_info()
        
        if 'product_id' not in data or 'quantity' not in data:
            return jsonify({'error': 'product_id and quantity are required'}), 400
        
        try:
            user = get_or_create_user(db, user_info)
        except ValueError as e:
            return jsonify({'error': str(e)}), 401
        
        product_id = int(data['product_id'])
        quantity = int(data['quantity'])
        
        if quantity <= 0:
            return jsonify({'error': 'Quantity must be positive'}), 400
        
        product = get_product_info(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        # check stock
        if product['stock'] < quantity:
            return jsonify({
                'error': 'Insufficient stock',
                'available': product['stock'],
                'requested': quantity
            }), 400
        
        total_price = product['price'] * quantity
        requires_payment = data.get('requires_payment', True) 
        
        # order with  status pending
        order = Order(
            user_id=user.id,
            product_id=product_id,
            product_name=product['name'],
            quantity=quantity,
            price_per_unit=product['price'],
            total_price=total_price,
            order_type=OrderType.BUY,
            status=OrderStatus.PENDING_PAYMENT if requires_payment else OrderStatus.PENDING,
            payment_status=PaymentStatus.PENDING if requires_payment else PaymentStatus.NOT_REQUIRED,
            currency='RON'
        )
        
        db.add(order)
        db.commit()
        db.refresh(order)
        
        # create stripe checkout session
        if requires_payment and STRIPE_SECRET_KEY:
            try:
                checkout_session = create_checkout_session(
                    order_id=order.id,
                    product_name=product['name'],
                    amount=total_price,
                    currency='ron',
                    metadata={
                        'order_id': str(order.id),
                        'user_id': user.id,
                        'product_id': str(product_id),
                        'quantity': str(quantity)
                    }
                )
                
                order.payment_intent_id = checkout_session.id
                order.payment_status = PaymentStatus.PROCESSING
                db.commit()
                db.refresh(order)
                
                return jsonify({
                    'message': 'Order created - complete payment via checkout link',
                    'order': order.to_dict(),
                    'payment': {
                        'checkout_url': checkout_session.url,
                        'session_id': checkout_session.id,
                        'amount': total_price,
                        'currency': 'RON',
                        'status': checkout_session.status
                    },
                    'instructions': 'Open checkout_url in browser to complete payment'
                }), 201
            except Exception as e:
                app.logger.error(f"Error creating checkout session: {e}")
                order.status = OrderStatus.FAILED
                order.payment_status = PaymentStatus.FAILED
                db.commit()
                
                return jsonify({
                    'error': 'Failed to initialize payment',
                    'order': order.to_dict(),
                    'details': str(e)
                }), 500
        
        else:
            success, result = adjust_product_stock(product_id, -quantity)
            
            if success:
                order.status = OrderStatus.COMPLETED
                order.payment_status = PaymentStatus.NOT_REQUIRED
                db.commit()
                db.refresh(order)
                
                return jsonify({
                    'message': 'Order created successfully (no payment required)',
                    'order': order.to_dict()
                }), 201
            else:
                order.status = OrderStatus.FAILED
                db.commit()
                
                return jsonify({
                    'error': 'Failed to adjust stock',
                    'order': order.to_dict(),
                    'details': result
                }), 500
            
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error creating order: {e}")
        return jsonify({'error': 'Failed to create order', 'details': str(e)}), 500

@app.route('/sell', methods=['POST'])
def sell_product():
    db = get_db()
    try:
        data = request.get_json()
        user_info = get_user_info()
        
        if 'product_id' not in data or 'quantity' not in data:
            return jsonify({'error': 'product_id and quantity are required'}), 400
        
        try:
            user = get_or_create_user(db, user_info)
        except ValueError as e:
            return jsonify({'error': str(e)}), 401
        
        product_id = int(data['product_id'])
        quantity = int(data['quantity'])
        
        if quantity <= 0:
            return jsonify({'error': 'Quantity must be positive'}), 400
        
        # prod info
        product = get_product_info(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        # here is the ideea we can sell with 0.8 of original price
        buyback_price = product['price'] * 0.8
        total_price = buyback_price * quantity
        
        order = Order(
            user_id=user.id,
            product_id=product_id,
            product_name=product['name'],
            quantity=quantity,
            price_per_unit=buyback_price,
            total_price=total_price,
            order_type=OrderType.SELL,
            status=OrderStatus.PENDING
        )
        
        db.add(order)
        db.commit()
        
        # increase stock
        success, result = adjust_product_stock(product_id, quantity)
        
        if success:
            order.status = OrderStatus.COMPLETED
            db.commit()
            db.refresh(order)
            
            return jsonify({
                'message': 'Sell order created successfully',
                'order': order.to_dict(),
                'info': 'Shop buys back at 80% of original price'
            }), 201
        else:
            order.status = OrderStatus.FAILED
            db.commit()
            
            return jsonify({
                'error': 'Failed to adjust stock',
                'order': order.to_dict(),
                'details': result
            }), 500
            
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error creating sell order: {e}")
        return jsonify({'error': 'Failed to create sell order', 'details': str(e)}), 500

@app.route('/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    db = get_db()
    try:
        user_info = get_user_info()
        
        order = db.query(Order).filter(Order.id == order_id).first()
        if not order:
            return jsonify({'error': 'Order not found'}), 404
        
        if 'admin' not in user_info.get('roles', []):
            if order.user_id != user_info.get('user_id'):
                return jsonify({'error': 'Unauthorized'}), 403
        
        return jsonify(order.to_dict())
    except Exception as e:
        app.logger.error(f"Error fetching order: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/orders/user/<user_id>', methods=['GET'])
def get_user_orders(user_id):
    db = get_db()
    try:
        user_info = get_user_info()
        
        if user_id != user_info.get('user_id') and 'admin' not in user_info.get('roles', []):
            return jsonify({'error': 'Unauthorized'}), 403
        
        orders = db.query(Order).filter(Order.user_id == user_id).order_by(Order.created_at.desc()).all()
        
        return jsonify({
            'orders': [o.to_dict() for o in orders],
            'count': len(orders)
        })
    except Exception as e:
        app.logger.error(f"Error fetching user orders: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/orders', methods=['GET'])
def get_all_orders():
    db = get_db()
    try:
        user_info = get_user_info()
        
        if 'admin' not in user_info.get('roles', []):
            return jsonify({'error': 'Admin access required'}), 403
        
        query = db.query(Order)
        
        status = request.args.get('status')
        if status:
            try:
                status_enum = OrderStatus(status)
                query = query.filter(Order.status == status_enum)
            except ValueError:
                return jsonify({'error': f'Invalid status: {status}'}), 400
        
        order_type = request.args.get('type')
        if order_type:
            try:
                type_enum = OrderType(order_type)
                query = query.filter(Order.order_type == type_enum)
            except ValueError:
                return jsonify({'error': f'Invalid order type: {order_type}'}), 400
        
        orders = query.order_by(Order.created_at.desc()).all()
        
        return jsonify({
            'orders': [o.to_dict() for o in orders],
            'count': len(orders),
            'filters': {
                'status': status,
                'type': order_type
            }
        })
    except Exception as e:
        app.logger.error(f"Error fetching orders: {e}")
        return jsonify({'error': 'Database error'}), 500

## statistics
@app.route('/orders/stats', methods=['GET'])
def get_order_stats():
    db = get_db()
    try:
        user_info = get_user_info()
        
        # only admin
        if 'admin' not in user_info.get('roles', []):
            return jsonify({'error': 'Admin access required'}), 403
        
        total_orders = db.query(Order).count()
        buy_orders = db.query(Order).filter(Order.order_type == OrderType.BUY).count()
        sell_orders = db.query(Order).filter(Order.order_type == OrderType.SELL).count()
        
        completed_orders = db.query(Order).filter(Order.status == OrderStatus.COMPLETED).count()
        pending_orders = db.query(Order).filter(Order.status == OrderStatus.PENDING).count()
        failed_orders = db.query(Order).filter(Order.status == OrderStatus.FAILED).count()
        
        buy_revenue = db.query(Order).filter(
            Order.order_type == OrderType.BUY,
            Order.status == OrderStatus.COMPLETED
        ).with_entities(Order.total_price).all()
        total_revenue = sum([order[0] for order in buy_revenue])
        
        return jsonify({
            'total_orders': total_orders,
            'by_type': {
                'buy': buy_orders,
                'sell': sell_orders
            },
            'by_status': {
                'completed': completed_orders,
                'pending': pending_orders,
                'failed': failed_orders
            },
            'revenue': {
                'total': round(total_revenue, 2),
                'currency': 'RON'
            }
        })
    except Exception as e:
        app.logger.error(f"Error calculating stats: {e}")
        return jsonify({'error': 'Database error'}), 500


@app.route('/users', methods=['GET'])
def get_users():
    """Get all users - admin only"""
    db = get_db()
    try:
        user_info = get_user_info()
        
        if 'admin' not in user_info.get('roles', []):
            return jsonify({'error': 'Admin access required'}), 403
        
        users = db.query(User).all()
        
        return jsonify({
            'users': [u.to_dict() for u in users],
            'count': len(users)
        })
    except Exception as e:
        app.logger.error(f"Error fetching users: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/users/<user_id>', methods=['GET'])
def get_user(user_id):
    db = get_db()
    try:
        user_info = get_user_info()
        
        if user_id != user_info.get('user_id') and 'admin' not in user_info.get('roles', []):
            return jsonify({'error': 'Unauthorized'}), 403
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(user.to_dict())
    except Exception as e:
        app.logger.error(f"Error fetching user: {e}")
        return jsonify({'error': 'Database error'}), 500

## Stripe Webhook Handler
@app.route('/webhooks/stripe', methods=['POST'])
def stripe_webhook():
    """
    webhook apelat cand plata este confirmata / esuata
    """
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    
    if not sig_header:
        app.logger.error("No Stripe signature header")
        return jsonify({'error': 'No signature'}), 400
    
    event = verify_webhook_signature(payload, sig_header)
    if not event:
        return jsonify({'error': 'Invalid signature'}), 400
    
    db = get_db()
    
    try:
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            order_id = session.get('client_reference_id') or session['metadata'].get('order_id')
            
            if order_id:
                app.logger.info(f"Checkout completed for order {order_id}")
                
                # find order
                order = db.query(Order).filter(Order.id == int(order_id)).first()
                if order:
                    # update status
                    order.payment_status = PaymentStatus.SUCCEEDED
                    order.payment_intent_id = session['id']
                    order.payment_method = session.get('payment_method_types', ['card'])[0] if session.get('payment_method_types') else 'card'
                    order.status = OrderStatus.PAYMENT_PROCESSING
                    order.updated_at = datetime.utcnow()
                    db.commit()
                    
                    # process oder update stock
                    success, result = adjust_product_stock(order.product_id, -order.quantity)
                    
                    if success:
                        order.status = OrderStatus.COMPLETED
                        db.commit()
                        app.logger.info(f"Order {order_id} completed successfully")
                    else:
                        order.status = OrderStatus.FAILED
                        db.commit()
                        app.logger.error(f"Failed to adjust stock for order {order_id}")
        
        elif event['type'] == 'payment_intent.succeeded':
            payment_intent = event['data']['object']
            order_id = payment_intent['metadata'].get('order_id')
            
            if order_id:
                app.logger.info(f"Payment succeeded for order {order_id}")
                
                order = db.query(Order).filter(Order.id == int(order_id)).first()
                if order:
                    order.payment_status = PaymentStatus.SUCCEEDED
                    order.payment_intent_id = payment_intent['id']
                    order.payment_method = payment_intent.get('payment_method_types', ['card'])[0]
                    order.status = OrderStatus.PAYMENT_PROCESSING
                    order.updated_at = datetime.utcnow()
                    db.commit()
                    
                    success, result = adjust_product_stock(order.product_id, -order.quantity)
                    
                    if success:
                        order.status = OrderStatus.COMPLETED
                        db.commit()
                        app.logger.info(f"Order {order_id} completed successfully")
                    else:
                        order.status = OrderStatus.FAILED
                        db.commit()
                        app.logger.error(f"Failed to adjust stock for order {order_id}")
        
        elif event['type'] == 'payment_intent.payment_failed':
            payment_intent = event['data']['object']
            order_id = payment_intent['metadata'].get('order_id')
            
            if order_id:
                app.logger.warning(f"Payment failed for order {order_id}")
                order = db.query(Order).filter(Order.id == int(order_id)).first()
                if order:
                    order.payment_status = PaymentStatus.FAILED
                    order.status = OrderStatus.FAILED
                    order.updated_at = datetime.utcnow()
                    db.commit()
        
        elif event['type'] == 'payment_intent.canceled':
            payment_intent = event['data']['object']
            order_id = payment_intent['metadata'].get('order_id')
            
            if order_id:
                app.logger.info(f"Payment canceled for order {order_id}")
                order = db.query(Order).filter(Order.id == int(order_id)).first()
                if order:
                    order.payment_status = PaymentStatus.CANCELLED
                    order.status = OrderStatus.CANCELLED
                    order.updated_at = datetime.utcnow()
                    db.commit()
        
        else:
            app.logger.info(f"Unhandled event type: {event['type']}")
        
        return jsonify({'status': 'success'}), 200
    
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error processing webhook: {e}")
        return jsonify({'error': 'Webhook processing failed'}), 500

@app.route('/payments/<int:order_id>/status', methods=['GET'])
def get_payment_status(order_id):
    db = get_db()
    try:
        user_info = get_user_info()
        
        order = db.query(Order).filter(Order.id == order_id).first()
        if not order:
            return jsonify({'error': 'Order not found'}), 404
        
        if order.user_id != user_info.get('user_id') and 'admin' not in user_info.get('roles', []):
            return jsonify({'error': 'Unauthorized'}), 403
        
        if order.payment_intent_id and STRIPE_SECRET_KEY:
            try:
                payment_intent = stripe.PaymentIntent.retrieve(order.payment_intent_id)
                
                return jsonify({
                    'order_id': order.id,
                    'payment_status': order.payment_status.value,
                    'order_status': order.status.value,
                    'stripe_status': payment_intent.status,
                    'amount': order.total_price,
                    'currency': order.currency,
                    'payment_method': order.payment_method,
                    'payment_intent_id': order.payment_intent_id
                })
            except stripe.error.StripeError as e:
                app.logger.error(f"Stripe error: {e}")
                return jsonify({
                    'order_id': order.id,
                    'payment_status': order.payment_status.value,
                    'order_status': order.status.value,
                    'error': 'Could not retrieve Stripe status'
                })
        else:
            return jsonify({
                'order_id': order.id,
                'payment_status': order.payment_status.value,
                'order_status': order.status.value,
                'amount': order.total_price,
                'currency': order.currency
            })
    
    except Exception as e:
        app.logger.error(f"Error checking payment status: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/health')
def health():
    db = get_db()
    try:
        db.execute('SELECT 1')
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'order-service',
            'database': 'connected'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'order-service',
            'database': 'disconnected',
            'error': str(e)
        }), 503

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)

