from flask import Flask, request, jsonify
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from datetime import datetime
from elasticsearch import Elasticsearch, exceptions as es_exceptions
import os
import time

app = Flask(__name__)

if not os.environ.get('DATABASE_URL'):
    raise ValueError("DATABASE_URL environment variable must be set")

DATABASE_URL = os.environ['DATABASE_URL']
ELASTICSEARCH_URL = os.environ.get('ELASTICSEARCH_URL', 'http://elasticsearch:9200')

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)
SessionLocal = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()

# Elasticsearch setup
es = None
ES_INDEX = 'products'

def init_elasticsearch():
    global es
    max_retries = 5
    retry_delay = 5
    
    for attempt in range(max_retries):
        try:
            es = Elasticsearch([ELASTICSEARCH_URL], request_timeout=30)
            if es.ping():
                app.logger.info("Connected to Elasticsearch")
                
                # Create index if it doesn't exist
                if not es.indices.exists(index=ES_INDEX):
                    es.indices.create(
                        index=ES_INDEX,
                        body={
                            "settings": {
                                "number_of_shards": 1,
                                "number_of_replicas": 0,
                                "analysis": {
                                    "analyzer": {
                                        "product_analyzer": {
                                            "type": "custom",
                                            "tokenizer": "standard",
                                            "filter": ["lowercase", "asciifolding"]
                                        }
                                    }
                                }
                            },
                            "mappings": {
                                "properties": {
                                    "name": {
                                        "type": "text",
                                        "analyzer": "product_analyzer",
                                        "fields": {
                                            "keyword": {"type": "keyword"}
                                        }
                                    },
                                    "description": {
                                        "type": "text",
                                        "analyzer": "product_analyzer"
                                    },
                                    "category": {
                                        "type": "keyword"
                                    },
                                    "price": {"type": "float"},
                                    "stock": {"type": "integer"},
                                    "in_stock": {"type": "boolean"},
                                    "created_at": {"type": "date"},
                                    "updated_at": {"type": "date"}
                                }
                            }
                        }
                    )
                    app.logger.info(f"Created Elasticsearch index: {ES_INDEX}")
                return True
            else:
                raise Exception("Cannot ping Elasticsearch")
        except Exception as e:
            app.logger.warning(f"Elasticsearch connection attempt {attempt + 1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            else:
                app.logger.error("Failed to connect to Elasticsearch after all retries")
                es = None
                return False

init_elasticsearch()

class Product(Base):
    __tablename__ = 'products'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    price = Column(Float, nullable=False)
    stock = Column(Integer, default=0)
    category = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'stock': self.stock,
            'category': self.category,
            'in_stock': self.stock > 0,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

Base.metadata.create_all(engine)

def get_db():
    db = SessionLocal()
    try:
        return db
    finally:
        pass 

@app.teardown_appcontext
def remove_session(exception=None):
    SessionLocal.remove()

def index_product(product):
    if es is None:
        app.logger.warning("Elasticsearch not available, skipping indexing")
        return False
    
    try:
        doc = {
            'name': product.name,
            'description': product.description or '',
            'category': product.category or '',
            'price': product.price,
            'stock': product.stock,
            'in_stock': product.stock > 0,
            'created_at': product.created_at.isoformat() if product.created_at else None,
            'updated_at': product.updated_at.isoformat() if product.updated_at else None
        }
        es.index(index=ES_INDEX, id=product.id, document=doc)
        return True
    except Exception as e:
        app.logger.error(f"Error indexing product {product.id}: {e}")
        return False

def delete_from_index(product_id):
    if es is None:
        return False
    
    try:
        es.delete(index=ES_INDEX, id=product_id, ignore=[404])
        return True
    except Exception as e:
        app.logger.error(f"Error deleting product {product_id} from index: {e}")
        return False

def search_elasticsearch(query_text='', category='', min_price=None, max_price=None, in_stock_only=False):
    if es is None:
        app.logger.warning("Elasticsearch not available")
        return None
    
    try:
        must_clauses = []
        filter_clauses = []
        
        # text search on name and description
        if query_text:
            must_clauses.append({
                "multi_match": {
                    "query": query_text,
                    "fields": ["name^2", "description"],
                    "type": "best_fields",
                    "fuzziness": "AUTO"
                }
            })
        
        if category:
            filter_clauses.append({"term": {"category": category}})
        
        if min_price is not None or max_price is not None:
            price_range = {}
            if min_price is not None:
                price_range["gte"] = min_price
            if max_price is not None:
                price_range["lte"] = max_price
            filter_clauses.append({"range": {"price": price_range}})
        
        if in_stock_only:
            filter_clauses.append({"term": {"in_stock": True}})
        
        if not must_clauses and not filter_clauses:
            query = {"match_all": {}}
        else:
            query = {
                "bool": {
                    "must": must_clauses if must_clauses else [{"match_all": {}}],
                    "filter": filter_clauses
                }
            }
        
        response = es.search(
            index=ES_INDEX,
            body={
                "query": query,
                "size": 100,
                "sort": [
                    {"_score": {"order": "desc"}},
                    {"created_at": {"order": "desc"}}
                ]
            }
        )
        
        return response
    except Exception as e:
        app.logger.error(f"Elasticsearch search error: {e}")
        return None

@app.route('/products', methods=['GET'])
def get_products():
    db = get_db()
    try:
        products = db.query(Product).all()
        return jsonify({
            'products': [p.to_dict() for p in products],
            'count': len(products)
        })
    except Exception as e:
        app.logger.error(f"Error fetching products: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    db = get_db()
    try:
        product = db.query(Product).filter(Product.id == product_id).first()
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        return jsonify(product.to_dict())
    except Exception as e:
        app.logger.error(f"Error fetching product: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/products/search', methods=['GET'])
def search_products():
    db = get_db()
    try:
        query_text = request.args.get('query', '')
        category = request.args.get('category', '')
        min_price = request.args.get('minPrice', type=float)
        max_price = request.args.get('maxPrice', type=float)
        
        query = db.query(Product)
        
        if query_text:
            search_pattern = f"%{query_text}%"
            query = query.filter(
                (Product.name.ilike(search_pattern)) |
                (Product.description.ilike(search_pattern))
            )
        
        if category:
            query = query.filter(Product.category == category)
        
        if min_price is not None:
            query = query.filter(Product.price >= min_price)
        if max_price is not None:
            query = query.filter(Product.price <= max_price)
        
        products = query.all()
        
        return jsonify({
            'products': [p.to_dict() for p in products],
            'count': len(products),
            'filters': {
                'query': query_text,
                'category': category,
                'minPrice': min_price,
                'maxPrice': max_price
            }
        })
    except Exception as e:
        app.logger.error(f"Error searching products: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/products', methods=['POST'])
def create_product():
    db = get_db()
    try:
        data = request.get_json()
        
        required_fields = ['name', 'price']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields: name, price'}), 400
        
        product = Product(
            name=data['name'],
            description=data.get('description', ''),
            price=float(data['price']),
            stock=int(data.get('stock', 0)),
            category=data.get('category', 'general')
        )
        
        db.add(product)
        db.commit()
        db.refresh(product)
        
        # Index in Elasticsearch
        index_product(product)
        
        return jsonify({
            'message': 'Product created successfully',
            'product': product.to_dict()
        }), 201
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error creating product: {e}")
        return jsonify({'error': 'Failed to create product'}), 500

@app.route('/products/<int:product_id>/price', methods=['PUT'])
def update_price(product_id):
    db = get_db()
    try:
        data = request.get_json()
        
        if 'price' not in data:
            return jsonify({'error': 'Price is required'}), 400
        
        product = db.query(Product).filter(Product.id == product_id).first()
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        old_price = product.price
        product.price = float(data['price'])
        product.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(product)
        
        # re index in elastic search
        index_product(product)
        
        return jsonify({
            'message': 'Price updated successfully',
            'product': product.to_dict(),
            'old_price': old_price
        })
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error updating price: {e}")
        return jsonify({'error': 'Failed to update price'}), 500

@app.route('/products/<int:product_id>/stock', methods=['PUT'])
def update_stock(product_id):
    db = get_db()
    try:
        data = request.get_json()
        
        if 'quantity' not in data:
            return jsonify({'error': 'Quantity is required'}), 400
        
        product = db.query(Product).filter(Product.id == product_id).first()
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        old_stock = product.stock
        product.stock = int(data['quantity'])
        product.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(product)
        
        index_product(product)
        
        return jsonify({
            'message': 'Stock updated successfully',
            'product': product.to_dict(),
            'old_stock': old_stock
        })
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error updating stock: {e}")
        return jsonify({'error': 'Failed to update stock'}), 500

@app.route('/products/<int:product_id>/stock/adjust', methods=['POST'])
def adjust_stock(product_id):
    db = get_db()
    try:
        data = request.get_json()
        
        if 'adjustment' not in data:
            return jsonify({'error': 'Adjustment value is required'}), 400
        
        adjustment = int(data['adjustment'])
        
        product = db.query(Product).filter(Product.id == product_id).first()
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        if adjustment < 0 and product.stock + adjustment < 0:
            return jsonify({
                'error': 'Insufficient stock',
                'available': product.stock,
                'requested': abs(adjustment)
            }), 400
        
        old_stock = product.stock
        product.stock += adjustment
        product.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(product)
        
        index_product(product)
        
        return jsonify({
            'message': 'Stock adjusted successfully',
            'product': product.to_dict(),
            'old_stock': old_stock,
            'adjustment': adjustment
        })
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error adjusting stock: {e}")
        return jsonify({'error': 'Failed to adjust stock'}), 500

@app.route('/products/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    db = get_db()
    try:
        product = db.query(Product).filter(Product.id == product_id).first()
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        product_data = product.to_dict()
        db.delete(product)
        db.commit()
        
        delete_from_index(product_id)
        
        return jsonify({
            'message': 'Product deleted successfully',
            'product': product_data
        })
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error deleting product: {e}")
        return jsonify({'error': 'Failed to delete product'}), 500

@app.route('/products/search/advanced', methods=['GET'])
def advanced_search():
    try:
        query = request.args.get('q') or request.args.get('query', '')
        category = request.args.get('category', '')
        min_price = request.args.get('minPrice', type=float)
        max_price = request.args.get('maxPrice', type=float)
        in_stock_only = request.args.get('inStock', '').lower() == 'true'
        
        es_results = search_elasticsearch(query, category, min_price, max_price, in_stock_only)
        
        if es_results and es_results.get('hits'):
            products = []
            for hit in es_results['hits']['hits']:
                product_data = hit['_source']
                product_data['id'] = int(hit['_id'])
                product_data['_score'] = hit['_score']
                products.append(product_data)
            
            return jsonify({
                'products': products,
                'count': len(products),
                'total': es_results['hits']['total']['value'],
                'search_engine': 'elasticsearch',
                'filters': {
                    'query': query,
                    'category': category,
                    'minPrice': min_price,
                    'maxPrice': max_price,
                    'inStock': in_stock_only
                }
            })
        else:
            db = get_db()
            query_db = db.query(Product)
            
            if query:
                search_pattern = f"%{query}%"
                query_db = query_db.filter(
                    (Product.name.ilike(search_pattern)) |
                    (Product.description.ilike(search_pattern))
                )
            
            if category:
                query_db = query_db.filter(Product.category == category)
            
            if min_price is not None:
                query_db = query_db.filter(Product.price >= min_price)
            if max_price is not None:
                query_db = query_db.filter(Product.price <= max_price)
            
            if in_stock_only:
                query_db = query_db.filter(Product.stock > 0)
            
            products = query_db.all()
            
            return jsonify({
                'products': [p.to_dict() for p in products],
                'count': len(products),
                'search_engine': 'database_fallback',
                'filters': {
                    'query': query,
                    'category': category,
                    'minPrice': min_price,
                    'maxPrice': max_price,
                    'inStock': in_stock_only
                }
            })
    except Exception as e:
        app.logger.error(f"Error in advanced search: {e}")
        return jsonify({'error': 'Search failed'}), 500

@app.route('/products/reindex', methods=['POST'])
def reindex_all_products():
    if es is None:
        return jsonify({'error': 'Elasticsearch not available'}), 503
    
    db = get_db()
    try:
        products = db.query(Product).all()
        
        indexed_count = 0
        failed_count = 0
        
        for product in products:
            if index_product(product):
                indexed_count += 1
            else:
                failed_count += 1
        
        return jsonify({
            'message': 'Reindexing completed',
            'total_products': len(products),
            'indexed': indexed_count,
            'failed': failed_count,
            'elasticsearch_index': ES_INDEX
        })
    except Exception as e:
        app.logger.error(f"Error reindexing products: {e}")
        return jsonify({'error': 'Reindexing failed'}), 500

@app.route('/products/search/suggest', methods=['GET'])
def search_suggestions():
    if es is None:
        return jsonify({'suggestions': []}), 200
    
    try:
        query = request.args.get('q', '')
        if not query or len(query) < 2:
            return jsonify({'suggestions': []})
        
        response = es.search(
            index=ES_INDEX,
            body={
                "suggest": {
                    "product-suggest": {
                        "prefix": query,
                        "completion": {
                            "field": "name.keyword",
                            "size": 10,
                            "skip_duplicates": True
                        }
                    }
                },
                "size": 0
            }
        )
        
        search_response = es.search(
            index=ES_INDEX,
            body={
                "query": {
                    "multi_match": {
                        "query": query,
                        "fields": ["name^2", "description"],
                        "type": "phrase_prefix"
                    }
                },
                "size": 5,
                "_source": ["name", "category", "price"]
            }
        )
        
        suggestions = []
        for hit in search_response['hits']['hits']:
            suggestions.append({
                'id': int(hit['_id']),
                'name': hit['_source']['name'],
                'category': hit['_source'].get('category'),
                'price': hit['_source']['price']
            })
        
        return jsonify({
            'suggestions': suggestions,
            'query': query
        })
    except Exception as e:
        app.logger.error(f"Error getting suggestions: {e}")
        return jsonify({'suggestions': []})

@app.route('/health')
def health():
    db = get_db()
    try:
        db.execute('SELECT 1')
        
        es_status = 'connected' if es and es.ping() else 'disconnected'
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'product-service',
            'database': 'connected',
            'elasticsearch': es_status
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'product-service',
            'database': 'disconnected',
            'error': str(e)
        }), 503

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)

