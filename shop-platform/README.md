# 🛒 Shop Platform

**Online shopping platform** — microservices architecture with Keycloak authentication, Elasticsearch search, and Stripe payments.

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Keycloak](https://img.shields.io/badge/Keycloak-OpenID-FF7900?logo=keycloak&logoColor=white)](https://www.keycloak.org/)

---

## 📋 Table of Contents

- [Description](#-description)
- [Architecture](#-architecture)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Requirements](#-requirements)
- [Installation & Running](#-installation--running)
- [API](#-api)
- [Roles](#-roles)
- [Author](#-author)

---

## 📖 Description

The application supports **buying** and **selling** (buy-back) products, with an integrated payment portal and advanced search. All operations are secured via **Keycloak** (OAuth2/OpenID Connect), and transactions are processed through **Stripe**.

---

## 🏗 Architecture

```
                    ┌─────────────────┐
                    │   Client / UI   │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   API Gateway   │  (port 5000)
                    │  Auth + Proxy   │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
┌────────▼────────┐ ┌────────▼────────┐ ┌───────▼────────┐
│ Product Service │ │  Order Service   │ │    Keycloak     │
│   (port 5001)   │ │   (port 5002)    │ │   (port 8080)   │
│ + Elasticsearch │ │ + Stripe         │ │   (Auth/SSO)    │
└────────┬────────┘ └────────┬────────┘ └─────────────────┘
         │                   │
         └───────────┬───────┘
                     │
            ┌────────▼────────┐
            │   PostgreSQL    │  (port 5432)
            │   shop_db       │
            └─────────────────┘
```

- **API Gateway** — routing, JWT validation, proxy to Product and Order services.
- **Product Service** — product CRUD, stock, search (including Elasticsearch).
- **Order Service** — orders (buy/sell), users, Stripe payments, webhooks.
- **Keycloak** — realm, client, roles: `visitor`, `user`, `admin`.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Products** | List, detail, search (query, category, price), suggestions, Elasticsearch reindex |
| **Orders** | Create order (buy), sell to shop (sell), list, filters (status, type) |
| **Payments** | Stripe checkout, webhooks for events, payment status per order |
| **Authentication** | OAuth2 login/logout, refresh token, `/auth/me` endpoint |
| **Admin** | Product management (CRUD, price, stock), delete products, order statistics |

---

## 🛠 Tech Stack

| Component | Stack |
|-----------|--------|
| Backend | Python 3, Flask |
| Database | PostgreSQL |
| Authentication | Keycloak (OAuth2 / OpenID Connect, JWT) |
| Search | Elasticsearch |
| Payments | Stripe (API + Webhooks) |
| ORM | SQLAlchemy |

---

## 📦 Requirements

- **Python** 3.10+
- **PostgreSQL** 15+
- **Keycloak** (e.g. 22+)
- **Elasticsearch** 8.x (optional for advanced search)
- **Stripe** account (for payments)

---

## 🚀 Installation & Running

### 1. Clone the repository

```bash
git clone https://github.com/<user>/shop-platform.git
cd shop-platform
```

### 2. Virtual environment and dependencies

```bash
python -m venv venv
source venv/bin/activate   # Linux/macOS
# or: venv\Scripts\activate   # Windows

pip install -r requirements.txt
```

### 3. Environment variables

Create `.env` files (or export variables) for each service.

**API Gateway** (example):

```env
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_PUBLIC_URL=http://localhost:8080
KEYCLOAK_REALM=shop-realm
KEYCLOAK_CLIENT_ID=shop-client
KEYCLOAK_CLIENT_SECRET=<client-secret>
PRODUCT_SERVICE_URL=http://localhost:5001
ORDER_SERVICE_URL=http://localhost:5002
GATEWAY_URL=http://localhost:5000
```

**Product Service**:

```env
DATABASE_URL=postgresql://shop_user:shop_password@localhost:5432/shop_db
ELASTICSEARCH_URL=http://localhost:9200
```

**Order Service**:

```env
DATABASE_URL=postgresql://shop_user:shop_password@localhost:5432/shop_db
PRODUCT_SERVICE_URL=http://localhost:5001
STRIPE_SECRET_KEY=sk_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

### 4. Database

Run the init script on PostgreSQL (e.g. `database/init.sql`). On first startup, tables are created automatically via SQLAlchemy.

### 5. Start services

In separate terminals (from the project root):

```bash
# Product Service
cd product-service && python app.py

# Order Service
cd order-service && python app.py

# API Gateway
cd api-gateway && python app.py
```

Keycloak must be running and configured (realm, client, users, roles). Start Elasticsearch if you use advanced search.

---

## 📡 API

All requests to the backend go through the **API Gateway** (`http://localhost:5000`). Authentication uses a **Bearer token** (JWT from Keycloak), except for public routes (e.g. login, health, some GETs).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/products` | List products |
| `GET` | `/products/<id>` | Product detail |
| `GET` | `/products/search` | Search (query, category, minPrice, maxPrice) |
| `GET` | `/products/search/advanced` | Elasticsearch search |
| `GET` | `/products/search/suggest` | Search suggestions |
| `POST` | `/admin/products` | Create product (admin) |
| `PUT` | `/admin/products/<id>/price` | Update price (admin) |
| `PUT` | `/admin/products/<id>/stock` | Update stock (admin) |
| `DELETE` | `/admin/products/<id>` | Delete product (admin) |
| `POST` | `/admin/products/reindex` | Reindex Elasticsearch (admin) |
| `POST` | `/orders` | Create order (buy) |
| `GET` | `/orders` | List orders (with filters; admin) |
| `GET` | `/orders/<id>` | Order detail |
| `POST` | `/sell` | Sell product to shop |
| `POST` | `/webhooks/stripe` | Stripe webhook (no JWT) |
| `GET` | `/payments/<order_id>/status` | Payment status |
| `GET` | `/auth/me` | Current user |
| `GET` | `/health` | Health check |

---

## 👥 Roles

| Role | Permissions |
|------|-------------|
| **visitor** | View products, search (as exposed by the gateway) |
| **user** | Orders (buy/sell), own orders, payments |
| **admin** | Product management, list orders, statistics, reindex, etc. |

Roles are managed in **Keycloak** (realm roles / client roles) and are included in the JWT.

---

## 📄 License

Educational project (SCD).

---

## 👤 Author

**Bîrleanu Teodor Matei**  
*343C3*

---

*If you run into setup issues or want to contribute, open an issue or a pull request.*
