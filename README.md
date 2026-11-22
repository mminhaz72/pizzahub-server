# ⚙️ PizzaHub — RESTful Backend API Server

The backend API service for **PizzaHub**, built with **Node.js**, **Express.js**, and **MongoDB**. It powers JWT token generation, role-based access control (RBAC), menu CRUD operations, order lifecycle management, and online payment integration.

- **Live API Base URL:** [https://pizzahub-server-red.vercel.app](https://pizzahub-server-red.vercel.app)
- **Live Client Application:** [https://pizzahub-client-pi.vercel.app](https://pizzahub-client-pi.vercel.app)

---

## ✨ Core Functionalities

- **JWT Authentication & Sync (`/auth/jwt`):** Exchanges verified frontend session credentials for signed backend JWT tokens and synchronizes user profiles across roles.
- **Role-Based Access Control (RBAC):** Protected middleware enforcing strict permissions for `customer`, `vendor`, and `admin` routes.
- **Menu Management:** Full CRUD endpoints for vendors to publish, update, and manage pizza items and pricing.
- **Order Lifecycle Management:** End-to-end order creation, status updates (`pending`, `accepted`, `delivered`, `cancelled`), and role-specific order filtering.
- **User & Vendor Administration:** Admin endpoints for managing user roles, blocking/unblocking accounts, and tracking vendor subscriptions.

---

## 🛠️ Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MongoDB (Native MongoDB Driver / Atlas)
- **Security & Auth:** JSON Web Tokens (JWT) & CORS
- **Deployment:** Vercel

---

## ⚙️ Environment Variables

Create a `.env` file in the root directory of `pizzahub-server` and configure the following variables (do not commit actual secrets to GitHub):

```env
PORT=5000
MONGODB_URI=your_mongodb_atlas_connection_string
JWT_SECRET=your_jwt_signing_secret
CLIENT_URL=[https://pizzahub-client-pi.vercel.app](https://pizzahub-client-pi.vercel.app)
STRIPE_SECRET_KEY=your_stripe_secret_key
```

---

## 🚀 Getting Started Locally

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/mminhaz72/pizzahub-server.git](https://github.com/mminhaz72/pizzahub-server.git)
   cd pizzahub-server
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the development server:**
   ```bash
   npm start
   ```

4. The server will run at `http://localhost:5000`.