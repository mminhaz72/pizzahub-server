# PizzaHub — Backend API Server

Express.js and MongoDB REST API powering **PizzaHub**, a role-based pizza ordering and delivery platform with JWT authentication, role-based access control (Customer, Vendor, Admin), and Stripe Checkout + Webhook subscription verification.

## Live & Repository Links
- **Live Server API:** https://pizzahub-server-red.vercel.app
- **Live Client Website:** https://pizzahub-client-pi.vercel.app
- **Client GitHub Repository:** https://github.com/mminhaz72/pizzahub-client
- **Server GitHub Repository:** https://github.com/mminhaz72/pizzahub-server

## Key Features
- **JWT Authentication & Role Authorization:** Issues signed 7-day JWT tokens via `/auth/jwt` and enforces `verifyToken`, `verifyAdmin`, `verifyVendor`, and `verifyCustomer` middlewares (`401` / `403`).
- **Menu Management & Approval Workflow:** Vendors publish menu items (`pending` status by default; Free plan capped at 3 active/pending items, Premium unlimited), while Admins approve, reject, or remove items.
- **Advanced Search & Price Sorting:** Dynamic MongoDB regex search across item name, description, and vendor name with category/location filtering and ascending/descending price sorting.
- **Order Lifecycle & Business Rules:** Prevents duplicate active orders for the same item and delivery date, blocks vendors/admins from placing customer orders, and restricts order status updates (`accepted`/`rejected`/`cancelled`).
- **Stripe Checkout & Verified Webhooks:** Creates Stripe Checkout sessions for vendor Premium upgrades and activates Premium status + logs immutable transactions only upon verified `checkout.session.completed` webhook events.

## Technology Stack (NPM Packages)
- `express`
- `mongodb`
- `jsonwebtoken`
- `stripe`
- `cors`
- `dotenv`

## Environment Variables
Create a `.env` file in the root directory with the following variables:
```env
PORT=5000
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
STRIPE_SECRET_KEY=your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=your_stripe_webhook_secret
CLIENT_URL=[https://pizzahub-client-pi.vercel.app](https://pizzahub-client-pi.vercel.app)