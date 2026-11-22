const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { MongoClient, ObjectId } = require("mongodb");
require("dotenv").config();

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY || "sk_test_dummy");

const app = express();
const port = process.env.PORT || 5000;

// CORS Configuration
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      process.env.CLIENT_URL,
      /\.vercel\.app$/,
    ].filter(Boolean),
    credentials: true,
  })
);

// MongoDB Connection Setup (Serverless-safe)
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

let db;
let usersCollection;
let menuItemsCollection;
let ordersCollection;
let transactionsCollection;

async function connectDB() {
  if (!db) {
    await client.connect();
    db = client.db("pizzahub");
    usersCollection = db.collection("users");
    menuItemsCollection = db.collection("menuItems");
    ordersCollection = db.collection("orders");
    transactionsCollection = db.collection("transactions");
  }
}

// ==========================================
// STRIPE WEBHOOK (MUST BE BEFORE express.json)
// ==========================================
app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("Webhook signature verification failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      await connectDB();

      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        const vendorId = session.metadata?.vendorId;
        const vendorEmail = session.metadata?.vendorEmail;
        const vendorName = session.metadata?.vendorName || "Vendor";

        if (vendorEmail) {
          const expiresAt = new Date();
          expiresAt.setDate(expiresAt.getDate() + 30);

          // Upgrade vendor to Premium
          await usersCollection.updateOne(
            { email: vendorEmail },
            {
              $set: {
                subscriptionPlan: "premium",
                subscriptionExpiresAt: expiresAt,
              },
            }
          );

          // Update all menuItems of this vendor to reflect premium status
          await menuItemsCollection.updateMany(
            { vendorEmail },
            { $set: { vendorPlan: "premium" } }
          );

          // Save immutable transaction record
          const existingTx = await transactionsCollection.findOne({
            stripeSessionId: session.id,
          });

          if (!existingTx) {
            await transactionsCollection.insertOne({
              vendorId: vendorId || "",
              vendorName,
              vendorEmail,
              plan: "premium",
              amount: (session.amount_total || 1999) / 100,
              currency: (session.currency || "usd").toUpperCase(),
              stripeSessionId: session.id,
              stripeSubscriptionId: session.subscription || session.payment_intent || "",
              status: "succeeded",
              createdAt: new Date(),
            });
          }
        }
      }

      if (event.type === "customer.subscription.deleted") {
        const subscription = event.data.object;
        await usersCollection.updateOne(
          { stripeSubscriptionId: subscription.id },
          {
            $set: {
              subscriptionPlan: "free",
              subscriptionExpiresAt: null,
            },
          }
        );
      }

      res.json({ received: true });
    } catch (err) {
      console.error("Webhook processing error:", err);
      res.status(500).json({ message: "Webhook handler failed" });
    }
  }
);

// Standard JSON parser for all other routes
app.use(express.json());

// ==========================================
// JWT & ROLE-BASED SECURITY MIDDLEWARES
// ==========================================
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized: No token provided" });
  }
  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: "Unauthorized: Invalid or expired token" });
    }
    req.decoded = decoded;
    next();
  });
};

const verifyActiveUser = async (req, res, next) => {
  try {
    await connectDB();
    const user = await usersCollection.findOne({ email: req.decoded.email });
    if (!user) {
      return res.status(404).send({ message: "User record not found" });
    }
    if (user.isBlocked) {
      return res.status(403).send({ message: "Forbidden: Your account has been blocked by Admin" });
    }
    req.currentUser = user;
    next();
  } catch (error) {
    res.status(500).send({ message: "Server error verifying user" });
  }
};

const verifyRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.currentUser || !allowedRoles.includes(req.currentUser.role)) {
      return res.status(403).send({
        message: `Forbidden: Requires ${allowedRoles.join(" or ")} privileges`,
      });
    }
    next();
  };
};

// ==========================================
// HEALTH CHECK & JWT AUTH ENDPOINTS
// ==========================================
app.get("/", (req, res) => {
  res.send({ status: "ok", message: "PizzaHub Express Server is running!" });
});

// Sync user from Better Auth & Issue JWT Token
app.post("/auth/jwt", async (req, res) => {
  try {
    await connectDB();
    const { email, name, image, role, businessName } = req.body;
    if (!email) {
      return res.status(400).send({ message: "Email is required" });
    }

    let user = await usersCollection.findOne({ email });

    if (!user) {
      // Prevent public registration as admin
      const safeRole = role === "vendor" ? "vendor" : "customer";
      const newUser = {
        name: name || email.split("@")[0],
        email,
        image: image || "",
        role: safeRole,
        isBlocked: false,
        businessName: safeRole === "vendor" ? businessName || `${name || "Pizza"} Kitchen` : "",
        subscriptionPlan: "free",
        subscriptionExpiresAt: null,
        createdAt: new Date(),
      };
      const result = await usersCollection.insertOne(newUser);
      user = { _id: result.insertedId, ...newUser };
    }

    if (user.isBlocked) {
      return res.status(403).send({ message: "Your account is blocked. Contact support." });
    }

    const token = jwt.sign(
      {
        userId: user._id.toString(),
        email: user.email,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.send({ token, user });
  } catch (error) {
    console.error("JWT Error:", error);
    res.status(500).send({ message: "Failed to generate token", error: error.message });
  }
});

// Get Current Logged-in User Profile
app.get("/users/me", verifyToken, verifyActiveUser, async (req, res) => {
  res.send(req.currentUser);
});

// Update Own Profile (Cannot change role or subscriptionPlan)
app.patch("/users/me", verifyToken, verifyActiveUser, async (req, res) => {
  try {
    const { name, image, businessName } = req.body;
    const updateFields = {};
    if (name && name.trim()) updateFields.name = name.trim();
    if (image !== undefined) updateFields.image = image;
    if (req.currentUser.role === "vendor" && businessName !== undefined) {
      updateFields.businessName = businessName.trim();
    }

    await usersCollection.updateOne(
      { _id: req.currentUser._id },
      { $set: updateFields }
    );
    const updatedUser = await usersCollection.findOne({ _id: req.currentUser._id });
    res.send({ message: "Profile updated successfully", user: updatedUser });
  } catch (error) {
    res.status(500).send({ message: "Failed to update profile" });
  }
});

// ==========================================
// PUBLIC & VENDOR MENU ITEMS APIs
// ==========================================
// Get Approved & Active Menu Items (Public - Search, Filter, Sort)
app.get("/menu-items", async (req, res) => {
  try {
    await connectDB();
    const { search, category, location, sort, featured, limit } = req.query;
    const query = { status: "approved" };

    if (category && category !== "All") {
      query.category = category;
    }

    if (location && location.trim() !== "") {
      query.location = { $regex: location.trim(), $options: "i" };
    }

    if (search && search.trim() !== "") {
      query.$or = [
        { itemName: { $regex: search.trim(), $options: "i" } },
        { description: { $regex: search.trim(), $options: "i" } },
        { vendorName: { $regex: search.trim(), $options: "i" } },
      ];
    }

    let sortOption = { createdAt: -1 };
    if (featured === "true") {
      // Premium vendors get featured placement first
      sortOption = { vendorPlan: -1, createdAt: -1 };
    } else if (sort === "price_asc") {
      sortOption = { price: 1 };
    } else if (sort === "price_desc") {
      sortOption = { price: -1 };
    }

    let cursor = menuItemsCollection.find(query).sort(sortOption);
    if (limit) {
      cursor = cursor.limit(parseInt(limit));
    }

    const items = await cursor.toArray();
    res.send(items);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch menu items", error: error.message });
  }
});

// Get Single Menu Item Details (Protected for logged-in users)
app.get("/menu-items/:id", verifyToken, verifyActiveUser, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid menu item ID format" });
    }
    const item = await menuItemsCollection.findOne({ _id: new ObjectId(id) });
    if (!item) {
      return res.status(404).send({ message: "Menu item not found" });
    }
    res.send(item);
  } catch (error) {
    res.status(500).send({ message: "Error fetching menu item" });
  }
});

// Add Review & Rating to a Menu Item (Optional Feature)
app.post(
  "/menu-items/:id/reviews",
  verifyToken,
  verifyActiveUser,
  verifyRole("customer"),
  async (req, res) => {
    try {
      const id = req.params.id;
      const { rating, comment } = req.body;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: "Invalid item ID" });
      }
      if (!rating || rating < 1 || rating > 5) {
        return res.status(400).send({ message: "Rating must be between 1 and 5" });
      }

      const review = {
        userId: req.currentUser._id.toString(),
        userName: req.currentUser.name,
        userImage: req.currentUser.image || "",
        rating: Number(rating),
        comment: comment?.trim() || "",
        createdAt: new Date(),
      };

      await menuItemsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $push: { reviews: review } }
      );
      res.status(201).send({ message: "Review added successfully", review });
    } catch (error) {
      res.status(500).send({ message: "Failed to submit review" });
    }
  }
);

// Vendor: Get Own Menu Items
app.get(
  "/vendor/menu-items",
  verifyToken,
  verifyActiveUser,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const items = await menuItemsCollection
        .find({ vendorEmail: req.currentUser.email })
        .sort({ createdAt: -1 })
        .toArray();
      res.send(items);
    } catch (error) {
      res.status(500).send({ message: "Failed to fetch your menu items" });
    }
  }
);

// Vendor: Create Menu Item (Enforces Free Plan max 3 active/pending limit)
app.post(
  "/vendor/menu-items",
  verifyToken,
  verifyActiveUser,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const { itemName, category, description, price, location, images } = req.body;

      if (!itemName || !category || !description || !price || !location || !images?.length) {
        return res.status(400).send({ message: "All fields including item image are required" });
      }

      // Check subscription limit for free vendors
      if (req.currentUser.subscriptionPlan !== "premium") {
        const activeCount = await menuItemsCollection.countDocuments({
          vendorEmail: req.currentUser.email,
          status: { $in: ["approved", "pending"] },
        });
        if (activeCount >= 3) {
          return res.status(403).send({
            message: "Free plan limit reached (max 3 active/pending items). Upgrade to Premium for unlimited items!",
          });
        }
      }

      const newItem = {
        vendorId: req.currentUser._id.toString(),
        vendorName: req.currentUser.businessName || req.currentUser.name,
        vendorEmail: req.currentUser.email,
        vendorPlan: req.currentUser.subscriptionPlan || "free",
        itemName: itemName.trim(),
        category,
        description: description.trim(),
        price: parseFloat(price),
        location: location.trim(),
        images: Array.isArray(images) ? images : [images],
        status: "pending", // Requires admin approval
        reviews: [],
        createdAt: new Date(),
      };

      const result = await menuItemsCollection.insertOne(newItem);
      res.status(201).send({ message: "Menu item submitted for admin approval", insertedId: result.insertedId });
    } catch (error) {
      res.status(500).send({ message: "Failed to add menu item" });
    }
  }
);

// Vendor: Update Own Menu Item
app.patch(
  "/vendor/menu-items/:id",
  verifyToken,
  verifyActiveUser,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const id = req.params.id;
      if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid ID" });

      const item = await menuItemsCollection.findOne({ _id: new ObjectId(id) });
      if (!item) return res.status(404).send({ message: "Menu item not found" });

      if (item.vendorEmail !== req.currentUser.email) {
        return res.status(403).send({ message: "Forbidden: You do not own this menu item" });
      }

      const { itemName, category, description, price, location, images, status } = req.body;
      const updates = {};
      if (itemName) updates.itemName = itemName.trim();
      if (category) updates.category = category;
      if (description) updates.description = description.trim();
      if (price !== undefined) updates.price = parseFloat(price);
      if (location) updates.location = location.trim();
      if (images && images.length) updates.images = images;

      // Vendor can toggle between approved and inactive (if already approved)
      if (status && ["approved", "inactive"].includes(status) && ["approved", "inactive"].includes(item.status)) {
        updates.status = status;
      }

      await menuItemsCollection.updateOne({ _id: new ObjectId(id) }, { $set: updates });
      res.send({ message: "Menu item updated successfully" });
    } catch (error) {
      res.status(500).send({ message: "Failed to update menu item" });
    }
  }
);

// Vendor: Delete Own Menu Item
app.delete(
  "/vendor/menu-items/:id",
  verifyToken,
  verifyActiveUser,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const id = req.params.id;
      if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid ID" });

      const item = await menuItemsCollection.findOne({ _id: new ObjectId(id) });
      if (!item) return res.status(404).send({ message: "Menu item not found" });

      if (item.vendorEmail !== req.currentUser.email) {
        return res.status(403).send({ message: "Forbidden: You cannot delete another vendor's item" });
      }

      await menuItemsCollection.deleteOne({ _id: new ObjectId(id) });
      res.send({ message: "Menu item deleted successfully" });
    } catch (error) {
      res.status(500).send({ message: "Failed to delete menu item" });
    }
  }
);

// ==========================================
// ORDER MANAGEMENT APIs
// ==========================================
// Customer: Place New Order
app.post(
  "/orders",
  verifyToken,
  verifyActiveUser,
  verifyRole("customer"),
  async (req, res) => {
    try {
      const { itemId, deliveryDate, deliveryAddress, message } = req.body;

      if (!itemId || !deliveryDate || !deliveryAddress) {
        return res.status(400).send({ message: "Item ID, delivery date, and address are required" });
      }
      if (!ObjectId.isValid(itemId)) {
        return res.status(400).send({ message: "Invalid menu item ID" });
      }

      const menuItem = await menuItemsCollection.findOne({ _id: new ObjectId(itemId) });
      if (!menuItem || menuItem.status !== "approved") {
        return res.status(400).send({ message: "This menu item is not available for ordering" });
      }

      // Prevent ordering own item
      if (menuItem.vendorEmail === req.currentUser.email) {
        return res.status(403).send({ message: "You cannot order your own menu item" });
      }

      // Prevent duplicate active orders for same item and delivery date
      const duplicateOrder = await ordersCollection.findOne({
        customerEmail: req.currentUser.email,
        itemId: itemId,
        deliveryDate: deliveryDate,
        status: { $in: ["pending", "accepted"] },
      });

      if (duplicateOrder) {
        return res.status(400).send({
          message: "You already have an active order for this pizza on the selected delivery date!",
        });
      }

      const newOrder = {
        itemId: itemId,
        itemName: menuItem.itemName,
        itemImage: menuItem.images?.[0] || "",
        price: menuItem.price,
        vendorId: menuItem.vendorId,
        vendorName: menuItem.vendorName,
        vendorEmail: menuItem.vendorEmail,
        customerId: req.currentUser._id.toString(),
        customerName: req.currentUser.name,
        customerEmail: req.currentUser.email,
        deliveryDate,
        deliveryAddress: deliveryAddress.trim(),
        message: message?.trim() || "",
        status: "pending",
        createdAt: new Date(),
      };

      const result = await ordersCollection.insertOne(newOrder);
      res.status(201).send({ message: "Order placed successfully!", insertedId: result.insertedId });
    } catch (error) {
      res.status(500).send({ message: "Failed to place order" });
    }
  }
);

// Customer: Get My Orders
app.get(
  "/customer/orders",
  verifyToken,
  verifyActiveUser,
  verifyRole("customer"),
  async (req, res) => {
    try {
      const orders = await ordersCollection
        .find({ customerEmail: req.currentUser.email })
        .sort({ createdAt: -1 })
        .toArray();
      res.send(orders);
    } catch (error) {
      res.status(500).send({ message: "Failed to fetch orders" });
    }
  }
);

// Customer: Cancel Pending Order
app.patch(
  "/customer/orders/:id/cancel",
  verifyToken,
  verifyActiveUser,
  verifyRole("customer"),
  async (req, res) => {
    try {
      const id = req.params.id;
      if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid order ID" });

      const order = await ordersCollection.findOne({ _id: new ObjectId(id) });
      if (!order) return res.status(404).send({ message: "Order not found" });

      if (order.customerEmail !== req.currentUser.email) {
        return res.status(403).send({ message: "Forbidden: Not your order" });
      }

      if (order.status !== "pending") {
        return res.status(400).send({
          message: `Cannot cancel order because it is already ${order.status}`,
        });
      }

      await ordersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status: "cancelled" } }
      );
      res.send({ message: "Order cancelled successfully" });
    } catch (error) {
      res.status(500).send({ message: "Failed to cancel order" });
    }
  }
);

// Vendor: Get Customer Orders for My Items
app.get(
  "/vendor/orders",
  verifyToken,
  verifyActiveUser,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const orders = await ordersCollection
        .find({ vendorEmail: req.currentUser.email })
        .sort({ createdAt: -1 })
        .toArray();
      res.send(orders);
    } catch (error) {
      res.status(500).send({ message: "Failed to fetch customer orders" });
    }
  }
);

// Vendor: Accept or Reject Pending Order (Only once)
app.patch(
  "/vendor/orders/:id/status",
  verifyToken,
  verifyActiveUser,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const id = req.params.id;
      const { status } = req.body;

      if (!["accepted", "rejected"].includes(status)) {
        return res.status(400).send({ message: "Status must be accepted or rejected" });
      }
      if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid order ID" });

      const order = await ordersCollection.findOne({ _id: new ObjectId(id) });
      if (!order) return res.status(404).send({ message: "Order not found" });

      if (order.vendorEmail !== req.currentUser.email) {
        return res.status(403).send({ message: "Forbidden: This order belongs to another vendor" });
      }

      if (order.status !== "pending") {
        return res.status(400).send({
          message: `Order status is already ${order.status} and cannot be changed again`,
        });
      }

      await ordersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status } }
      );
      res.send({ message: `Order ${status} successfully` });
    } catch (error) {
      res.status(500).send({ message: "Failed to update order status" });
    }
  }
);

// ==========================================
// STRIPE CHECKOUT SESSION (VENDOR PREMIUM)
// ==========================================
app.post(
  "/create-checkout-session",
  verifyToken,
  verifyActiveUser,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      if (req.currentUser.subscriptionPlan === "premium") {
        return res.status(400).send({ message: "You are already on the Premium plan!" });
      }

      const clientUrl = process.env.CLIENT_URL || "http://localhost:3000";

      const session = await stripe.checkout.sessions.create({
        //payment_method_types: ["card"],
        mode: "payment",
        customer_email: req.currentUser.email,
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: "PizzaHub Vendor Premium Subscription",
                description:
                  "Unlimited active menu items, Premium vendor badge, and featured homepage placement.",
              },
              unit_amount: 1999, // $19.99
            },
            quantity: 1,
          },
        ],
        metadata: {
          vendorId: req.currentUser._id.toString(),
          vendorEmail: req.currentUser.email,
          vendorName: req.currentUser.businessName || req.currentUser.name,
        },
        success_url: `${clientUrl}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${clientUrl}/payment/cancel`,
      });

      res.send({ url: session.url });
    } catch (error) {
      console.error("Stripe Checkout Error:", error);
      res.status(500).send({ message: "Failed to create Stripe checkout session", error: error.message });
    }
  }
);

// ==========================================
// ADMIN MANAGEMENT APIs
// ==========================================
// Admin: Dashboard Overview Stats
app.get(
  "/admin/stats",
  verifyToken,
  verifyActiveUser,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const [
        totalUsers,
        totalVendors,
        totalCustomers,
        totalMenuItems,
        pendingMenuItems,
        totalTransactions,
        transactions,
      ] = await Promise.all([
        usersCollection.countDocuments(),
        usersCollection.countDocuments({ role: "vendor" }),
        usersCollection.countDocuments({ role: "customer" }),
        menuItemsCollection.countDocuments(),
        menuItemsCollection.countDocuments({ status: "pending" }),
        transactionsCollection.countDocuments(),
        transactionsCollection.find().toArray(),
      ]);

      const totalRevenue = transactions.reduce((sum, tx) => sum + (tx.amount || 0), 0);

      res.send({
        totalUsers,
        totalVendors,
        totalCustomers,
        totalMenuItems,
        pendingMenuItems,
        totalTransactions,
        totalRevenue,
      });
    } catch (error) {
      res.status(500).send({ message: "Failed to load admin stats" });
    }
  }
);

// Admin: Get All Users (Search & Role Filter)
app.get(
  "/admin/users",
  verifyToken,
  verifyActiveUser,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const { search, role } = req.query;
      const query = {};
      if (role && role !== "all") {
        query.role = role;
      }
      if (search && search.trim()) {
        query.$or = [
          { name: { $regex: search.trim(), $options: "i" } },
          { email: { $regex: search.trim(), $options: "i" } },
        ];
      }

      const users = await usersCollection.find(query).sort({ createdAt: -1 }).toArray();
      res.send(users);
    } catch (error) {
      res.status(500).send({ message: "Failed to fetch users" });
    }
  }
);

// Admin: Block or Unblock User
app.patch(
  "/admin/users/:id/block",
  verifyToken,
  verifyActiveUser,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const id = req.params.id;
      const { isBlocked } = req.body;
      if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid user ID" });

      if (id === req.currentUser._id.toString()) {
        return res.status(400).send({ message: "Admin cannot block themselves" });
      }

      await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { isBlocked: Boolean(isBlocked) } }
      );
      res.send({ message: isBlocked ? "User blocked successfully" : "User unblocked successfully" });
    } catch (error) {
      res.status(500).send({ message: "Failed to update user status" });
    }
  }
);

// Admin: Get All Submitted Menu Items
app.get(
  "/admin/menu-items",
  verifyToken,
  verifyActiveUser,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const { search, status } = req.query;
      const query = {};
      if (status && status !== "all") {
        query.status = status;
      }
      if (search && search.trim()) {
        query.$or = [
          { itemName: { $regex: search.trim(), $options: "i" } },
          { vendorName: { $regex: search.trim(), $options: "i" } },
        ];
      }

      const items = await menuItemsCollection.find(query).sort({ createdAt: -1 }).toArray();
      res.send(items);
    } catch (error) {
      res.status(500).send({ message: "Failed to fetch menu items" });
    }
  }
);

// Admin: Approve, Reject, or Change Status of Menu Item
app.patch(
  "/admin/menu-items/:id/status",
  verifyToken,
  verifyActiveUser,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const id = req.params.id;
      const { status } = req.body;
      if (!["approved", "rejected", "pending", "inactive"].includes(status)) {
        return res.status(400).send({ message: "Invalid status value" });
      }
      if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid ID" });

      await menuItemsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status } }
      );
      res.send({ message: `Menu item marked as ${status}` });
    } catch (error) {
      res.status(500).send({ message: "Failed to update item status" });
    }
  }
);

// Admin: Delete Inappropriate Menu Item
app.delete(
  "/admin/menu-items/:id",
  verifyToken,
  verifyActiveUser,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const id = req.params.id;
      if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid ID" });

      await menuItemsCollection.deleteOne({ _id: new ObjectId(id) });
      res.send({ message: "Menu item deleted by admin" });
    } catch (error) {
      res.status(500).send({ message: "Failed to delete item" });
    }
  }
);

// Admin: View All Transactions (Read-Only - No edit/delete endpoints exist)
app.get(
  "/admin/transactions",
  verifyToken,
  verifyActiveUser,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const transactions = await transactionsCollection
        .find()
        .sort({ createdAt: -1 })
        .toArray();
      res.send(transactions);
    } catch (error) {
      res.status(500).send({ message: "Failed to fetch transactions" });
    }
  }
);

app.listen(port, () => {
  console.log(`PizzaHub server running on port ${port}`);
});

module.exports = app;