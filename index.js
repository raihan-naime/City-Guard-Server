require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const admin = require("firebase-admin");

// --- Configuration & Constants ---
const app = express();
const port = process.env.PORT || 5000;
const mongoUri = process.env.MONGO_URI;

// --- Middleware Setup ---
app.use(cors());
app.use(express.json());

// --- Firebase Admin Init ---
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  let serviceAccount;
  try {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  } catch (error) {
    // If parsing fails, assume it is a file path
    serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT;
  }

  try {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log("Firebase Admin initialized with service account");
  } catch (error) {
    console.error("Error initializing Firebase Admin:", error.message);
  }
} else {
  // Use default credentials or unauthenticated (development/fallback)
  try {
    admin.initializeApp();
    console.log("Firebase Admin initialized with default credentials");
  } catch (e) {
    console.log("Firebase default init failed", e.message);
  }
}

// --- Custom Middleware: Verify Token ---
const verifyToken = async (req, res, next) => {
  const token = req.headers?.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized access' });
  }

  try {
    // If admin is not initialized, this might throw
    if (!admin.apps.length) {
      return res.status(500).json({ message: 'Firebase not configured on server' });
    }

    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Token verification failed:', error);
    return res.status(403).json({ message: 'Forbidden access' });
  }
};



// --- MongoDB Connection & Server Start ---
let db;

async function run() {
  try {
    if (!mongoUri) {
      throw new Error("MONGO_URI is not defined in .env");
    }

    const client = new MongoClient(mongoUri, { 
      // useNewUrlParser and useUnifiedTopology are no longer needed in v4+, 
      // but keeping them doesn't hurt if using older driver versions.
      // v6.21.0 doesn't need them.
    });
    
    await client.connect();
     const db = client.db('City_Guard'); // Uses the database name from the connection string
    console.log('MongoDB Connected');

    // --- Collections ---
    const usersCollection = db.collection('users');
    const issuesCollection = db.collection('issues');
    const paymentsCollection = db.collection('payments');

    // --- Custom Middleware ---
    const verifyAdmin = async (req, res, next) => {
        const email = req.user.email;
        const user = await usersCollection.findOne({ email });
        const isAdmin = user?.role === 'admin';
        if (!isAdmin) {
            return res.status(403).json({ message: 'Forbidden access: Admin only' });
        }
        next();
    };
    // logic to verify staff or admin
    const verifyStaff = async (req, res, next) => {
        const email = req.user.email;
        const user = await usersCollection.findOne({ email });
        if (user?.role !== 'staff' && user?.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden access: Staff or Admin only' });
        }
        next();
    };

    // --- Routes ---

    // Root
    app.get('/', (req, res) => {
      res.send('CityGuard Server is Running');
    });

    // ===========================
    // USER ROUTES
    // ===========================

    // Sync User (Create or Update on login)
    app.post('/users/sync', async (req, res) => {
      try {
        const { email, name, photoURL } = req.body;
        // Check if user exists
        const existingUser = await usersCollection.findOne({ email });

        if (!existingUser) {
          // Create new user
          const newUser = {
            email,
            name,
            photoURL,
            role: 'citizen',
            createdAt: new Date()
          };
          const result = await usersCollection.insertOne(newUser);
          const insertedUser = await usersCollection.findOne({ _id: result.insertedId });
          return res.status(200).json(insertedUser);
        } else {
            // Optional: Update info if needed
             // await usersCollection.updateOne({ _id: existingUser._id }, { $set: { name, photoURL } });
             // const updated = await usersCollection.findOne({ _id: existingUser._id });
             return res.status(200).json(existingUser);
        }
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Get Current User Info
    app.get('/users/me', verifyToken, async (req, res) => {
      try {
        const user = await usersCollection.findOne({ email: req.user.email });
        if (!user) return res.status(404).json({ message: "User not found" });
        res.json(user);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Update User Profile
    app.put('/users/me', verifyToken, async (req, res) => {
        try {
            const { name, photoURL } = req.body;
            const updatedUser = await usersCollection.findOneAndUpdate(
                { email: req.user.email },
                { $set: { name, photoURL } },
                { returnDocument: 'after' }
            );
            res.json(updatedUser);
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Admin: Get all users
    app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const allUsers = await usersCollection.find({}).toArray();
        res.json(allUsers);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Admin: Make User Admin/Staff or Block
    // Corresponds to PATCH /users/:id/role
    app.patch('/users/:id/role', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { role } = req.body;
        const result = await usersCollection.findOneAndUpdate(
          { _id: new ObjectId(req.params.id) },
          { $set: { role } },
          { returnDocument: 'after' }
        );
        res.json(result);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Block/Unblock User
    app.patch('/users/:id/block', verifyToken, verifyAdmin, async (req, res) => {
        try {
            const { isBlocked } = req.body;
            const result = await usersCollection.findOneAndUpdate(
                { _id: new ObjectId(req.params.id) },
                { $set: { isBlocked } },
                { returnDocument: 'after' }
            );
            res.json(result);
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Create Staff (Admin only)
    app.post('/users/staff', verifyToken, verifyAdmin, async (req, res) => {
        try {
            const { email, password, name } = req.body;
            
            // Check requester role (Assuming middleware doesn't fully enforce admin yet)
            const requester = await usersCollection.findOne({ email: req.user.email });
            if (!requester || requester.role !== 'admin') {
                return res.status(403).json({ message: "Admin access required" });
            }

            // Create in Firebase
            await admin.auth().createUser({
                email,
                password,
                displayName: name,
            });

            // Create in DB
            const newUser = {
                email,
                name,
                role: 'staff',
                photoURL: "https://i.ibb.co/5GzXkwq/user.png",
                createdAt: new Date()
            };
            const result = await usersCollection.insertOne(newUser);
            const insertedUser = await usersCollection.findOne({ _id: result.insertedId });

            res.status(201).json(insertedUser);
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Delete User (Staff/Admin)
    app.delete('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
         try {
             // Delete from DB
             const user = await usersCollection.findOne({ _id: new ObjectId(req.params.id) });
             if(user) {
                 // Delete from Firebase
                 try {
                     const fbUser = await admin.auth().getUserByEmail(user.email);
                     await admin.auth().deleteUser(fbUser.uid);
                 } catch(e) {
                     console.log("Firebase user delete error or not found", e.message);
                 }
                 await usersCollection.deleteOne({ _id: new ObjectId(req.params.id) });
             }
             res.json({message: "User deleted"});
         } catch (error) {
             res.status(500).json({ message: error.message });
         }
    });

    // ===========================
    // ISSUE ROUTES
    // ===========================

    // Create Issue
    app.post('/issues', verifyToken, async (req, res) => {
        try {
            const user = await usersCollection.findOne({ email: req.user.email });
            if (!user) return res.status(404).json({ message: "User not found" });

            if (user.isBlocked) {
                return res.status(403).json({ message: "Account is blocked" });
            }

            // Check limits for free users
            if (user.subscriptionStatus === 'free') {
                 const issueCount = await issuesCollection.countDocuments({ author: user._id });
                 if (issueCount >= 3) {
                     return res.status(403).json({ message: "Free limit reached. Upgrade to Premium." });
                 }
            }
            // Construct issue object
            const newIssue = {
                ...req.body,
                author: user._id, // Storing ObjectId reference
                upvotes: [],
                upvoteCount: 0,
                status: 'pending', // Default status if not provided
                priority: 'normal',
                timeline: [{
                    status: 'pending',
                    message: 'Issue reported by citizen',
                    updatedBy: user.name,
                    date: new Date()
                }],
                createdAt: new Date()
            };
            console.log(newIssue);
            
            const result = await issuesCollection.insertOne(newIssue);
            const insertedIssue = await issuesCollection.findOne({ _id: result.insertedId });
            res.status(201).json(insertedIssue);
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Citizen Status
    app.get('/stats/citizen', verifyToken, async (req, res) => {
        try {
            const user = await usersCollection.findOne({ email: req.user.email });
            if (!user) return res.status(404).json({ message: "User not found" });

            const total = await issuesCollection.countDocuments({ author: user._id });
            const pending = await issuesCollection.countDocuments({ author: user._id, status: 'pending' });
            const inProgress = await issuesCollection.countDocuments({ 
                author: user._id, 
                status: { $in: ['in-progress', 'processing'] } 
            });
            const resolved = await issuesCollection.countDocuments({ author: user._id, status: 'resolved' });
            const paymentCount = await paymentsCollection.countDocuments({ user: user._id });

            res.json({
                total,
                pending,
                inProgress,
                resolved,
                paymentCount
            });
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Get All Issues
    app.get('/issues', async (req, res) => {
        try {
            const { search, category, status, priority, page = 1, limit = 10, boosted, author, assignedTo } = req.query;
            let query = {};

            // Search by title or location
            if (search) {
                query.$or = [
                    { title: { $regex: search, $options: 'i' } },
                    { location: { $regex: search, $options: 'i' } }
                ];
            }

            if (category) query.category = category;
            if (status) query.status = status;
            if (priority) query.priority = priority;
            
            if (author) { 
                 if(author.includes('@')){
                     const u = await usersCollection.findOne({email: author});
                     if(u) query.author = u._id;
                 } else {
                     try { query.author = new ObjectId(author); } catch(e) {}
                 }
            }
            if (assignedTo) {
                 if(assignedTo.includes('@')){
                     const u = await usersCollection.findOne({email: assignedTo});
                     if(u) query.assignedTo = u._id;
                 } else {
                    try { query.assignedTo = new ObjectId(assignedTo); } catch(e){}
                 }
            }

            const skip = (parseInt(page) - 1) * parseInt(limit);
            
            // Aggregation pipeline for Populate equivalent
            const pipeline = [
                { $match: query },
                // Default priority for old docs
                { $addFields: { priority: { $ifNull: ["$priority", "normal"] } } },
                // Sort
                { $sort: { priority: 1, createdAt: -1 } },
                // Pagination
                { $skip: skip },
                { $limit: parseInt(limit) },
                // Lookup Author
                {
                    $lookup: {
                        from: 'users',
                        localField: 'author',
                        foreignField: '_id',
                        as: 'authorDetails'
                    }
                },
                { $unwind: { path: '$authorDetails', preserveNullAndEmptyArrays: true } },
                // Lookup AssignedTo
                {
                    $lookup: {
                        from: 'users',
                        localField: 'assignedTo',
                        foreignField: '_id',
                        as: 'assignedToDetails'
                    }
                },
                { $unwind: { path: '$assignedToDetails', preserveNullAndEmptyArrays: true } },
                // Project fields (optional, to clean up)
                {
                    $addFields: {
                        author: { 
                             name: '$authorDetails.name', 
                             photoURL: '$authorDetails.photoURL',
                             _id: '$authorDetails._id'
                        },
                        assignedTo: {
                            name: '$assignedToDetails.name',
                            email: '$assignedToDetails.email',
                            photoURL: '$assignedToDetails.photoURL',
                            _id: '$assignedToDetails._id'
                        }
                    }
                },
                { $project: { authorDetails: 0, assignedToDetails: 0 } }
            ];

            const issues = await issuesCollection.aggregate(pipeline).toArray();
            const count = await issuesCollection.countDocuments(query);

            res.json({
                issues,
                totalPages: Math.ceil(count / limit),
                currentPage: parseInt(page)
            });
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: error.message });
        }
    });

    // Get Issue by ID with populated fields
    app.get('/issues/:id', async (req, res) => {
        try {
            const issueId = new ObjectId(req.params.id);
            const pipeline = [
                { $match: { _id: issueId } },
                {
                    $lookup: {
                        from: 'users',
                        localField: 'author',
                        foreignField: '_id',
                        as: 'authorDetails'
                    }
                },
                { $unwind: { path: '$authorDetails', preserveNullAndEmptyArrays: true } },
                {
                    $lookup: {
                        from: 'users',
                        localField: 'assignedTo',
                        foreignField: '_id',
                        as: 'assignedToDetails'
                    }
                },
                { $unwind: { path: '$assignedToDetails', preserveNullAndEmptyArrays: true } },
                {
                    $addFields: {
                        author: { 
                             name: '$authorDetails.name', 
                             photoURL: '$authorDetails.photoURL',
                             _id: '$authorDetails._id'
                        },
                        assignedTo: {
                            name: '$assignedToDetails.name',
                            email: '$assignedToDetails.email',
                            photoURL: '$assignedToDetails.photoURL',
                            _id: '$assignedToDetails._id'
                        }
                    }
                },
                { $project: { authorDetails: 0, assignedToDetails: 0 } }
            ];

            const result = await issuesCollection.aggregate(pipeline).toArray();
            const issue = result[0];

            if (!issue) return res.status(404).json({ message: "Issue not found" });
            res.json(issue);
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Update Issue Status
    app.patch('/issues/:id/status', verifyToken, verifyStaff, async (req, res) => {
        try {
            const { status } = req.body;
            const user = await usersCollection.findOne({ email: req.user.email });
            if (!user) return res.status(404).json({ message: "User not found" });

            if (user.role === 'citizen') return res.status(403).json({ message: "Access denied" });

            const issueId = new ObjectId(req.params.id);
            
            const updateDoc = {
                $set: { status },
                $push: {
                    timeline: {
                        status: status,
                        message: `Status updated to ${status}`,
                        updatedBy: user.name,
                        date: new Date()
                    }
                }
            };

            const result = await issuesCollection.findOneAndUpdate(
                { _id: issueId },
                updateDoc,
                { returnDocument: 'after' }
            );

            if (!result) return res.status(404).json({ message: "Issue not found" });
            res.json(result);
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Add Progress Update (Staff)
    app.post('/issues/:id/progress', verifyToken, verifyStaff, async (req, res) => {
        try {
            const { message } = req.body;
            const user = await usersCollection.findOne({ email: req.user.email });
            if (!user) return res.status(404).json({ message: "User not found" });

            const issueId = new ObjectId(req.params.id);
            const issue = await issuesCollection.findOne({ _id: issueId });
            if(!issue) return res.status(404).json({ message: "Issue not found" });
            
            const result = await issuesCollection.findOneAndUpdate(
                { _id: issueId },
                {
                    $push: {
                        timeline: {
                            status: issue.status, // Keep current status
                            message: message,
                            updatedBy: user.name,
                            date: new Date()
                        }
                    }
                },
                { returnDocument: 'after' }
            );

            res.json(result);
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Upvote Issue as Citizen
    app.patch('/issues/:id/upvote', verifyToken, async (req, res) => {
        try {
            const user = await usersCollection.findOne({ email: req.user.email });
            if (user.isBlocked) return res.status(403).json({ message: "Account is blocked" });
            const issueId = new ObjectId(req.params.id);
            const issue = await issuesCollection.findOne({ _id: issueId });

            if (!issue) return res.status(404).json({ message: "Issue not found" });

            // Check if user is author
            if (issue.author.toString() === user._id.toString()) {
                return res.status(400).json({ message: "Cannot upvote your own issue" });
            }

            // Check if already upvoted
            // Note: issue.upvotes might be array of ObjectIds or strings. 
            // In MongoDB, direct comparison works if types match. 
            // Assuming upvotes stores ObjectIds.
            const upvotes = issue.upvotes || [];
            const hasUpvoted = upvotes.find(id => id.toString() === user._id.toString());

            if (hasUpvoted) {
                return res.status(400).json({ message: "Already upvoted" });
            }

            const result = await issuesCollection.findOneAndUpdate(
                { _id: issueId },
                { 
                    $push: { upvotes: user._id },
                    $inc: { upvoteCount: 1 }
                },
                { returnDocument: 'after' }
            );

            res.json(result);
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Assign Staff
    app.patch('/issues/:id/assign', verifyToken, verifyAdmin, async (req, res) => {
        try {
            const { staffId } = req.body;
            console.log(`Assigning staff ${staffId} to issue ${req.params.id} by ${req.user.email}`);

            const user = await usersCollection.findOne({ email: req.user.email });
            // verifyAdmin middleware already checks this, but extra check is fine or remove it. 
            // Previous code had: if (user.role !== 'admin') return res.status(403).json({ message: "Admin only" });
            
            const staff = await usersCollection.findOne({ _id: new ObjectId(staffId) });
            if (!staff) {
                console.log("Staff not found");
                return res.status(400).json({ message: "Invalid staff ID" });
            }
            if (staff.role !== 'staff') {
                console.log(`User ${staff.email} is not staff.`);
                return res.status(400).json({ message: "User is not a staff member" });
            }

            const issueId = new ObjectId(req.params.id);
            const issue = await issuesCollection.findOne({ _id: issueId });
            
            if(!issue) return res.status(404).json({message: "Issue not found"});

            const result = await issuesCollection.findOneAndUpdate(
                { _id: issueId },
                {
                    $set: { assignedTo: staff._id },
                    $push: {
                        timeline: {
                            status: issue.status,
                            message: `Assigned to ${staff.name}`,
                            updatedBy: user.name,
                            date: new Date()
                        }
                    }
                },
                { returnDocument: 'after' }
            );
            res.json(result);
        } catch (error) {
            console.error("Assign error:", error);
            res.status(500).json({ message: error.message });
        }
    });

    // Delete Issue and its data (Author or Admin)
    app.delete('/issues/:id', verifyToken, async (req, res) => {
        try {
            const user = await usersCollection.findOne({ email: req.user.email });
            const issueId = new ObjectId(req.params.id);
            const issue = await issuesCollection.findOne({ _id: issueId });

            if (!issue) return res.status(404).json({ message: "Issue not found" });

            if (issue.author.toString() !== user._id.toString()) {
                if (user.role !== 'admin') return res.status(403).json({ message: "Access denied" });
            }

            await issuesCollection.deleteOne({ _id: issueId });
            res.json({ message: "Issue deleted" });
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Update Issue Details (Author only)
    app.put('/issues/:id', verifyToken, async (req, res) => {
        try {
            const { title, description, location, image } = req.body;
            const user = await usersCollection.findOne({ email: req.user.email });
            if (user.isBlocked) return res.status(403).json({ message: "Account is blocked" });
            const issueId = new ObjectId(req.params.id);
            const issue = await issuesCollection.findOne({ _id: issueId });

            if (!issue) return res.status(404).json({ message: "Issue not found" });

            if (issue.author.toString() !== user._id.toString()) {
                return res.status(403).json({ message: "Access denied" });
            }
            
            if (issue.status !== 'pending') {
                 return res.status(400).json({ message: "Cannot edit non-pending issues" });
            }

            const updateDoc = {
                $set: {
                    title, description, location, image
                }
            };

            const result = await issuesCollection.updateOne({ _id: issueId }, updateDoc);
            res.json(result);
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // ===========================
    // PAYMENT ROUTES
    // ===========================

    // Process Payment
    app.post('/payments', verifyToken, async (req, res) => {
        try {
            const { amount, purpose, issueId, paymentMethodId } = req.body;
            const user = await usersCollection.findOne({ email: req.user.email });
            if (!user) return res.status(404).json({ message: "User not found" });

            if (user.isBlocked) return res.status(403).json({ message: "Account is blocked" });

            const transactionId = `txn_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

            const payment = {
                user: user._id,
                amount,
                transactionId,
                purpose,
                issueId: issueId ? new ObjectId(issueId) : null,
                date: new Date()
            };

            await paymentsCollection.insertOne(payment);

            // Handle Post-Payment
            if (purpose === 'boost_issue' && issueId) {
                const iId = new ObjectId(issueId);
                const issue = await issuesCollection.findOne({ _id: iId });
                if (issue) {
                     await issuesCollection.updateOne(
                         { _id: iId },
                         { 
                             $set: { priority: 'high' },
                             $push: {
                                 timeline: {
                                    status: issue.status,
                                    message: 'Issue priority boosted to High',
                                    updatedBy: user.name,
                                    date: new Date()
                                 }
                             }
                         }
                     );
                }
            } else if (purpose === 'subscription') {
                await usersCollection.updateOne(
                    { _id: user._id },
                    { $set: { subscriptionStatus: 'premium' } }
                );
            }

            res.status(200).json({ success: true, payment, message: "Payment successful" });
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Create Payment Intent
    app.post('/create-payment-intent', verifyToken, async (req, res) => {
        try {
            const { price } = req.body;
            const amount = parseInt(price * 100); 
            
            // Ensure process.env.STRIPE_SECRET_KEY is defined
            if (!process.env.STRIPE_SECRET_KEY) {
                console.error("STRIPE_SECRET_KEY is missing!");
                return res.status(500).send({ message: "Server configuration error" });
            }

            const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

            const paymentIntent = await stripe.paymentIntents.create({
                amount: amount,
                currency: 'bdt', 
                payment_method_types: ['card']
            });
            
            console.log("Created PaymentIntent:", paymentIntent.id);

            res.send({
                clientSecret: paymentIntent.client_secret
            });


        } catch (error) {
             res.status(500).send({ message: error.message });
        }
    });

    // Get My Payments
    app.get('/payments/me', verifyToken, async (req, res) => {
        try {
            const user = await usersCollection.findOne({ email: req.user.email });
            if (!user) return res.status(404).json({ message: "User not found" });

            const myPayments = await paymentsCollection.find({ user: user._id }).sort({ date: -1 }).toArray();
            res.json(myPayments);
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Admin: Get All Payments
    app.get('/payments', verifyToken, verifyAdmin, async (req, res) => {
        try {
            const pipeline = [
                { $sort: { date: -1 } },
                {
                    $lookup: {
                        from: 'users',
                        localField: 'user',
                        foreignField: '_id',
                        as: 'userDetails'
                    }
                },
                { $unwind: { path: '$userDetails', preserveNullAndEmptyArrays: true } },
                {
                    $addFields: {
                        user: {
                            name: '$userDetails.name',
                            email: '$userDetails.email'
                        }
                    }
                },
                { $project: { userDetails: 0 } }
            ];
            
            const payments = await paymentsCollection.aggregate(pipeline).toArray();
            res.json(payments);
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Staff Stats
    app.get('/stats/staff', verifyToken, verifyStaff, async (req, res) => {
        try {
            const user = await usersCollection.findOne({ email: req.user.email });
            if (!user) return res.status(404).json({ message: "User not found" });


            const assignedIssues = await issuesCollection.find({ assignedTo: user._id }).toArray();
            
            const totalAssigned = assignedIssues.length;
            const resolvedCount = assignedIssues.filter(i => i.status === 'resolved').length;
            // Assuming "Today's Task" implies currently active items
            const todayTasks = assignedIssues.filter(i => i.status === 'pending' || i.status === 'in-progress').length;
            
            const statusDistribution = {
                pending: assignedIssues.filter(i => i.status === 'pending').length,
                inProgress: assignedIssues.filter(i => i.status === 'in-progress').length,
                resolved: assignedIssues.filter(i => i.status === 'resolved').length,
                closed: assignedIssues.filter(i => i.status === 'closed').length,
            };

            res.json({
                totalAssigned,
                resolvedCount,
                todayTasks,
                statusDistribution
            });
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    });

    // Confirm connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
    
    if (process.env.STRIPE_SECRET_KEY) {
        console.log("Stripe Secret Key loaded successfully.");
    } else {
        console.error("WARNING: STRIPE_SECRET_KEY is missing in .env!");
    }

  } finally {
    // await client.close();
  }
}
run().catch(console.dir);

// Root Endpoint
app.get('/', (req, res) => {
    res.send('CityGuard Server is running')
})

app.listen(port, () => {
    console.log(`CityGuard Server is running on port ${port}`);
})
