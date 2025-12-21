📁 Step 1: Clone the Repository
git clone <your-backend-repo-url>


Navigate into the backend folder:

cd server

📦 Step 2: Install Dependencies

Install all required npm packages listed in package.json:

npm install


This will install:

express

mongodb

cors

dotenv

firebase-admin

stripe

🔐 Step 3: Create Environment Variables

Create a .env file in the server root directory.

touch .env


Add the following environment variables (example):

PORT=5000
MONGODB_URI=your_mongodb_connection_string
STRIPE_SECRET_KEY=your_stripe_secret_key
FIREBASE_SERVICE_ACCOUNT=your_firebase_service_account_json


⚠️ Never commit .env files to GitHub

▶️ Step 4: Run the Backend Server
Production Mode
npm start


This runs:

node index.js

Development Mode (if applicable)
npm run dev


⚠️ Note: Your dev script runs npm run dev from the parent directory.
Make sure your root project has a dev script (usually with nodemon).

🌐 Step 5: Verify Server is Running

Once started, you should see something like:

Server running on port 5000
MongoDB connected successfully


Test the server in your browser or Postman:

http://localhost:5000

🧪 Step 6: Test API Endpoints

Use:

Postman

Thunder Client

Frontend client

Example:

GET http://localhost:5000/api/issues

📂 Project Scripts Explained
Script	Description
npm start	Runs server in production mode
npm run dev	Runs development server (from parent directory)
npm test	Placeholder test script
❗ Common Issues & Fixes

Port already in use

Change PORT value in .env


MongoDB connection error

Check MONGODB_URI in .env


Stripe error

Use STRIPE SECRET KEY (not publishable key)

🛑 Important Notes

Make sure index.js exists in the server root

.env must be loaded using require('dotenv').config()

Do not expose secret keys publicly
