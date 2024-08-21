const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const connectToDatabase = require('../models/db');
const router = express.Router();
const dotenv = require('dotenv');
const { check, validationResult } = require('express-validator');
const pino = require('pino');  // Import Pino logger
dotenv.config();

const logger = pino();  // Create a Pino logger instance

//Create JWT secret
dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', async (req, res) => {
    try {
        //Connect to `secondChance` in MongoDB through `connectToDatabase` in `db.js`.
        const db = await connectToDatabase();

        //Access the `users` collection
        const collection = db.collection("users");

        //Check for existing email in DB
        const existingEmail = await collection.findOne({ email: req.body.email });

        if (existingEmail) {
            logger.error('Email id already exists');
            return res.status(400).json({ error: 'Email id already exists' });
        }

        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);
        const email = req.body.email;

        //Save user details
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });

        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };

        //Create JWT
        const authtoken = jwt.sign(payload, JWT_SECRET);
        logger.info('User registered successfully');
        res.json({ authtoken, email });
    } catch (e) {
        logger.error(e);
        return res.status(500).send('Internal server error');
    }
});

//Login Endpoint
router.post('/login', async (req, res) => {
    console.log("\n\n Inside login")

    try {
        // connect to `secondChance` in MongoDB through `connectToDatabase`
        const db = await connectToDatabase();
        //Access MongoDB `users` collection
        const collection = db.collection("users");
        //Check for user credentials in database
        const theUser = await collection.findOne({ email: req.body.email });
        //Check if the password matches
        if (theUser) {
            let result = await bcryptjs.compare(req.body.password, theUser.password)
            //send appropriate message if mismatch
            if (!result) {
                logger.error('Passwords do not match');
                return res.status(404).json({ error: 'Wrong pasword' });
            }
            //Fetch user details
            let payload = {
                user: {
                    id: theUser._id.toString(),
                },
            };

            const userName = theUser.firstName;
            const userEmail = theUser.email;
            //Create JWT authentication if passwords match
            const authtoken = jwt.sign(payload, JWT_SECRET);
            logger.info('User logged in successfully');
            return res.status(200).json({ authtoken, userName, userEmail });
            //Send appropriate message if user not found
        } else {
            logger.error('User not found');
            return res.status(404).json({ error: 'User not found' });
        }
    } catch (e) {
        logger.error(e);
        return res.status(500).json({ error: 'Internal server error', details: e.message });
    }
});

// update API
router.put('/update',
    [
        check('name', 'Name is required').not().isEmpty(),  // Add validation for 'name' field
    ],
    async (req, res) => {
        // Task 2: Validate the input using `validationResult` and return approiate message if there is an error.
        const errors = validationResult(req);
        // Task 3: Check if `email` is present in the header and throw an appropriate error message if not present.
        if (!errors.isEmpty()) {
            logger.error('Validation errors in update request', errors.array());
            return res.status(400).json({ errors: errors.array() });
        }
        try {
            const email = req.headers.email;
            if (!email) {
                logger.error('Email not found in the request headers');
                return res.status(400).json({ error: "Email not found in the request headers" });
            }
            //Task 4: Connect to MongoDB
            const db = await connectToDatabase();
            const collection = db.collection("users");
            //Task 5: Find user credentials
            const existingUser = await collection.findOne({ email });
            if (!existingUser) {
                logger.error('User not found');
                return res.status(404).json({ error: "User not found" });
            }
            existingUser.firstName = req.body.name;
            existingUser.updatedAt = new Date();
            //Task 6: Update user credentials in DB
            const updatedUser = await collection.findOneAndUpdate(
                { email },
                { $set: existingUser },
                { returnDocument: 'after' }
            );
            //Task 7: Create JWT authentication with user._id as payload using secret key from .env file
            const payload = {
                user: {
                    id: updatedUser._id.toString(),
                },
            };
            const authtoken = jwt.sign(payload, JWT_SECRET);
            logger.info('User updated successfully');
            res.json({ authtoken });
        } catch (error) {
            logger.error(error);
            return res.status(500).send("Internal Server Error");
        }
    });

module.exports = router;