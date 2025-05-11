import dotenv from 'dotenv';
import express from 'express';
import multer from 'multer';
import crypto from 'crypto';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { Blockfrost, Lucid, Data, toHex, Constr} from 'lucid-cardano';
import { BlockFrostAPI } from '@blockfrost/blockfrost-js';
import NodeCache from 'node-cache';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import * as Cardano from '@emurgo/cardano-serialization-lib-nodejs';
import winston from 'winston';
import { createLogger, format, transports } from 'winston';
import rateLimit from 'express-rate-limit';
import { logger, stream } from './config/logger.js';
import escrow from './utils/escrowContract.js';
import { getAikenScriptAddress,getAikenScript } from './utils/escrowContract.js';

// Custom API Error class
class APIError extends Error {
    constructor(message, statusCode, code, details = {}) {
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.details = details;
        this.name = 'APIError';
    }
}

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// IMPORTANT: First check if the .env file exists in the expected location
const envPath = path.join(__dirname, '.env');
console.log(`Checking for .env file at: ${envPath}`);
const envFileExists = fs.existsSync(envPath);
console.log(`.env file exists: ${envFileExists}`);

// If file doesn't exist, show where the process is running from
if (!envFileExists) {
  console.log('Current working directory:', process.cwd());
  console.log('__dirname:', __dirname);
  console.log('Looking for .env file in parent directory...');
  
  // Check parent directory
  const parentEnvPath = path.join(__dirname, '..', '.env');
  const parentEnvExists = fs.existsSync(parentEnvPath);
  console.log(`.env file in parent directory exists: ${parentEnvExists}`);
}

// Step 2: Load environment variables with explicit path
// This ensures dotenv looks in the right place
const result = dotenv.config({ path: envPath });

// Step 3: Check if dotenv loaded successfully
if (result.error) {
  console.error('Error loading .env file:', result.error);
} else {
  console.log('.env file loaded successfully');
}

// Step 4: Print loaded environment variables
console.log('Environment variables after loading:', {
  NODE_ENV: process.env.NODE_ENV || 'not set',
  CARDANO_NETWORK: process.env.CARDANO_NETWORK || 'not set',
  BLOCKFROST_API_KEY: process.env.BLOCKFROST_API_KEY ? 'exists' : 'missing',
  CARDANO_SEED_PHRASE: process.env.CARDANO_SEED_PHRASE ? 'exists' : 'missing',
  JWT_SECRET: process.env.JWT_SECRET ? 'exists' : 'missing'
});

// Step 5: If variables are still missing, create a temporary .env file for testing
if (!process.env.BLOCKFROST_API_KEY || !process.env.CARDANO_SEED_PHRASE) {
  console.log('Creating temporary .env file for testing...');
  
  // Create minimal .env file for testing
  const tempEnvContent = `
NODE_ENV=development
CARDANO_NETWORK=preview
BLOCKFROST_API_KEY=temp_key_for_testing
CARDANO_SEED_PHRASE=temp_phrase_for_testing
JWT_SECRET=temp_secret_for_testing
  `.trim();
  
  fs.writeFileSync(envPath, tempEnvContent);
  console.log('Temporary .env file created at:', envPath);
  
  // Reload with the new file
  dotenv.config({ path: envPath });
  
  // Verify the variables are now available
  console.log('Environment variables after creating test file:', {
    NODE_ENV: process.env.NODE_ENV || 'not set',
    CARDANO_NETWORK: process.env.CARDANO_NETWORK || 'not set',
    BLOCKFROST_API_KEY: process.env.BLOCKFROST_API_KEY ? 'exists' : 'missing',
    CARDANO_SEED_PHRASE: process.env.CARDANO_SEED_PHRASE ? 'exists' : 'missing',
    JWT_SECRET: process.env.JWT_SECRET ? 'exists' : 'missing'
  });
}

// Custom metadata label for document verification
const METADATA_LABEL = '9876549875324532'; // Custom label for document verification

const app = express();
const port = process.env.PORT || 3000;

// Initialize cache with TTL of 1 hour (3600 seconds)
const verificationCache = new NodeCache({ stdTTL: 3600 });
const metadataCache = new NodeCache({ stdTTL: 300 }); // 5 minutes cache for metadata

// Global variables for transaction tracking
let lastKnownTransactionId = null;
let hashRegistry = {}; // In-memory hash registry for quick lookups

// Initialize Lucid with seed phrase
let lucid;
let blockfrost;
async function initializeLucid() {
    try {
        // Check for required environment variables
        if (!process.env.BLOCKFROST_API_KEY) {
            throw new Error('BLOCKFROST_API_KEY environment variable is not set');
        }
        if (!process.env.CARDANO_SEED_PHRASE) {
            throw new Error('CARDANO_SEED_PHRASE environment variable is not set');
        }

        console.log('Initializing Blockfrost API...');
        console.log('API Key exists:', !!process.env.BLOCKFROST_API_KEY);
        console.log('Network:', process.env.CARDANO_NETWORK || 'preview');

        // Initialize Blockfrost API
        blockfrost = new BlockFrostAPI({
            projectId: process.env.BLOCKFROST_API_KEY,
            network: process.env.CARDANO_NETWORK || 'preview'
        });

        // Validate that the API key works by making a test request
        try {
            const health = await blockfrost.health();
            console.log('Blockfrost API health:', health);
            
            // Test the API key with a simple request
            const latestBlock = await blockfrost.blocksLatest();
            console.log('Latest block:', latestBlock.height, 'Slot:', latestBlock.slot);
            console.log('Blockfrost API key validation successful');
        } catch (apiError) {
            console.error('Blockfrost API key validation failed:', apiError);
            throw new Error('Blockfrost API key validation failed: ' + (apiError.message || 'Unknown error'));
        }

        // Initialize Lucid with Blockfrost provider
        console.log('Initializing Lucid with Blockfrost provider...');
        lucid = await Lucid.new(
            new Blockfrost(
                process.env.CARDANO_NETWORK === 'mainnet' 
                    ? "https://cardano-mainnet.blockfrost.io/api/v0"
                    : "https://cardano-preview.blockfrost.io/api/v0",
                process.env.BLOCKFROST_API_KEY
            ),
            process.env.CARDANO_NETWORK === 'mainnet' ? "Mainnet" : "Preview"
        );
        console.log('Lucid initialized successfully');

        // Load seed phrase from environment variable
        const seedPhrase = process.env.CARDANO_SEED_PHRASE;
        if (!seedPhrase) {
            throw new Error('CARDANO_SEED_PHRASE environment variable is not set');
        }

        // Select wallet using seed phrase
        await lucid.selectWalletFromSeed(seedPhrase);
       
        // Verify wallet connection by checking address and UTXOs
        const address = await lucid.wallet.address();
        const utxos = await lucid.wallet.getUtxos();
        console.log('Connected to wallet');
        console.log('Wallet address:', address);
        console.log('Wallet UTXOs count:', utxos.length);
        
        // Initial population of the hash registry
        await populateHashRegistry();
    } catch (error) {
        console.error('Error initializing Lucid:', error);
        throw new Error('Failed to initialize wallet connection: ' + error.message);
    }
}

// Function to populate the hash registry from blockchain
async function populateHashRegistry() {
    try {
        console.log('Populating hash registry from blockchain...');
        const transactions = await blockfrost.metadataTxsLabel(METADATA_LABEL, { 
            count: 100, // Get more transactions at once
            page: 1 
        });
        
        let count = 0;
        for (const tx of transactions) {
            const txId = tx.tx_hash;
            const metadata = await blockfrost.txsMetadata(txId);
            
            if (metadata && metadata[METADATA_LABEL] && metadata[METADATA_LABEL].hash) {
                const hash = metadata[METADATA_LABEL].hash;
                hashRegistry[hash] = {
                    timestamp: metadata[METADATA_LABEL].timestamp,
                    type: metadata[METADATA_LABEL].type,
                    student: metadata[METADATA_LABEL].student,
                    txId: txId,
                    blockTime: tx.block_time ? new Date(tx.block_time * 1000).toISOString() : null
                };
                count++;
            }
            
            // Update last known transaction ID
            lastKnownTransactionId = txId;
        }
        
        console.log(`Hash registry populated with ${count} entries`);
    } catch (error) {
        console.error('Error populating hash registry:', error);
    }
}

// Function to update hash registry with new transactions
async function updateHashRegistry() {
    try {
        if (!lastKnownTransactionId) {
            await populateHashRegistry();
            return;
        }
        
        console.log('Checking for new transactions since:', lastKnownTransactionId);
        
        // Get new transactions since last known
        const newTransactions = await blockfrost.metadataTxsLabel(METADATA_LABEL, { 
            count: 50,
            page: 1 
        });
        
        let foundLastKnown = false;
        let count = 0;
        
        for (const tx of newTransactions) {
            const txId = tx.tx_hash;
            
            // Skip until we find the last known transaction
            if (txId === lastKnownTransactionId) {
                foundLastKnown = true;
                continue;
            }
            
            if (!foundLastKnown && newTransactions.length < 50) {
                // If we can't find the last known, it might be too old - update completely
                await populateHashRegistry();
                return;
            }
            
            if (foundLastKnown || newTransactions.length < 50) {
                const metadata = await blockfrost.txsMetadata(txId);
                
                if (metadata && metadata[METADATA_LABEL] && metadata[METADATA_LABEL].hash) {
                    const hash = metadata[METADATA_LABEL].hash;
                    hashRegistry[hash] = {
                        timestamp: metadata[METADATA_LABEL].timestamp,
                        type: metadata[METADATA_LABEL].type,
                        student: metadata[METADATA_LABEL].student,
                        txId: txId,
                        blockTime: tx.block_time ? new Date(tx.block_time * 1000).toISOString() : null
                    };
                    count++;
                }
                
                // Update last known transaction ID
                lastKnownTransactionId = txId;
            }
        }
        
        if (count > 0) {
            console.log(`Hash registry updated with ${count} new entries`);
        } else {
            console.log('No new entries added to hash registry');
        }
    } catch (error) {
        console.error('Error updating hash registry:', error);
    }
}

// Schedule regular updates to the hash registry (every 5 minutes)
setInterval(updateHashRegistry, 5 * 60 * 1000);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'uploads';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage: storage });

// Helper function to calculate SHA-256 hash
function calculateHash(filePath) {
    const fileBuffer = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(fileBuffer).digest('hex');
}

// Helper function to store hash on Cardano
async function storeHashOnCardano(hash, metadata) {
    try {
        if (!lucid) {
            throw new Error('Lucid not initialized');
        }

        // Create metadata object with custom label
        const metadataObj = {
            [METADATA_LABEL]: {
                'hash': hash,
                'timestamp': Math.floor(Date.now() / 1000),
                'type': metadata.documentType,
                'student': metadata.studentName
            }
        };

        // Create and sign transaction using Lucid
        const tx = await lucid
            .newTx()
            .attachMetadata(METADATA_LABEL, metadataObj)
            .complete();

        // Sign the transaction with private key
        const signedTx = await tx.sign().complete();

        // Submit the signed transaction
        const txHash = await signedTx.submit();
        
        // Add to local hash registry immediately
        hashRegistry[hash] = {
            timestamp: Math.floor(Date.now() / 1000),
            type: metadata.documentType,
            student: metadata.studentName,
            txId: txHash,
            blockTime: new Date().toISOString()
        };
        
        return { tx_hash: txHash };
    } catch (error) {
        if (error.status_code === 425) {
            console.error('Mempool is full. Please retry in a few seconds.');
            throw new Error('Network is busy. Please try again in a few seconds.');
        } else if (error.status_code === 403) {
            console.error('Network token mismatch. Please check your API key.');
            throw new Error('Invalid API configuration. Please contact support.');
        }
        console.error('Error storing hash on Cardano:', error);
        throw new Error('Failed to store hash on blockchain');
    }
}

// Optimized helper function to verify hash on Cardano
async function verifyHashOnCardano(hash) {
    try {
        // Check cache first
        const cachedResult = verificationCache.get(hash);
        if (cachedResult) {
            console.log(`✅ Hash found in cache`);
            return cachedResult;
        }

        console.log(`Searching for hash: ${hash}`);
        
        // Check in-memory registry first (much faster)
        if (hashRegistry[hash]) {
            const result = {
                found: true,
                timestamp: hashRegistry[hash].timestamp,
                type: hashRegistry[hash].type,
                student: hashRegistry[hash].student,
                txId: hashRegistry[hash].txId,
                blockTime: hashRegistry[hash].blockTime
            };
            
            // Cache the result
            verificationCache.set(hash, result);
            
            console.log(`✅ Hash verified through in-memory registry!`);
            return result;
        }

        // If we have a lastKnownTransactionId, check that specific transaction first
        if (lastKnownTransactionId) {
            console.log(`Checking specific transaction: ${lastKnownTransactionId}`);
            const metadata = await blockfrost.txsMetadata(lastKnownTransactionId);
            
            // Debug logging
            console.log('Transaction metadata:', JSON.stringify(metadata, null, 2));
            console.log('Looking for hash:', hash);
            console.log('Metadata label:', METADATA_LABEL);
            
            // Find the metadata entry for our label
            const metadataEntry = metadata.find(entry => entry.label === METADATA_LABEL);
            if (metadataEntry && metadataEntry.json_metadata && metadataEntry.json_metadata[METADATA_LABEL]) {
                const docMetadata = metadataEntry.json_metadata[METADATA_LABEL];
                console.log('Found metadata for our label:', JSON.stringify(docMetadata, null, 2));
                console.log('Metadata hash:', docMetadata.hash);
                console.log('Hash match:', docMetadata.hash === hash);
                
                if (docMetadata.hash === hash) {
                    const result = {
                        found: true,
                        timestamp: docMetadata.timestamp,
                        type: docMetadata.type,
                        student: docMetadata.student,
                        txId: lastKnownTransactionId,
                        blockTime: new Date().toISOString()
                    };
                    
                    // Update our registry with this hash
                    hashRegistry[hash] = {
                        timestamp: docMetadata.timestamp,
                        type: docMetadata.type,
                        student: docMetadata.student,
                        txId: lastKnownTransactionId,
                        blockTime: new Date().toISOString()
                    };
                    
                    // Cache the result
                    verificationCache.set(hash, result);
                    
                    console.log(`✅ Hash verified in specific transaction!`);
                    return result;
                }
            } else {
                console.log('No metadata found for our label');
            }
        }
        
        // If not found in specific transaction, check if we need to update our registry
        await updateHashRegistry();
        
        // Check registry again after update
        if (hashRegistry[hash]) {
            const result = {
                found: true,
                timestamp: hashRegistry[hash].timestamp,
                type: hashRegistry[hash].type,
                student: hashRegistry[hash].student,
                txId: hashRegistry[hash].txId,
                blockTime: hashRegistry[hash].blockTime
            };
            
            // Cache the result
            verificationCache.set(hash, result);
            
            console.log(`✅ Hash verified through updated registry!`);
            return result;
        }
        
        return { found: false };
    } catch (error) {
        console.error('Error verifying hash on Cardano:', error);
        throw error;
    }
}

// Email templates
const emailTemplates = {
    verification: (token) => ({
        subject: 'Verify your email address',
        html: `
            <h1>Welcome to Student Verification System</h1>
            <p>Please click the link below to verify your email address:</p>
            <a href="${process.env.FRONTEND_URL}/verify-email?token=${token}">Verify Email</a>
            <p>This link will expire in 24 hours.</p>
        `
    }),
    passwordReset: (token) => ({
        subject: 'Reset your password',
        html: `
            <h1>Password Reset Request</h1>
            <p>Click the link below to reset your password:</p>
            <a href="${process.env.FRONTEND_URL}/reset-password?token=${token}">Reset Password</a>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this, please ignore this email.</p>
        `
    })
};

// Initialize user storage
const users = new Map();
const userProfiles = new Map();
const tasks = new Map(); // Initialize tasks storage

// Add default development profiles
if (process.env.NODE_ENV === 'development') {
    const devUser = {
        id: 'dev-student',
        email: 'dev@example.com',
        firstName: 'Akeem',
        lastName: 'Adetunji',
        role: 'student',
        cardanoAddress: 'addr_test1qrk47v4t4xlywf3eh8ae7s54s354k86c6rh8mu8utzm22ky28mcycq87r9qef4gdm8555ft8valqhxkgx3uypyt0v3lqsmpkfu'
    };
    
    const devClient = {
        id: 'dev-client',
        email: 'client@example.com',
        firstName: 'John',
        lastName: 'Doe',
        role: 'client',
        cardanoAddress: 'addr_test1qrk47v4t4xlywf3eh8ae7s54s354k86c6rh8mu8utzm22ky28mcycq87r9qef4gdm8555ft8valqhxkgx3uypyt0v3lqsmpkfu'
    };

    // Add to users Map
    users.set('dev-student', devUser);
    users.set('dev-client', devClient);

    // Add to userProfiles Map
    userProfiles.set('dev-student', {
        ...devUser,
        university: 'Test University',
        studentId: 'DEV123',
        skills: ['JavaScript', 'Python', 'Cardano'],
        createdAt: new Date().toISOString()
    });

    userProfiles.set('dev-client', {
        ...devClient,
        organization: 'Test Organization',
        position: 'Project Manager',
        createdAt: new Date().toISOString()
    });
}

// Enhanced user storage with verification status
const verificationTokens = new Map();
const passwordResetTokens = new Map();

// Generate secure random token
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Simple JWT authentication middleware
const authenticateToken = (req, res, next) => {
    // Skip authentication in development mode
    if (process.env.NODE_ENV === 'development') {
        // Detect if this is a client or student dashboard/API call
        // For now, always set to dev-client for client dashboard testing
        req.user = {
            id: 'dev-client',
            role: 'client',
            firstName: 'John',
            lastName: 'Doe'
        };
        return next();
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Simple registration endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, firstName, lastName, role, walletAddress } = req.body;

        // Log the received data (excluding password)
        console.log('Registration attempt:', {
            email,
            firstName,
            lastName,
            role,
            walletAddress,
            hasPassword: !!password
        });

        // Basic validation with specific error messages
        const missingFields = [];
        if (!email) missingFields.push('email');
        if (!password) missingFields.push('password');
        if (!firstName) missingFields.push('firstName');
        if (!lastName) missingFields.push('lastName');
        if (!role) missingFields.push('role');
        if (!walletAddress) missingFields.push('walletAddress');

        if (missingFields.length > 0) {
            console.log('Missing required fields:', missingFields);
            return res.status(400).json({ 
                error: 'Missing required fields',
                details: missingFields,
                message: `Please provide: ${missingFields.join(', ')}`
            });
        }

        // Validate wallet address format
        if (!walletAddress.match(/^(addr|addr_test1)[0-9a-zA-Z]{98,}$/)) {
            console.log('Invalid wallet address format:', walletAddress);
            return res.status(400).json({ 
                error: 'Invalid wallet address format',
                message: 'Please enter a valid Cardano wallet address (mainnet or testnet)'
            });
        }

        // Check if email exists
        if (users.has(email)) {
            console.log('Email already registered:', email);
            return res.status(400).json({ 
                error: 'Email already registered',
                message: 'This email address is already in use'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = {
            email,
            password: hashedPassword,
            firstName,
            lastName,
            role,
            walletAddress,
            createdAt: new Date().toISOString()
        };

        // Store user
        users.set(email, user);

        // Generate JWT token
        const token = jwt.sign(
            { email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'Registration successful',
            token,
            user: {
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                role: user.role,
                walletAddress: user.walletAddress
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Simple login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Basic validation
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        // Find user
        const user = users.get(email);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Protected route example
app.get('/api/user/profile', authenticateToken, (req, res) => {
    const user = users.get(req.user.email);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    res.json({
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role
    });
});

// Initialize Lucid when server starts
initializeLucid().catch(console.error);

// ==========================================
// Certificate Verification System (betaedu)
// ==========================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/verify-certificate', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'verify.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ==========================================
// Student Freelance Platform Routes
// ==========================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Role-based middleware
const requireRole = (role) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        if (req.user.role !== role) {
            return res.status(403).json({ error: 'Unauthorized access' });
        }
        next();
    };
};

// Update client dashboard route to require authentication and client role
app.get('/client-dashboard', authenticateToken, requireRole('client'), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'client-dashboard.html'));
});

app.get('/student-dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'student-dashboard.html'));
});

// Serve static files
app.use(express.static('public'));

// ==========================================
// API Routes for Freelance Platform
// ==========================================
app.post('/api/register', async (req, res) => {
    try {
        const { fullName, email, password, type, cardanoAddress, university, studentId, skills, organization, position } = req.body;
        
        // Check if email already exists
        const existingUser = Array.from(users.values()).find(u => u.email === email);
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user object
        const user = {
            id: Date.now().toString(),
            username: fullName,
            email,
            password: hashedPassword,
            role: type || 'student',
            cardanoAddress,
            profile: {
                university,
                studentId,
                skills,
                organization,
                position
            }
        };
        
        // Store user
        users.set(user.id, user);
        
        // Create user profile
        const profile = {
            userId: user.id,
            fullName,
            email,
            type,
            cardanoAddress,
            university,
            studentId,
            skills,
            organization,
            position,
            createdAt: new Date().toISOString()
        };
        userProfiles.set(user.id, profile);
        
        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ 
            token, 
            user: { 
                id: user.id, 
                username: user.username, 
                email: user.email, 
                role: user.role,
                type: user.role,
                cardanoAddress: user.cardanoAddress
            } 
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find user (in a real app, this would query a database)
        const user = Array.from(users.values()).find(u => u.email === email);
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ 
            token, 
            user: { 
                id: user.id, 
                username: user.username, 
                email: user.email, 
                role: user.role,
                cardanoAddress: user.cardanoAddress 
            } 
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Protected routes
app.get('/api/user', authenticateToken, (req, res) => {
    const user = users.get(req.user.id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    res.json({ 
        id: user.id, 
        username: user.username, 
        email: user.email, 
        role: user.role,
        cardanoAddress: user.cardanoAddress 
    });
});

app.get('/api/tasks', authenticateToken, async (req, res) => {
    try {
        const tasks = JSON.parse(fs.readFileSync('data/tasks.json', 'utf8')).tasks;
        res.json(tasks);
    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    }
});

app.post('/api/tasks', authenticateToken, async (req, res) => {
    try {
        // Read current tasks
        const tasksData = JSON.parse(fs.readFileSync('data/tasks.json', 'utf8'));
        
        // Create new task
        const newTask = {
            id: Date.now().toString(),
            ...req.body,
            status: 'active',
            clientId: req.user.id,
            assignedTo: null,
            createdAt: new Date().toISOString()
        };
        
        // Add new task to tasks array
        tasksData.tasks.push(newTask);
        
        // Write updated tasks back to file
        fs.writeFileSync('data/tasks.json', JSON.stringify(tasksData, null, 2));
        
        res.status(201).json(newTask);
    } catch (error) {
        console.error('Error creating task:', error);
        res.status(500).json({ error: 'Failed to create task' });
    }
});

app.post('/api/tasks/:taskId/cancel', authenticateToken, async (req, res) => {
    try {
        const tasksData = JSON.parse(fs.readFileSync('data/tasks.json', 'utf8'));
        const taskIndex = tasksData.tasks.findIndex(t => t.id === req.params.taskId);
        
        if (taskIndex === -1) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        const task = tasksData.tasks[taskIndex];
        
        // Check authorization: Either the client who posted the task or the student who accepted it
        const isClient = task.clientId === req.user.id;
        const isStudent = task.assignedTo === req.user.id;
        
        if (!isClient && !isStudent) {
            return res.status(403).json({ error: 'Not authorized to cancel this task' });
        }
        
        // If task has an associated escrow transaction, cancel it
        if (task.escrowTxHash) {
            try {
                const result = await cancelEscrowContract(task.escrowTxHash, task.clientId);
                // Store the cancellation transaction hash
                task.refundTxHash = result.txHash;
            } catch (escrowError) {
                console.error('Error cancelling escrow:', escrowError);
                // Continue with task cancellation even if escrow cancellation fails
                // This ensures the task status is updated in our system
            }
        }
        
        // Update task status
        task.status = 'cancelled';
        task.cancelledAt = new Date().toISOString();
        task.cancelledBy = req.user.id;
        
        // Write updated tasks back to file
        fs.writeFileSync('data/tasks.json', JSON.stringify(tasksData, null, 2));
        
        res.json(task);
    } catch (error) {
        console.error('Error cancelling task:', error);
        res.status(500).json({ error: 'Failed to cancel task' });
    }
});

app.post('/api/tasks/:taskId/complete', authenticateToken, async (req, res) => {
    try {
        console.log('Completing task:', req.params.taskId);
        // Read tasks from file
        const tasksData = JSON.parse(fs.readFileSync('data/tasks.json', 'utf8'));
        
        // Find the task
        const taskIndex = tasksData.tasks.findIndex(t => t.id === req.params.taskId);
        console.log('Task index:', taskIndex);
        
        if (taskIndex === -1) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        const task = tasksData.tasks[taskIndex];
        console.log('Is Task null Task:', task);
        
        // Check if task is assigned to someone
        if (!task.assignedTo) {
            console.log('Task is not assigned to anyone');
            return res.status(400).json({ error: 'Task is not assigned to anyone' });
        }
        
        const isClient = task.clientId === 'dev-client';
        const isStudent = task.assignedTo === 'dev-student';
        
        if (!isClient && !isStudent) {
            return res.status(403).json({ error: 'Not authorized to complete this task' });
        }
        
        // Different logic based on who is marking the task as complete
        if (isStudent) {
            // Student marks the task as ready for review
            if (task.status === 'active') {
                task.status = 'completed_by_student';
                task.completedByStudentAt = new Date().toISOString();
                
                // Write updated tasks back to file
                fs.writeFileSync('data/tasks.json', JSON.stringify(tasksData, null, 2));
                
                return res.json(task);
            } 
        }
        if (isClient) {
            // Client approves and finalizes the task
            if (task.status === 'completed_by_student') {
                // If task has an escrow transaction, complete it
                if (task.escrowTxHash) {
                    try {
                        console.log('ClientId ',task.clientId)
                        console.log('AssignedTo ',task.assignedTo)
                        const result = await completeEscrowContract(
                            task.escrowTxHash, 
                            task.clientId, 
                            task.assignedTo
                        );
                        // Store the completion transaction hash
                        task.paymentTxHash = result.txHash;
                    } catch (escrowError) {
                        console.error('Error completing escrow:', escrowError);
                        return res.status(500).json({ 
                            error: 'Failed to release payment', 
                            details: escrowError.message 
                        });
                    }
                }
                
                // Update task status
                task.status = 'completed';
                task.completedAt = new Date().toISOString();
                
                // Write updated tasks back to file
                fs.writeFileSync('data/tasks.json', JSON.stringify(tasksData, null, 2));
                
                res.json(task);
            } else {
                return res.status(400).json({ 
                    error: 'Task must be marked as completed by student first',
                    status: task.status
                });
            }
        }
    } catch (error) {
        console.error('Error completing task:', error);
        res.status(500).json({ error: 'Failed to complete task' });
    }
});

// Smart Contract Configuration
let ESCROW_VALIDATOR_ADDRESS = process.env.ESCROW_VALIDATOR_ADDRESS;

// Provide a testing address if in development mode and address not set
if (!ESCROW_VALIDATOR_ADDRESS && process.env.NODE_ENV === 'development') {
    ESCROW_VALIDATOR_ADDRESS = 'addr_test1qp9ppj4m8w4mshktrv3s85m4thgvnw3ps0p9lf53k359nphfz6367p7tqsz7mpc4h7892gkfafqfj35eh0pjqnl3hansxvdaxt';
}

console.log('Environment ESCROW_VALIDATOR_ADDRESS:', ESCROW_VALIDATOR_ADDRESS);
const PLATFORM_FEE_PERCENTAGE = 5;

// Transaction monitoring system
const transactionStatus = new Map();
const transactionCallbacks = new Map();

// Transaction status types
const TransactionStatus = {
    PENDING: 'pending',
    CONFIRMED: 'confirmed',
    FAILED: 'failed',
    EXPIRED: 'expired'
};

// Function to monitor transaction status
async function monitorTransaction(txHash, callback) {
    try {
        // Store callback for later use
        transactionCallbacks.set(txHash, callback);
        
        // Initial delay before checking (give time for the tx to propagate)
        await new Promise(resolve => setTimeout(resolve, 5000));
        
        // Implement retry with exponential backoff
        let retries = 0;
        const maxRetries = 5;
        let delay = 2000; // Start with 2 second delay
        
        const checkTxStatus = async () => {
            try {
                console.log(`Checking status of transaction ${txHash}, attempt ${retries + 1}/${maxRetries}`);
                const tx = await blockfrost.txs(txHash);
                
                if (tx.status === 'confirmed') {
                    await updateTransactionStatus(txHash, TransactionStatus.CONFIRMED);
                    return true;
                } else {
                    await updateTransactionStatus(txHash, TransactionStatus.PENDING);
                    
                    // Start polling for status updates
                    const pollInterval = setInterval(async () => {
                        try {
                            const updatedTx = await blockfrost.txs(txHash);
                            
                            if (updatedTx.status === 'confirmed') {
                                clearInterval(pollInterval);
                                await updateTransactionStatus(txHash, TransactionStatus.CONFIRMED);
                            } else if (updatedTx.status === 'failed') {
                                clearInterval(pollInterval);
                                await updateTransactionStatus(txHash, TransactionStatus.FAILED);
                            }
                        } catch (error) {
                            logger.error('Error polling transaction status:', error);
                            clearInterval(pollInterval);
                            await updateTransactionStatus(txHash, TransactionStatus.FAILED);
                        }
                    }, 10000); // Poll every 10 seconds
                    
                    // Set timeout for transaction expiration
                    setTimeout(async () => {
                        if (transactionStatus.get(txHash) === TransactionStatus.PENDING) {
                            clearInterval(pollInterval);
                            await updateTransactionStatus(txHash, TransactionStatus.EXPIRED);
                        }
                    }, 3600000); // 1 hour timeout
                    
                    return true;
                }
            } catch (error) {
                // Handle 404 specifically - tx might not be on chain yet
                if (error.status_code === 404) {
                    retries++;
                    if (retries < maxRetries) {
                        console.log(`Transaction ${txHash} not found yet, retrying in ${delay/1000} seconds...`);
                        await new Promise(resolve => setTimeout(resolve, delay));
                        delay *= 2; // Exponential backoff
                        return await checkTxStatus();
                    } else {
                        console.log(`Transaction ${txHash} not found after ${maxRetries} attempts`);
                        await updateTransactionStatus(txHash, TransactionStatus.FAILED);
                        return false;
                    }
                } else {
                    throw error;
                }
            }
        };
        
        await checkTxStatus();
    } catch (error) {
        logger.error('Error monitoring transaction:', error);
        await updateTransactionStatus(txHash, TransactionStatus.FAILED);
    }
}

// Function to update transaction status
async function updateTransactionStatus(txHash, status) {
    try {
        // Update status in memory
        transactionStatus.set(txHash, status);
        
        // Get callback if exists
        const callback = transactionCallbacks.get(txHash);
        if (callback) {
            await callback(status);
            transactionCallbacks.delete(txHash);
        }
        
        // Log status update
        logger.info(`Transaction ${txHash} status updated to ${status}`);
        
        // Update escrow status in database if needed
        if (status === TransactionStatus.CONFIRMED) {
            await updateEscrowStatus(txHash, 'completed');
        } else if (status === TransactionStatus.FAILED || status === TransactionStatus.EXPIRED) {
            await updateEscrowStatus(txHash, 'failed');
        }
    } catch (error) {
        logger.error('Error updating transaction status:', error);
    }
}

// Function to update escrow status
async function updateEscrowStatus(txHash, status) {
    try {
        // Find escrow by transaction hash
        const escrow = Array.from(tasks.values()).find(task => task.txHash === txHash);
        if (escrow) {
            escrow.status = status;
            tasks.set(escrow.id, escrow);
            
            // Notify relevant parties
            await notifyEscrowStatusUpdate(escrow);
        }
    } catch (error) {
        logger.error('Error updating escrow status:', error);
    }
}

// Function to notify parties about escrow status update
async function notifyEscrowStatusUpdate(escrow) {
    try {
        const client = users.get(escrow.clientId);
        const student = users.get(escrow.assignedTo);
        
        if (client && client.email) {
            await sendEmail(
                client.email,
                'Escrow Status Update',
                `Your escrow transaction (${escrow.txHash}) has been ${escrow.status}.`
            );
        }
        
        if (student && student.email) {
            await sendEmail(
                student.email,
                'Escrow Status Update',
                `Your escrow transaction (${escrow.txHash}) has been ${escrow.status}.`
            );
        }
    } catch (error) {
        logger.error('Error sending escrow status notifications:', error);
    }
}

// Function to create or update user profile
async function updateUserProfile(userId, profileData) {
    const existingProfile = userProfiles.get(userId) || {};
    const updatedProfile = {
        ...existingProfile,
        ...profileData,
        lastUpdated: new Date().toISOString()
    };
    userProfiles.set(userId, updatedProfile);
    return updatedProfile;
}

// Function to verify student documents
async function verifyStudentDocuments(userId) {
    const profile = userProfiles.get(userId);
    if (!profile || !profile.documents) {
        return { verified: false, message: 'No documents found' };
    }

    const verificationResults = await Promise.all(
        profile.documents.map(async (doc) => {
            const verification = await verifyHashOnCardano(doc.hash);
            return {
                documentId: doc.id,
                verified: verification.found,
                timestamp: verification.timestamp,
                txId: verification.txId
            };
        })
    );

    return {
        verified: verificationResults.every(result => result.verified),
        documents: verificationResults
    };
}

// Enhanced escrow creation with transaction monitoring
async function createEscrowContract(clientId, studentId, amount, autoDeduct) {
    try {
        if (!lucid) {
            throw new APIError('Blockchain connection not initialized', 500, 'BLOCKCHAIN_ERROR');
        }

        // Validate amount
        if (!amount || typeof amount !== 'number' || amount <= 0) {
            throw new APIError('Invalid amount provided', 400, 'INVALID_AMOUNT');
        }

        let clientProfile;
        let studentProfile;

        if (process.env.NODE_ENV === 'development') {
            // Use mock profiles in development mode
            clientProfile = {
                id: 'dev-client',
                cardanoAddress: 'addr_test1qrk47v4t4xlywf3eh8ae7s54s354k86c6rh8mu8utzm22ky28mcycq87r9qef4gdm8555ft8valqhxkgx3uypyt0v3lqsmpkfu',
                name: 'Akeem Adetunji'
            };
            studentProfile = {
                id: 'dev-student',
                cardanoAddress: 'addr_test1qp2zaa5z74telpcag6dnxhle4gjl9j74660f8w0a00q0fwl0u42l9qnj0vz7dkvcs98vptzf7h27maqn5aa4k2amx08sqqqa9r',
                name: 'Azeem Adetunji'
            };
        } else {
            clientProfile = userProfiles.get(clientId);
            studentProfile = userProfiles.get(studentId);

            if (!clientProfile || !studentProfile) {
                throw new APIError('User profiles not found', 404, 'PROFILE_NOT_FOUND');
            }
        }

        // Verify student documents (skip in development mode)
        if (process.env.NODE_ENV !== 'development') {
            const verification = await verifyStudentDocuments(studentId);
            if (!verification.verified) {
                throw new APIError('Student documents not verified', 400, 'DOCUMENT_NOT_VERIFIED');
            }
        }

        // Calculate platform fee
        const platformFee = Math.floor(amount * (PLATFORM_FEE_PERCENTAGE / 100));
        const studentAmount = amount - platformFee;

        // Convert addresses to BaseAddress and extract payment key hash
        const buyerAddress = Cardano.Address.from_bech32(clientProfile.cardanoAddress);
        const sellerAddress = Cardano.Address.from_bech32(studentProfile.cardanoAddress);
        
        const buyerBase = Cardano.BaseAddress.from_address(buyerAddress);
        const sellerBase = Cardano.BaseAddress.from_address(sellerAddress);
        if (!buyerBase || !sellerBase) {
            throw new Error('Provided address is not a BaseAddress');
        }
        
        // Get key hashes
        const buyerVkh = buyerBase.payment_cred().to_keyhash().to_bytes();
        const sellerVkh = sellerBase.payment_cred().to_keyhash().to_bytes();

        // Create escrow datum matching on-chain type - EXACTLY as in the Aiken contract
        const deadline = (Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days from now
        
        // Debug logging
        console.log('Data types for serialization:');
        console.log('buyer:', buyerVkh);
        console.log('seller:', sellerVkh);
        console.log('- buyer:', typeof buyerVkh, buyerVkh instanceof Uint8Array);
        console.log('- seller:', typeof sellerVkh, sellerVkh instanceof Uint8Array);
        console.log('- amount:', typeof amount, amount);
        console.log('- deadline:', typeof deadline);
        
        try {
            // Derive the script address from the compiled Aiken contract
            const scriptAddress = await getAikenScriptAddress(lucid);
            console.log('Using derived Aiken script address:', scriptAddress);
            
            // Convert byte arrays to hex strings for serialization
            const buyerHex = toHex(buyerVkh);
            const sellerHex = toHex(sellerVkh);
            
            // Ensure amount is a BigInt
            const amountBigInt = BigInt(Math.floor(amount));
            
            let jolly = new Constr(0, [
                buyerHex,
                sellerHex,
                5000000n,
                BigInt(deadline)
            ]);
            
            console.log('Created datum with amount:', amountBigInt.toString());
            
            const datum = Data.to(jolly);
            
            console.log('Created datum:', datum);
            
            // Create and submit transaction using payToContract with inline datum
            const tx = await lucid
                .newTx()
                .payToContract(
                    scriptAddress,
                    { inline: datum },
                    { lovelace: 5000000n }
                )
                .complete();

            try {
                const signedTx = await tx.sign().complete();
                const txHash = await signedTx.submit();

                console.log('Successfully submitted transaction:', txHash);
                
                return {
                    success: true,
                    txHash,
                    amount,
                    platformFee,
                    studentAmount,
                    status: TransactionStatus.PENDING
                };
            } catch (txError) {
                console.error('Transaction submission error:', txError);
                const errorMessage = txError.info || txError.message || 'Unknown transaction error';
                
                throw new APIError(
                    `Transaction submission failed: ${errorMessage}`,
                    500,
                    'TX_SUBMISSION_FAILED',
                    { details: errorMessage }
                );
            }
        } catch (error) {
            console.error('Error in escrow contract creation:', error);
            throw new APIError(
                'Failed to create escrow contract',
                500,
                'ESCROW_CREATION_FAILED',
                { details: error.message }
            );
        }
    } catch (error) {
        logger.error('Error creating escrow contract:', error);
        throw error instanceof APIError 
            ? error 
            : new APIError(
                'Failed to create escrow contract',
                500,
                'ESCROW_CREATION_FAILED',
                { details: error.message }
            );
    }
}

// Enhanced escrow completion with transaction monitoring
async function completeEscrowContract(txHash, clientId, studentId) {
    try {
        if (!lucid) {
            throw new APIError('Blockchain connection not initialized', 500, 'BLOCKCHAIN_ERROR');
        }
        console.log('Client Profile:', clientId);
        console.log('Student Profile:', studentId);
        console.log('User Profiles:', userProfiles);
        console.log('Client ID:', clientId);
        console.log('Student ID:', studentId);
        const clientProfile = userProfiles.get(clientId);
        const studentProfile = userProfiles.get(studentId);
       

        if (!clientProfile || !studentProfile) {
            throw new APIError('User profiles not found', 404, 'PROFILE_NOT_FOUND');
        }

        // --- Use Aiken script address and proper redeemer ---
        try {
            // Derive the script address from the compiled Aiken contract
            const scriptAddress = await getAikenScriptAddress(lucid);
            console.log('Using derived Aiken script address (complete):', scriptAddress);
            const aikenScript = await getAikenScript(lucid);
            console.log('Using derived Aiken script (complete):', aikenScript);

            // Construct the ApproveWork redeemer as a Constr (index 0, field: ApproveWork action, index 2)
            // EscrowRedeemer(EscrowAction.ApproveWork)
            const redeemer = Data.to(new Constr(0, [BigInt(2)]));
        
            const scriptUtxo = await lucid.utxosAt(scriptAddress);
            console.log('Created ApproveWork redeemer:', redeemer);
            console.log('Script Utxo datum:', scriptUtxo);
        


            // TODO: Retrieve studentAmount and platformFee for this escrow (not available in current signature)
            // For now, use placeholders or fetch from DB/UTXO as needed
            // const studentAmount = ...;
            // const platformFee = ...;

            // Create and submit transaction
            const tx = await lucid
                .newTx()
                .collectFrom(scriptUtxo,redeemer)
                .attachSpendingValidator(aikenScript)
                //.payToAddress(studentProfile.cardanoAddress, { lovelace:100n })
                // .payToAddress(process.env.PLATFORM_WALLET_ADDRESS, { lovelace: BigInt(platformFee) })
                .complete();

            const signedTx = await tx.sign().complete();
            const newTxHash = await signedTx.submit();

            // Start monitoring transaction
           
            return {
                txHash: newTxHash,
                status: TransactionStatus.PENDING
            };
        } catch (error) {
            console.error('Redeemer serialization error:', error);
            throw new APIError(
                'Failed to complete escrow contract - redeemer error',
                500,
                'ESCROW_REDEEMER_ERROR',
                { details: error.message }
            );
        }
    } catch (error) {
        logger.error('Error completing escrow contract:', error);
        throw new APIError(
            'Failed to complete escrow contract',
            500,
            'ESCROW_COMPLETION_FAILED',
            { details: error.message }
        );
    }
}

// Enhanced escrow cancellation with transaction monitoring (refunds to client)
async function cancelEscrowContract(txHash, clientId) {
    try {
        if (!lucid) {
            throw new APIError('Blockchain connection not initialized', 500, 'BLOCKCHAIN_ERROR');
        }

        const clientProfile = userProfiles.get(clientId);

        if (!clientProfile) {
            throw new APIError('Client profile not found', 404, 'PROFILE_NOT_FOUND');
        }

        try {
            // Derive the script address from the compiled Aiken contract
            const scriptAddress = await getAikenScriptAddress(lucid);
            console.log('Using derived Aiken script address (cancel):', scriptAddress);

            // Construct the ClaimRefund redeemer as a Constr (index 0, field: ClaimRefund action, index 0)
            // EscrowRedeemer(EscrowAction.ClaimRefund)
            const redeemer = new Constr(0, [new Constr(0, [])]);
            console.log('Created ClaimRefund redeemer:', redeemer);

            // TODO: Retrieve amount for this escrow (not available in current signature)
            // For now, use placeholder or fetch from DB/UTXO as needed
            // const amount = ...;

            // Create and submit transaction to refund the client
            const tx = await lucid
                .newTx()
                .spendFromContract(scriptAddress, { inline: redeemer })
                // .payToAddress(clientProfile.cardanoAddress, { lovelace: BigInt(amount) })
                .complete();

            const signedTx = await tx.sign().complete();
            const newTxHash = await signedTx.submit();

            // Start monitoring transaction
            await monitorTransaction(newTxHash, async (status) => {
                logger.info(`Escrow cancellation transaction ${newTxHash} status: ${status}`);
            });

            return {
                txHash: newTxHash,
                status: TransactionStatus.PENDING
            };
        } catch (error) {
            console.error('Redeemer serialization error:', error);
            throw new APIError(
                'Failed to cancel escrow contract - redeemer error',
                500,
                'ESCROW_REDEEMER_ERROR',
                { details: error.message }
            );
        }
    } catch (error) {
        logger.error('Error cancelling escrow contract:', error);
        throw new APIError(
            'Failed to cancel escrow contract',
            500,
            'ESCROW_CANCELLATION_FAILED',
            { details: error.message }
        );
    }
}

// API endpoint to get transaction status
app.get('/api/escrow/:txHash/status', authenticateToken, async (req, res) => {
    try {
        const { txHash } = req.params;
        const status = transactionStatus.get(txHash) || TransactionStatus.PENDING;
        
        res.json({ status });
    } catch (error) {
        logger.error('Error getting transaction status:', error);
        res.status(500).json({ error: 'Failed to get transaction status' });
    }
});

// API Routes for Unified Platform
app.post('/api/profile', authenticateToken, async (req, res) => {
    try {
        const profileData = req.body;
        const updatedProfile = await updateUserProfile(req.user.id, profileData);
        res.json(updatedProfile);
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

app.get('/api/profile/:userId', authenticateToken, async (req, res) => {
    try {
        const profile = userProfiles.get(req.params.userId);
        if (!profile) {
            return res.status(404).json({ error: 'Profile not found' });
        }
        res.json(profile);
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

app.post('/api/escrow', authenticateToken, async (req, res) => {
    try {
        const { studentId, amount, autoDeduct } = req.body;
        
        // If autoDeduct is enabled, verify client's balance first
        if (autoDeduct) {
            const clientProfile = userProfiles.get(req.user.id);
            if (!clientProfile) {
                throw new APIError('Client profile not found', 404, 'PROFILE_NOT_FOUND');
            }

            // Get client's balance
            const balance = await getWalletBalance(clientProfile.cardanoAddress);
            if (balance < amount) {
                throw new APIError('Insufficient balance', 400, 'INSUFFICIENT_BALANCE');
            }
        }

        const result = await createEscrowContract(req.user.id, studentId, amount, autoDeduct);
        res.json(result);
    } catch (error) {
        console.error('Error creating escrow:', error);
        res.status(error.status || 500).json({ 
            error: error.message || 'Failed to create escrow contract',
            code: error.code
        });
    }
});

app.post('/api/escrow/:txHash/complete', authenticateToken, async (req, res) => {
    try {
        const { studentId } = req.body;
        const result = await completeEscrowContract(req.params.txHash, req.user.id, studentId);
        res.json(result);
    } catch (error) {
        console.error('Error completing escrow:', error);
        res.status(500).json({ error: 'Failed to complete escrow contract' });
    }
});

// Endpoint for cancelling escrow contract - returns funds to client
app.post('/api/escrow/:txHash/cancel', authenticateToken, async (req, res) => {
    try {
        const result = await cancelEscrowContract(req.params.txHash, req.user.id);
        res.json(result);
    } catch (error) {
        console.error('Error cancelling escrow:', error);
        res.status(500).json({ error: 'Failed to cancel escrow contract' });
    }
});

// Wallet balance endpoint
app.get('/api/wallet/balance', authenticateToken, async (req, res) => {
    try {
        let user;
        if (process.env.NODE_ENV === 'development') {
            // In development mode, use the mock user
            user = {
                cardanoAddress: 'addr_test1qrk47v4t4xlywf3eh8ae7s54s354k86c6rh8mu8utzm22ky28mcycq87r9qef4gdm8555ft8valqhxkgx3uypyt0v3lqsmpkfu'
            };
        } else {
            user = users.get(req.user.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
            }
        }

        // Get wallet balance from Blockfrost
        const address = user.cardanoAddress;
        const utxos = await blockfrost.addressesUtxos(address);
        
        // Calculate total balance in lovelace
        const balance = utxos.reduce((total, utxo) => {
            return total + BigInt(utxo.amount[0].quantity);
        }, BigInt(0));

        // Convert lovelace to ADA (1 ADA = 1,000,000 lovelace)
        const adaBalance = Number(balance) / 1000000;

        res.json({ balance: adaBalance.toFixed(2) });
    } catch (error) {
        console.error('Error getting wallet balance:', error);
        res.status(500).json({ error: 'Failed to get wallet balance' });
    }
});

// View wallet endpoint
app.get('/api/wallet', authenticateToken, async (req, res) => {
    try {
        const user = users.get(req.user.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Get wallet details from Blockfrost
        const address = user.cardanoAddress;
        const utxos = await blockfrost.addressesUtxos(address);
        const transactions = await blockfrost.addressesTransactions(address);
        
        // Calculate total balance
        const balance = utxos.reduce((total, utxo) => {
            return total + BigInt(utxo.amount[0].quantity);
        }, BigInt(0));

        // Convert lovelace to ADA
        const adaBalance = Number(balance) / 1000000;

        // Format transaction history
        const txHistory = await Promise.all(transactions.map(async (tx) => {
            const txDetails = await blockfrost.txs(tx.tx_hash);
            return {
                hash: tx.tx_hash,
                amount: txDetails.amount[0].quantity / 1000000,
                type: txDetails.amount[0].quantity > 0 ? 'received' : 'sent',
                timestamp: txDetails.block_time,
                status: txDetails.status
            };
        }));

        res.json({
            address: user.cardanoAddress,
            balance: adaBalance.toFixed(2),
            transactions: txHistory
        });
    } catch (error) {
        console.error('Error getting wallet details:', error);
        res.status(500).json({ error: 'Failed to get wallet details' });
    }
});

// Add send ADA endpoint
app.post('/api/wallet/send', async (req, res) => {
    try {
        const { recipientAddress, amount } = req.body;

        // Initialize Lucid with Blockfrost provider
        const lucid = await Lucid.new(
            new Blockfrost(
                "https://cardano-preview.blockfrost.io/api/v0",
                process.env.BLOCKFROST_API_KEY
            ),
            "Preview"
        );

        // Select wallet using seed phrase
        lucid.selectWalletFromSeed(process.env.CARDANO_SEED_PHRASE);

        // Create transaction
        const tx = await lucid
            .newTx()
            .payToAddress(recipientAddress, { lovelace: BigInt(amount * 1000000) })
            .complete();

        // Sign and submit the transaction
        const signedTx = await tx.sign().complete();
        const txHash = await signedTx.submit();

        // Return success immediately after submission
        res.json({
            success: true,
            txHash,
            message: 'Transaction submitted successfully. Check transaction history for status updates.'
        });
    } catch (error) {
        console.error('Error sending ADA:', error);
        if (error instanceof APIError) {
            res.status(error.statusCode).json({ error: error.message });
        } else {
            res.status(500).json({ error: 'Failed to send ADA' });
        }
    }
});

// Wallet balance endpoint for specific address
app.get('/api/wallet/balance/:address', authenticateToken, async (req, res) => {
    try {
        const { address } = req.params;

        // Get wallet balance from Blockfrost
        const utxos = await blockfrost.addressesUtxos(address);
        
        // Calculate total balance in lovelace
        const balance = utxos.reduce((total, utxo) => {
            return total + BigInt(utxo.amount[0].quantity);
        }, BigInt(0));

        // Convert lovelace to ADA (1 ADA = 1,000,000 lovelace)
        const adaBalance = Number(balance) / 1000000;

        res.json({ balance: adaBalance.toFixed(2) });
    } catch (error) {
        console.error('Error getting wallet balance:', error);
        res.status(500).json({ error: 'Failed to get wallet balance' });
    }
});

// Wallet transactions endpoint for specific address
app.get('/api/wallet/transactions/:address', authenticateToken, async (req, res) => {
    try {
        const { address } = req.params;

        // Get transactions from Blockfrost
        const transactions = await blockfrost.addressesTransactions(address);
        
        // Format transaction history with proper error handling
        const txHistory = await Promise.all(transactions.map(async (tx) => {
            try {
                const txDetails = await blockfrost.txs(tx.tx_hash);
                
                // Safely access amount and determine transaction type
                let amount = 0;
                let type = 'unknown';
                
                if (txDetails.amount && Array.isArray(txDetails.amount) && txDetails.amount.length > 0) {
                    amount = txDetails.amount[0].quantity / 1000000; // Convert lovelace to ADA
                    type = amount > 0 ? 'received' : 'sent';
                }
                
                return {
                    hash: tx.tx_hash,
                    amount: amount,
                    type: type,
                    timestamp: txDetails.block_time || Date.now() / 1000,
                    status: txDetails.status || 'unknown'
                };
            } catch (txError) {
                console.error(`Error processing transaction ${tx.tx_hash}:`, txError);
                // Return a basic transaction object for failed transactions
                return {
                    hash: tx.tx_hash,
                    amount: 0,
                    type: 'unknown',
                    timestamp: Date.now() / 1000,
                    status: 'error'
                };
            }
        }));

        res.json(txHistory);
    } catch (error) {
        console.error('Error getting wallet transactions:', error);
        res.status(500).json({ error: 'Failed to get wallet transactions' });
    }
});

// Get available jobs for students
app.get('/api/tasks/available', async (req, res) => {
    try {
        // Read tasks from file
        const tasksData = JSON.parse(fs.readFileSync('data/tasks.json', 'utf8'));
        
        // Filter active tasks that haven't been assigned
        const availableTasks = tasksData.tasks.filter(task => 
            task.status === 'active' && !task.assignedTo
        );
        
        // Get client names for each task and map budget to amount
        const tasksWithClientNames = availableTasks.map(task => {
            const client = users.get(task.clientId);
            return {
                ...task,
                amount: task.budget, // Map budget to amount
                clientName: client ? `${client.firstName} ${client.lastName}` : 'Unknown Client',
                requiredSkills: task.requirements || [] // Map requirements to requiredSkills
            };
        });
        
        res.json(tasksWithClientNames);
    } catch (error) {
        console.error('Error fetching available tasks:', error);
        res.status(500).json({ error: 'Failed to fetch available tasks' });
    }
});

// Get student's accepted jobs
app.get('/api/tasks/my-jobs', async (req, res) => {
    try {
        // Read tasks from file
        const tasksData = JSON.parse(fs.readFileSync('data/tasks.json', 'utf8'));
        
        // Filter tasks assigned to the current student
        const myTasks = tasksData.tasks.filter(task => 
            task.assignedTo === 'dev-student' // Use dev-student for the current student
        );
        
        // Get client names for each task and map budget to amount
        const tasksWithClientNames = myTasks.map(task => {
            const client = users.get(task.clientId);
            return {
                ...task,
                amount: task.budget, // Map budget to amount
                clientName: client ? `${client.firstName} ${client.lastName}` : 'Unknown Client',
                requiredSkills: task.requirements || [] // Map requirements to requiredSkills
            };
        });
        
        res.json(tasksWithClientNames);
    } catch (error) {
        console.error('Error fetching my tasks:', error);
        res.status(500).json({ error: 'Failed to fetch my tasks' });
    }
});

// Accept a job
app.post('/api/tasks/:taskId/accept', authenticateToken, async (req, res) => {
    try {
        // Read tasks from file
        const tasksData = JSON.parse(fs.readFileSync('data/tasks.json', 'utf8'));
        
        // Find the task
        const taskIndex = tasksData.tasks.findIndex(t => t.id === req.params.taskId);
        
        if (taskIndex === -1) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        const task = tasksData.tasks[taskIndex];
        
        // Check if task is available
        if (task.status !== 'active' || task.assignedTo) {
            return res.status(400).json({ error: 'Task is not available' });
        }

        // --- NEW: Attempt to create escrow contract before assigning ---
        try {
            // Use mock data for dev, or real IDs in production
            const clientId = 'dev-client'; // Always use dev-client in development
            const studentId = 'dev-student'; // Always use dev-student in development
            const amount = task.budget || task.amount;
            const autoDeduct = true;

            const escrowResult = await createEscrowContract(clientId, studentId, amount, autoDeduct);

            if (!escrowResult || !escrowResult.txHash) {
                throw new Error('Escrow creation failed');
            }

            // Assign task to student only if escrow succeeded
            task.assignedTo = 'dev-student'; // Use dev-student instead of req.user.id
            task.assignedAt = new Date().toISOString();
            task.escrowTxHash = escrowResult.txHash; // Save txHash for reference

            // Write updated tasks back to file
            fs.writeFileSync('data/tasks.json', JSON.stringify(tasksData, null, 2));

            res.json(task);
        } catch (escrowError) {
            // If escrow fails, do not assign the job
            return res.status(500).json({ error: 'Failed to create escrow: ' + (escrowError.message || escrowError) });
        }
    } catch (error) {
        console.error('Error accepting task:', error);
        res.status(500).json({ error: 'Failed to accept task' });
    }
});

// Function to get wallet balance
async function getWalletBalance(address) {
    try {
        if (!blockfrost) {
            throw new Error('Blockfrost API not initialized');
        }

        // Get UTXOs for the address
        const utxos = await blockfrost.addressesUtxos(address);
        
        // Calculate total balance in lovelace
        const balance = utxos.reduce((total, utxo) => {
            return total + BigInt(utxo.amount[0].quantity);
        }, BigInt(0));

        // Convert lovelace to ADA (1 ADA = 1,000,000 lovelace)
        return Number(balance) / 1000000;
    } catch (error) {
        console.error('Error getting wallet balance:', error);
        throw new APIError(
            'Failed to get wallet balance',
            500,
            'BALANCE_CHECK_FAILED',
            { details: error.message }
        );
    }
}

// Error handling middleware
app.use((err, req, res, next) => {
    // Handle specific error types
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            error: 'Validation Error',
            message: err.message
        });
    }

    if (err.name === 'MongoError' && err.code === 11000) {
        return res.status(409).json({
            error: 'Duplicate Entry',
            message: 'A record with this information already exists'
        });
    }

    // Handle authentication errors
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            error: 'Authentication Error',
            message: 'Invalid token provided'
        });
    }

    if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
            error: 'Authentication Error',
            message: 'Token has expired'
        });
    }

    // Default error response
    res.status(err.status || 500).json({
        error: err.name || 'Internal Server Error',
        message: err.message || 'An unexpected error occurred'
    });
});

// Start the server
app.listen(process.env.PORT || 3000, () => {
    console.log(`Server is running on port ${process.env.PORT || 3000}`);
});

// Escrow Contract Routes
app.post('/api/escrow/create', async (req, res) => {
    try {
        const { sellerAddress, amount, deadline } = req.body;
        
        // Validate inputs
        if (!sellerAddress || !amount || !deadline) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Create escrow transaction
        const txHash = await escrow.createEscrow(
            sellerAddress,
            BigInt(amount),
            parseInt(deadline)
        );

        res.json({ success: true, txHash });
    } catch (error) {
        console.error('Error creating escrow:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/escrow/approve', async (req, res) => {
    try {
        const { escrowUtxo } = req.body;
        
        if (!escrowUtxo) {
            return res.status(400).json({ error: 'Missing escrow UTXO' });
        }

        const txHash = await escrow.approveWork(escrowUtxo);
        res.json({ success: true, txHash });
    } catch (error) {
        console.error('Error approving work:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/escrow/claim-payment', async (req, res) => {
    try {
        const { escrowUtxo } = req.body;
        
        if (!escrowUtxo) {
            return res.status(400).json({ error: 'Missing escrow UTXO' });
        }

        const txHash = await escrow.claimPayment(escrowUtxo);
        res.json({ success: true, txHash });
    } catch (error) {
        console.error('Error claiming payment:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/escrow/claim-refund', async (req, res) => {
    try {
        const { escrowUtxo } = req.body;
        
        if (!escrowUtxo) {
            return res.status(400).json({ error: 'Missing escrow UTXO' });
        }

        const txHash = await escrow.claimRefund(escrowUtxo);
        res.json({ success: true, txHash });
    } catch (error) {
        console.error('Error claiming refund:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add a new API endpoint for checking transaction status
app.get('/api/blockchain/tx/:txHash', async (req, res) => {
    try {
        const { txHash } = req.params;
        
        if (!txHash || txHash.length < 10) {
            return res.status(400).json({ error: 'Invalid transaction hash' });
        }
        
        try {
            console.log(`Checking transaction ${txHash} on blockchain...`);
            const txDetails = await blockfrost.txs(txHash);
            
            // Get additional information about inputs and outputs
            const txUtxos = await blockfrost.txsUtxos(txHash);
            
            res.json({
                success: true,
                transaction: {
                    hash: txDetails.hash,
                    block: txDetails.block,
                    block_height: txDetails.block_height,
                    slot: txDetails.slot,
                    index: txDetails.index,
                    output_amount: txDetails.output_amount,
                    fees: txDetails.fees,
                    deposit: txDetails.deposit,
                    size: txDetails.size,
                    invalid_before: txDetails.invalid_before,
                    invalid_hereafter: txDetails.invalid_hereafter,
                    utxos: txUtxos,
                    status: txDetails.status || 'confirmed'
                }
            });
        } catch (error) {
            if (error.status_code === 404) {
                return res.status(404).json({ 
                    success: false, 
                    error: 'Transaction not found on blockchain',
                    message: 'The transaction might still be processing or may have failed to submit'
                });
            }
            throw error;
        }
    } catch (error) {
        console.error('Error checking transaction status:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to check transaction status',
            message: error.message || 'Unknown error'
        });
    }
}); 

// Get a single task by ID
app.get('/api/tasks/:taskId', authenticateToken, async (req, res) => {
    try {
        // Read tasks from file
        const tasksData = JSON.parse(fs.readFileSync('data/tasks.json', 'utf8'));
        
        // Find the task
        const task = tasksData.tasks.find(t => t.id === req.params.taskId);
        
        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        // Map budget to amount for consistency
        const taskWithAmount = {
            ...task,
            amount: task.budget // Map budget to amount
        };
        
        res.json(taskWithAmount);
    } catch (error) {
        console.error('Error fetching task:', error);
        res.status(500).json({ error: 'Failed to fetch task' });
    }
});

// Document upload endpoint for admin dashboard
app.post('/api/upload', upload.single('document'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        const { studentName, documentType, description } = req.body;
        if (!studentName || !documentType) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        // Calculate hash
        const hash = calculateHash(req.file.path);
        // Store hash and metadata on Cardano
        const metadata = {
            studentName,
            documentType,
            description: description || ''
        };
        const result = await storeHashOnCardano(hash, metadata);
        res.json({ success: true, txId: result.tx_hash, hash });
    } catch (error) {
        console.error('Error uploading document:', error);
        res.status(500).json({ error: error.message || 'Failed to upload document' });
    }
});

// Document verification endpoint for verify page
app.post('/api/verify', upload.single('document'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        // Calculate hash
        const hash = calculateHash(req.file.path);
        // Verify hash on Cardano
        const result = await verifyHashOnCardano(hash);
        if (result.found) {
            res.json({ verified: true, hash, metadata: {
                student: result.student,
                type: result.type,
                timestamp: result.timestamp
            }});
        } else {
            res.json({ verified: false, hash });
        }
    } catch (error) {
        console.error('Error verifying document:', error);
        res.status(500).json({ error: error.message || 'Failed to verify document' });
    }
});
