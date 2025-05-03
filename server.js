import 'dotenv/config';
import express from 'express';
import multer from 'multer';
import crypto from 'crypto';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { Blockfrost, Lucid } from 'lucid-cardano';
import { BlockFrostAPI } from '@blockfrost/blockfrost-js';
import NodeCache from 'node-cache';

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
        // Initialize Blockfrost API
        blockfrost = new BlockFrostAPI({
            projectId: process.env.BLOCKFROST_API_KEY,
            network: 'preview'
        });

        // Initialize Lucid with Blockfrost provider
        console.log('Initializing Lucid with Blockfrost provider...');
        lucid = await Lucid.new(
            new Blockfrost("https://cardano-preview.blockfrost.io/api/v0", process.env.BLOCKFROST_API_KEY),
            "Preview"
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
        throw new Error('Failed to initialize wallet connection');
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
        throw error;
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
        
        // As a last resort, do a direct blockchain query
        // Get cached metadata or fetch new
        let transactions = metadataCache.get(`metadata_txs_${METADATA_LABEL}`);
        if (!transactions) {
            transactions = await blockfrost.metadataTxsLabel(METADATA_LABEL, { count: 100 });
            metadataCache.set(`metadata_txs_${METADATA_LABEL}`, transactions);
        }
        
        // For each transaction, check if it contains our hash
        for (const tx of transactions) {
            const txId = tx.tx_hash;
            
            // Try to get cached metadata for this transaction
            let metadata = metadataCache.get(`metadata_tx_${txId}`);
            if (!metadata) {
                metadata = await blockfrost.txsMetadata(txId);
                metadataCache.set(`metadata_tx_${txId}`, metadata);
            }
            
            // Find the metadata entry for our label
            const metadataEntry = metadata.find(entry => entry.label === METADATA_LABEL);
            if (metadataEntry && metadataEntry.json_metadata && metadataEntry.json_metadata[METADATA_LABEL]) {
                const docMetadata = metadataEntry.json_metadata[METADATA_LABEL];
                if (docMetadata.hash === hash) {
                    const result = {
                        found: true,
                        timestamp: docMetadata.timestamp,
                        type: docMetadata.type,
                        student: docMetadata.student,
                        txId: txId,
                        blockTime: tx.block_time ? new Date(tx.block_time * 1000).toISOString() : null
                    };
                    
                    // Update our registry with this hash
                    hashRegistry[hash] = {
                        timestamp: docMetadata.timestamp,
                        type: docMetadata.type,
                        student: docMetadata.student,
                        txId: txId,
                        blockTime: tx.block_time ? new Date(tx.block_time * 1000).toISOString() : null
                    };
                    
                    // Cache the result
                    verificationCache.set(hash, result);
                    
                    console.log(`✅ Hash verified on Cardano blockchain!`);
                    console.log(`Transaction ID: ${txId}`);
                    return result;
                }
            }
        }
        
        console.log('❌ Hash not found on the blockchain');
        // Cache negative results too, but for shorter time
        const notFoundResult = { found: false };
        verificationCache.set(hash, notFoundResult, 300); // Cache for 5 minutes
        return notFoundResult;
        
    } catch (error) {
        if (error.status_code === 403) {
            console.error('Network token mismatch. Please check your API key.');
            throw new Error('Invalid API configuration. Please contact support.');
        } else if (error.status_code === 429) {
            console.error('Rate limit exceeded. Please try again later.');
            throw new Error('Too many requests. Please try again in a few seconds.');
        }
        console.error('Error verifying hash on Cardano:', error);
        throw error;
    }
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/verify', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'verify.html'));
});

// API endpoint for document upload (admin)
app.post('/api/upload', upload.single('document'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const hash = calculateHash(req.file.path);
        
        // Store hash on Cardano blockchain
        const metadata = {
            studentName: req.body.studentName,
            documentType: req.body.documentType,
            description: req.body.description
        };

        const txResult = await storeHashOnCardano(hash, metadata);

        res.json({
            success: true,
            hash: hash,
            txId: txResult.tx_hash,
            message: 'Document hashed and stored on blockchain successfully'
        });

        // Clean up uploaded file
        fs.unlinkSync(req.file.path);
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Error processing document' });
    }
});

// API endpoint for document verification
app.post('/api/verify', upload.single('document'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        console.time('verification');
        const hash = calculateHash(req.file.path);
        
        // Verify hash on Cardano blockchain
        const verificationResult = await verifyHashOnCardano(hash);
        console.timeEnd('verification');

        res.json({
            success: true,
            hash: hash,
            verified: verificationResult.found,
            metadata: verificationResult.found ? {
                timestamp: verificationResult.timestamp,
                type: verificationResult.type,
                student: verificationResult.student
            } : null,
            message: verificationResult.found ? 
                'Document verified successfully' : 
                'Document not found in blockchain records'
        });

        // Clean up uploaded file
        fs.unlinkSync(req.file.path);
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ error: 'Error verifying document' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        hashRegistrySize: Object.keys(hashRegistry).length,
        cacheStats: {
            verification: verificationCache.getStats(),
            metadata: metadataCache.getStats()
        }
    });
});

// Force registry update endpoint (admin only - should be protected in production)
app.post('/api/admin/update-registry', async (req, res) => {
    try {
        await populateHashRegistry();
        res.json({
            success: true,
            hashRegistrySize: Object.keys(hashRegistry).length,
            message: 'Hash registry updated successfully'
        });
    } catch (error) {
        console.error('Registry update error:', error);
        res.status(500).json({ error: 'Error updating registry' });
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
    
    // Initialize Lucid and populate hash registry
    initializeLucid().catch(console.error);
}); 