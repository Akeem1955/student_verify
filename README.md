# Student Document Verification System

A blockchain-powered document verification system built on Cardano, using Blockfrost API for secure and immutable academic record verification.

## Features

- Secure document verification using Cardano blockchain
- Admin portal for universities to upload and register documents
- Instant verification system for checking document authenticity
- Mobile-first, responsive design
- Tamper-proof record storage

## Setup

1. Clone this repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file in the root directory with your Blockfrost API key:
   ```
   BLOCKFROST_API_KEY=your_api_key_here
   ```
4. Start the server:
   ```bash
   node server.js
   ```
5. Open `http://localhost:3000` in your browser

## Technology Stack

- Frontend: HTML5, CSS3, JavaScript
- Backend: Node.js
- Blockchain: Cardano (via Blockfrost API)
- Security: SHA-256 hashing

## Project Structure

```
├── public/
│   ├── css/
│   │   └── styles.css
│   ├── js/
│   │   ├── main.js
│   │   ├── admin.js
│   │   └── verify.js
│   └── images/
├── server.js
├── package.json
└── README.md
```

## Security

- All documents are hashed using SHA-256 before being stored on the blockchain
- No raw document data is stored, only hashes
- Secure API key management
- HTTPS recommended for production deployment

## License

MIT License 