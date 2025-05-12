# Student Platform - Document Verification & Freelance System

A unified platform combining document verification and freelance opportunities for students, powered by Cardano blockchain technology.

## 🌟 Features

### 1. Document Verification System (betaedu)
- Secure document verification using Cardano blockchain
- Real-time certificate validation
- Admin dashboard for document management
- Blockchain-based audit trail

### 2. Student Freelance Platform
- Student and client dashboards
- Smart contract-based escrow system
- Document verification integration
- Secure payment processing

## 🔗 Integration Features

- **Unified User Profiles**: Combined student credentials and freelance capabilities
- **Smart Contract Escrow**: Secure payment handling with Aiken smart contracts
- **Document Verification**: Blockchain-based document authenticity verification
- **Platform Fee**: 5% fee on successful transactions

## 🛠️ Technical Stack

- **Frontend**: HTML, CSS, JavaScript
- **Backend**: Node.js, Express.js
- **Blockchain**: Cardano (Preview Network)
- **Smart Contracts**: Aiken
- **APIs**: Blockfrost API
- **Authentication**: JWT

## 📋 Prerequisites

- Node.js (v14 or higher)
- Cardano wallet with test ADA
- Blockfrost API key
- Cardano seed phrase

## 🚀 Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd student-platform
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory:
```env
PORT=3000
JWT_SECRET=your-jwt-secret
BLOCKFROST_API_KEY=your-blockfrost-api-key
CARDANO_SEED_PHRASE=your-cardano-seed-phrase
ESCROW_VALIDATOR_ADDRESS=your-escrow-validator-address
PLATFORM_WALLET_ADDRESS=your-platform-wallet-address
```

4. Start the server:
```bash
npm start
```

## 📁 Project Structure

```
student-platform/
├── public/
│   ├── betaedu/           # Document verification system
│   │   ├── index.html
│   │   ├── verify.html
│   │   └── admin.html
│   ├── js/               # JavaScript files
│   ├── css/              # Stylesheets
│   └── landing.html      # Freelance platform landing
├── server.js            # Main server file
├── package.json
└── README.md
```

## 🔐 Security Features

- JWT-based authentication
- Password hashing with bcrypt
- Smart contract-based escrow
- Blockchain-verified documents
- Secure file uploads

## 💰 Smart Contract Integration

The platform uses Aiken smart contracts for:
- Document verification
- Payment escrow
- Platform fee management

## 📱 API Endpoints

### Document Verification
- `GET /verify-certificate` - Verify a certificate
- `GET /admin-dashboard` - Admin dashboard

### Freelance Platform
- `GET /freelance` - Landing page
- `GET /freelance/login` - Login page
- `GET /freelance/register` - Registration page
- `GET /freelance/client-dashboard` - Client dashboard
- `GET /freelance/student-dashboard` - Student dashboard

### API Routes
- `POST /api/register` - User registration
- `POST /api/login` - User login
- `POST /api/profile` - Update user profile
- `GET /api/profile/:userId` - Get user profile
- `POST /api/escrow` - Create escrow contract
- `POST /api/escrow/:txHash/complete` - Complete escrow contract

## 🔄 Workflow

1. **Student Registration**
   - Create account
   - Upload and verify documents
   - Set up freelance profile

2. **Client Registration**
   - Create account
   - Fund wallet
   - Post jobs

3. **Job Process**
   - Client posts job
   - Student applies
   - Smart contract escrow created
   - Work completed
   - Payment released

## 🧪 Testing

1. Start the server:
```bash
npm start
```

2. Access the applications:
   - Document Verification: `http://localhost:3000/`
   - Freelance Platform: `http://localhost:3000/freelance`

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
 