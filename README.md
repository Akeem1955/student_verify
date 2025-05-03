# Student Document Verification System

A blockchain-based system for verifying student documents using the Cardano blockchain. This system allows administrators to upload student documents and users to verify their authenticity.

## Features

- Document upload and registration on Cardano blockchain
- Document verification using blockchain records
- In-memory hash registry for quick lookups
- Caching system for improved performance
- Admin portal for document management
- User-friendly verification interface

## Prerequisites

- Node.js (v16 or higher)
- npm (Node Package Manager)
- A Blockfrost API key (for Cardano blockchain interaction)
- A Cardano wallet with some ADA (for transaction fees)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd student-verify
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory with the following variables:
```env
PORT=3000
BLOCKFROST_API_KEY=your_blockfrost_api_key
CARDANO_SEED_PHRASE=your_wallet_seed_phrase
```

## Configuration

### Blockfrost API Key
1. Go to [Blockfrost](https://blockfrost.io/)
2. Create an account and get an API key
3. Add the API key to your `.env` file

### Cardano Wallet
1. Create a Cardano wallet (e.g., using Daedalus or Yoroi)
2. Get your seed phrase (24 words)
3. Add the seed phrase to your `.env` file
4. Ensure your wallet has some ADA for transaction fees

## Running the Application

1. Start the server:
```bash
npm start
```

2. Access the application:
- Main page: http://localhost:3000
- Admin portal: http://localhost:3000/admin
- Verification page: http://localhost:3000/verify

## Usage

### Admin Portal
1. Access the admin portal at `/admin`
2. Fill in the student details:
   - Student Name
   - Document Type
   - Description
3. Upload the document
4. The system will:
   - Calculate the document hash
   - Store the hash on the Cardano blockchain
   - Show the transaction ID and hash

### Document Verification
1. Access the verification page at `/verify`
2. Upload the document to verify
3. The system will:
   - Calculate the document hash
   - Check the blockchain for the hash
   - Display verification results

## Technical Details

### Metadata Structure
The system uses a custom metadata label (`9876549875324532`) on the Cardano blockchain with the following structure:
```json
{
  "9876549875324532": {
    "hash": "document_hash",
    "type": "document_type",
    "student": "student_name",
    "timestamp": "unix_timestamp"
  }
}
```

### Caching System
- Verification results are cached for 1 hour
- Metadata is cached for 5 minutes
- In-memory hash registry for quick lookups

### Security Considerations
- Never share your `.env` file
- Keep your seed phrase secure
- Use HTTPS in production
- Implement proper authentication for the admin portal

## API Endpoints

- `GET /`: Main page
- `GET /admin`: Admin portal
- `GET /verify`: Verification page
- `POST /api/upload`: Upload document (admin)
- `POST /api/verify`: Verify document
- `GET /api/health`: Health check
- `POST /api/admin/update-registry`: Force registry update (admin)

## Error Handling

The system handles various error cases:
- Network issues
- Invalid documents
- Blockchain transaction failures
- Rate limiting
- API key issues

## Performance Optimization

- In-memory hash registry for quick lookups
- Caching system for verification results
- Optimized blockchain queries
- Batch processing for registry updates

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the repository or contact the maintainers. 