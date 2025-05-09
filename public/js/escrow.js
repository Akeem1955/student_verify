// Escrow contract interaction module
class EscrowManager {
    constructor() {
        this.platformFeePercentage = 5; // 5% platform fee
        this.platformAddress = 'addr_test1qp2zaa5z74telpcag6dnxhle4gjl9j74660f8w0a00q0fwl0u42l9qnj0vz7dkvcs98vptzf7h27maqn5aa4k2amx08sqqqa9r';
    }

    // Create an escrow contract using Aiken contract
    async createEscrow(clientId, studentId, amount, autoDeduct = false) {
        try {
            const response = await fetch('/api/escrow', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    clientId,
                    studentId,
                    amount,
                    autoDeduct
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || 'Failed to create escrow contract');
            }

            const result = await response.json();
            
            // Validate the response contains required fields
            if (!result.txHash) {
                throw new Error('Invalid response from escrow creation');
            }

            return {
                success: true,
                txHash: result.txHash,
                message: 'Escrow contract created successfully'
            };
        } catch (error) {
            console.error('Error creating escrow:', error);
            return {
                success: false,
                message: error.message || 'Failed to create escrow contract'
            };
        }
    }

    // Complete an escrow contract
    async completeEscrow(txHash, clientId, studentId) {
        try {
            const response = await fetch(`/api/escrow/${txHash}/complete`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    clientId,
                    studentId
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || 'Failed to complete escrow contract');
            }

            const result = await response.json();
            return {
                success: true,
                txHash: result.txHash,
                message: 'Escrow contract completed successfully'
            };
        } catch (error) {
            console.error('Error completing escrow:', error);
            return {
                success: false,
                message: error.message || 'Failed to complete escrow contract'
            };
        }
    }

    // Get escrow status
    async getEscrowStatus(txHash) {
        try {
            const response = await fetch(`/api/escrow/${txHash}/status`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || 'Failed to get escrow status');
            }

            const result = await response.json();
            return {
                status: result.status,
                message: result.message
            };
        } catch (error) {
            console.error('Error getting escrow status:', error);
            return {
                status: 'failed',
                message: error.message || 'Failed to get escrow status'
            };
        }
    }

    // Calculate platform fee
    calculatePlatformFee(amount) {
        return Math.floor(amount * (this.platformFeePercentage / 100));
    }

    // Calculate student amount
    calculateStudentAmount(amount) {
        return amount - this.calculatePlatformFee(amount);
    }
}

// Export the EscrowManager class
export default EscrowManager; 