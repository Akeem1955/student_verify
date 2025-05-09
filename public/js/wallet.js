// Wallet Module
const Wallet = {
    // State
    state: {
        balance: 0,
        address: '',
        transactions: []
    },

    // Initialize wallet module
    init() {
        this.loadWalletInfo();
        this.setupEventListeners();
    },

    // Setup event listeners
    setupEventListeners() {
        const copyBtn = document.getElementById('copyWalletBtn');
        if (copyBtn) {
            copyBtn.addEventListener('click', () => this.copyWalletAddress());
        }
    },

    // Load wallet information
    async loadWalletInfo() {
        try {
            const response = await fetch('/api/wallet', {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });

            if (!response.ok) throw new Error('Failed to load wallet info');
            const wallet = await response.json();
            this.updateWalletInfo(wallet);
        } catch (error) {
            console.error('Error loading wallet info:', error);
            StudentDashboard.showError('Failed to load wallet information');
        }
    },

    // Update wallet information in UI
    updateWalletInfo(wallet) {
        this.state.balance = wallet.balance;
        this.state.address = wallet.address;
        this.state.transactions = wallet.transactions || [];

        const balanceElement = document.getElementById('walletBalance');
        const addressElement = document.getElementById('walletAddress');
        
        if (balanceElement) {
            balanceElement.textContent = `₳${wallet.balance}`;
        }
        
        if (addressElement) {
            addressElement.textContent = wallet.address;
        }

        this.renderTransactions();
    },

    // Copy wallet address to clipboard
    copyWalletAddress() {
        navigator.clipboard.writeText(this.state.address).then(() => {
            StudentDashboard.showSuccess('Wallet address copied to clipboard');
        }).catch(() => {
            StudentDashboard.showError('Failed to copy wallet address');
        });
    },

    // Render transactions
    renderTransactions() {
        const transactionList = document.getElementById('transactionList');
        if (!transactionList) return;

        transactionList.innerHTML = this.state.transactions.length ? '' : '<p>No transactions yet</p>';
        
        this.state.transactions.forEach(tx => {
            const txElement = document.createElement('div');
            txElement.className = `transaction-item ${tx.type}`;
            txElement.innerHTML = `
                <div class="transaction-info">
                    <span class="transaction-type">${tx.type}</span>
                    <span class="transaction-amount">${tx.amount} ADA</span>
                </div>
                <div class="transaction-details">
                    <span class="transaction-date">${new Date(tx.timestamp * 1000).toLocaleString()}</span>
                    <span class="transaction-status">${tx.status}</span>
                </div>
            `;
            transactionList.appendChild(txElement);
        });
    },

    // Show wallet modal
    showWalletModal() {
        const walletModal = document.getElementById('walletModal');
        if (!walletModal) return;

        walletModal.style.display = 'block';
        this.loadWalletInfo(); // Refresh wallet info when modal is opened
    },

    // Hide wallet modal
    hideWalletModal() {
        const walletModal = document.getElementById('walletModal');
        if (walletModal) {
            walletModal.style.display = 'none';
        }
    }
};

// Export the module
window.Wallet = Wallet; 