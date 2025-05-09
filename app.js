// DOM Elements
const studentEscrow = {
    amount: document.getElementById('studentAmount'),
    deadline: document.getElementById('studentDeadline'),
    status: document.getElementById('studentStatus'),
    claimBtn: document.getElementById('claimPaymentBtn'),
    message: document.getElementById('studentMessage')
};

const clientEscrow = {
    address: document.getElementById('studentAddress'),
    amount: document.getElementById('clientAmount'),
    deadline: document.getElementById('clientDeadline'),
    createBtn: document.getElementById('createEscrowBtn'),
    approveBtn: document.getElementById('approveWorkBtn'),
    refundBtn: document.getElementById('claimRefundBtn'),
    message: document.getElementById('clientMessage')
};

// Mock data - replace with actual data from your backend
let currentEscrow = {
    utxo: 'mock_utxo_id',
    amount: 1000000, // 1 ADA in lovelace
    deadline: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days from now
    studentAddress: 'addr_test1...'
};

// Update UI with escrow data
function updateEscrowUI() {
    // Student view
    studentEscrow.amount.textContent = (currentEscrow.amount / 1000000).toFixed(2);
    studentEscrow.deadline.textContent = new Date(currentEscrow.deadline).toLocaleString();
    studentEscrow.status.textContent = isDeadlinePassed() ? 'Deadline Passed' : 'Active';

    // Client view
    clientEscrow.address.textContent = currentEscrow.studentAddress;
    clientEscrow.amount.textContent = (currentEscrow.amount / 1000000).toFixed(2);
    clientEscrow.deadline.textContent = new Date(currentEscrow.deadline).toLocaleString();
}

// Helper functions
function isDeadlinePassed() {
    return Date.now() > currentEscrow.deadline;
}

function showMessage(element, message, isError = false) {
    element.textContent = message;
    element.className = `message ${isError ? 'error' : 'success'}`;
    setTimeout(() => {
        element.textContent = '';
        element.className = 'message';
    }, 5000);
}

// Event Handlers
studentEscrow.claimBtn.addEventListener('click', async () => {
    try {
        studentEscrow.claimBtn.disabled = true;
        const txHash = await escrow.claimPayment(currentEscrow.utxo);
        showMessage(studentEscrow.message, `Payment claimed successfully! Transaction: ${txHash}`);
    } catch (error) {
        showMessage(studentEscrow.message, error.message, true);
    } finally {
        studentEscrow.claimBtn.disabled = false;
    }
});

clientEscrow.createBtn.addEventListener('click', async () => {
    try {
        clientEscrow.createBtn.disabled = true;
        const txHash = await escrow.createEscrow(
            currentEscrow.studentAddress,
            currentEscrow.amount,
            currentEscrow.deadline
        );
        showMessage(clientEscrow.message, `Escrow created successfully! Transaction: ${txHash}`);
    } catch (error) {
        showMessage(clientEscrow.message, error.message, true);
    } finally {
        clientEscrow.createBtn.disabled = false;
    }
});

clientEscrow.approveBtn.addEventListener('click', async () => {
    try {
        clientEscrow.approveBtn.disabled = true;
        const txHash = await escrow.approveWork(currentEscrow.utxo);
        showMessage(clientEscrow.message, `Work approved successfully! Transaction: ${txHash}`);
    } catch (error) {
        showMessage(clientEscrow.message, error.message, true);
    } finally {
        clientEscrow.approveBtn.disabled = false;
    }
});

clientEscrow.refundBtn.addEventListener('click', async () => {
    try {
        clientEscrow.refundBtn.disabled = true;
        const txHash = await escrow.claimRefund(currentEscrow.utxo);
        showMessage(clientEscrow.message, `Refund claimed successfully! Transaction: ${txHash}`);
    } catch (error) {
        showMessage(clientEscrow.message, error.message, true);
    } finally {
        clientEscrow.refundBtn.disabled = false;
    }
});

// Initialize UI
updateEscrowUI(); 