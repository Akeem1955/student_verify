import { ForgeScript, Transaction } from '@meshsdk/core';
import { readFileSync } from "fs";
import { Lucid } from "lucid-cardano";

// Initialize wallet with your configuration
const wallet = {
    networkId: 0, // 0 for testnet, 1 for mainnet
    getUsedAddresses: async () => {
        // Implement actual wallet integration here
        return ['addr_test1...'];
    },
    signTx: async (tx) => {
        // Implement actual signing here
        return tx;
    },
    submitTx: async (tx) => {
        // Implement actual transaction submission here
        return 'tx_hash_' + Math.random().toString(36).substr(2, 9);
    }
};

// Get script address
function getScript() {
    const scriptKeyHash = process.env.SCRIPT_KEY_HASH || '';
    return {
        script: { keyHash: scriptKeyHash },
        scriptAddr: process.env.SCRIPT_ADDRESS || 'addr_test1...'
    };
}

// Get transaction builder
function getTxBuilder() {
    return {
        txOut: (addr, assets) => {
            console.log('Creating transaction output to:', addr, assets);
            return this;
        },
        txOutDatumHashValue: (datum) => {
            console.log('Adding datum:', datum);
            return this;
        },
        changeAddress: (addr) => {
            console.log('Setting change address:', addr);
            return this;
        },
        complete: async () => {
            console.log('Completing transaction');
            return 'tx_hex';
        }
    };
}

// Escrow contract functions
const escrow = {
    async createEscrow(sellerAddress, amount, deadline) {
        try {
            const { scriptAddr } = getScript();
            const buyerAddress = (await wallet.getUsedAddresses())[0];
            
            // Create the datum
            const datum = {
                buyer: buyerAddress,
                seller: sellerAddress,
                amount,
                deadline
            };

            // Build transaction
            const txBuilder = getTxBuilder();
            await txBuilder
                .txOut(scriptAddr, [{ unit: 'lovelace', quantity: amount.toString() }])
                .txOutDatumHashValue(datum)
                .changeAddress(buyerAddress)
                .complete();

            const unsignedTx = txBuilder.txHex;
            const signedTx = await wallet.signTx(unsignedTx);
            const txHash = await wallet.submitTx(signedTx);

            return txHash;
        } catch (error) {
            console.error('Error creating escrow:', error);
            throw error;
        }
    },

    async approveWork(escrowUtxo) {
        try {
            const { scriptAddr } = getScript();
            const buyerAddress = (await wallet.getUsedAddresses())[0];

            const redeemer = {
                action: 'ApproveWork'
            };

            const txBuilder = getTxBuilder();
            await txBuilder
                .spendValue(escrowUtxo, scriptAddr)
                .txOut(buyerAddress, [{ unit: 'lovelace', quantity: '0' }])
                .txOutDatumValue(redeemer)
                .changeAddress(buyerAddress)
                .complete();

            const unsignedTx = txBuilder.txHex;
            const signedTx = await wallet.signTx(unsignedTx);
            const txHash = await wallet.submitTx(signedTx);

            return txHash;
        } catch (error) {
            console.error('Error approving work:', error);
            throw error;
        }
    },

    async claimPayment(escrowUtxo) {
        try {
            const { scriptAddr } = getScript();
            const sellerAddress = (await wallet.getUsedAddresses())[0];

            const redeemer = {
                action: 'ClaimPayment'
            };

            const txBuilder = getTxBuilder();
            await txBuilder
                .spendValue(escrowUtxo, scriptAddr)
                .txOut(sellerAddress, [{ unit: 'lovelace', quantity: '0' }])
                .txOutDatumValue(redeemer)
                .changeAddress(sellerAddress)
                .complete();

            const unsignedTx = txBuilder.txHex;
            const signedTx = await wallet.signTx(unsignedTx);
            const txHash = await wallet.submitTx(signedTx);

            return txHash;
        } catch (error) {
            console.error('Error claiming payment:', error);
            throw error;
        }
    },

    async claimRefund(escrowUtxo) {
        try {
            const { scriptAddr } = getScript();
            const buyerAddress = (await wallet.getUsedAddresses())[0];

            const redeemer = {
                action: 'ClaimRefund'
            };

            const txBuilder = getTxBuilder();
            await txBuilder
                .spendValue(escrowUtxo, scriptAddr)
                .txOut(buyerAddress, [{ unit: 'lovelace', quantity: '0' }])
                .txOutDatumValue(redeemer)
                .changeAddress(buyerAddress)
                .complete();

            const unsignedTx = txBuilder.txHex;
            const signedTx = await wallet.signTx(unsignedTx);
            const txHash = await wallet.submitTx(signedTx);

            return txHash;
        } catch (error) {
            console.error('Error claiming refund:', error);
            throw error;
        }
    }
};

/**
 * Loads the compiled Aiken contract from plutus.json and derives the script address using Lucid.
 * Assumes Lucid is already initialized and passed as an argument.
 * @param {Lucid} lucid - An initialized Lucid instance
 * @returns {Promise<string>} - The script address derived from the Aiken contract
 */
export async function getAikenScriptAddress(lucid) {
    // Load the compiled Aiken contract
    const plutusJson = JSON.parse(readFileSync("./freelance_escrow/plutus.json", "utf8"));
    // Find the validator (adjust the title if needed)
    const validator = plutusJson.validators.find(v => v.title === "escrow.escrow.spend");
    if (!validator) throw new Error("Validator not found in plutus.json");
    // Get the CBOR code
    const scriptCbor = validator.compiledCode;
    // Create a Lucid script object
    const script = {
        type: "PlutusV2", // Use PlutusV3 as per your contract
        script: scriptCbor,
    };
    // Derive the script address
    return lucid.utils.validatorToAddress(script);
}

export async function getAikenScript(lucid) {
    // Load the compiled Aiken contract
    const plutusJson = JSON.parse(readFileSync("./freelance_escrow/plutus.json", "utf8"));
    // Find the validator (adjust the title if needed)
    const validator = plutusJson.validators.find(v => v.title === "escrow.escrow.spend");
    if (!validator) throw new Error("Validator not found in plutus.json");
    // Get the CBOR code
    const scriptCbor = validator.compiledCode;
    // Create a Lucid script object
    const script = {
        type: "PlutusV2", // Use PlutusV3 as per your contract
        script: scriptCbor,
    };
    // Derive the script address
    return script;
}

export default escrow; 