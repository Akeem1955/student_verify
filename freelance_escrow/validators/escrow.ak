use aiken/collection/list
use cardano/transaction.{OutputReference, Transaction, ValidityRange}
use aiken/crypto.{VerificationKeyHash}
use aiken/interval.{Interval, Finite, NegativeInfinity, PositiveInfinity}

// Helper functions
fn is_buyer_signed(tx: Transaction, buyer: VerificationKeyHash) -> Bool {
  list.has(tx.extra_signatories, buyer)
}

fn is_seller_signed(tx: Transaction, seller: VerificationKeyHash) -> Bool {
  list.has(tx.extra_signatories, seller)
}

fn is_deadline_passed(validity_range: ValidityRange, deadline: Int) -> Bool {
  when validity_range.lower_bound.bound_type is {
    Finite(n) -> n > deadline
    NegativeInfinity -> False
    PositiveInfinity -> True
  }
}

// Datum that will be attached when locking funds in the escrow
pub type EscrowDatum {
  buyer: VerificationKeyHash,
  seller: VerificationKeyHash,
  amount: Int,
  deadline: Int,
}

// Redeemer for spending from the escrow
pub type EscrowRedeemer {
  action: EscrowAction,
}

// Possible actions that can be taken on the escrow
pub type EscrowAction {
  // Buyer can claim refund if deadline passed
  ClaimRefund
  // Seller can claim payment if buyer approves
  ClaimPayment
  // Buyer can approve the work and release payment
  ApproveWork
}

validator escrow {
  spend(datum: Option<EscrowDatum>, redeemer: EscrowRedeemer, _utxo: OutputReference, tx: Transaction) {
    expect Some(EscrowDatum { buyer, seller, deadline, .. }) = datum

    when redeemer.action is {
      ClaimRefund -> 
        // Buyer can claim refund if deadline has passed
        is_buyer_signed(tx, buyer) && is_deadline_passed(tx.validity_range, deadline)
      ClaimPayment -> 
        // Seller can claim payment if buyer approves
        is_seller_signed(tx, seller) && is_buyer_signed(tx, buyer)
      ApproveWork -> 
        // Buyer can approve the work and release payment
        is_buyer_signed(tx, buyer)
    }
  }
} 