use aiken/transaction.{ScriptContext, TxInInfo, TxOut}
use aiken/list
use aiken/math
use aiken/bytearray
use aiken/bool

test "test_job_creation" {
    let datum = JobDatum {
        job_id: bytearray.from_hex("1234"),
        client_address: bytearray.from_hex("client123"),
        student_address: bytearray.from_hex("student123"),
        payment_amount: 1000000,
        status: JobStatus.Started
    }
    
    let redeemer = StartJob
    let ctx = ScriptContext {
        tx: Transaction {
            inputs: [],
            outputs: [],
            fee: 0,
            mint: [],
            dcert: [],
            wdrl: [],
            valid_range: TimeRange { start: 0, end: 0 },
            update: None
        },
        script_purpose: Spending { parameters: bytearray.from_hex("platform123") }
    }
    
    let result = freelance_escrow.spend(datum, redeemer, ctx)
    expect result == True
}

test "test_job_completion" {
    let datum = JobDatum {
        job_id: bytearray.from_hex("1234"),
        client_address: bytearray.from_hex("client123"),
        student_address: bytearray.from_hex("student123"),
        payment_amount: 1000000,
        status: JobStatus.Started
    }
    
    let redeemer = CompleteJob
    let platform_address = bytearray.from_hex("platform123")
    let student_address = bytearray.from_hex("student123")
    
    let platform_fee = calculate_platform_fee(datum.payment_amount)
    let student_amount = calculate_student_amount(datum.payment_amount)
    
    let outputs = [
        TxOut {
            address: platform_address,
            value: platform_fee,
            datum: None
        },
        TxOut {
            address: student_address,
            value: student_amount,
            datum: None
        }
    ]
    
    let ctx = ScriptContext {
        tx: Transaction {
            inputs: [],
            outputs: outputs,
            fee: 0,
            mint: [],
            dcert: [],
            wdrl: [],
            valid_range: TimeRange { start: 0, end: 0 },
            update: None
        },
        script_purpose: Spending { parameters: platform_address }
    }
    
    let result = freelance_escrow.spend(datum, redeemer, ctx)
    expect result == True
}

test "test_platform_fee_calculation" {
    let amount = 1000000
    let fee = calculate_platform_fee(amount)
    let student_amount = calculate_student_amount(amount)
    
    expect fee == 50000
    expect student_amount == 950000
    expect amount == fee + student_amount
} 