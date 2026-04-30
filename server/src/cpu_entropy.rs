#[cfg(any(target_arch = "x86_64"))]
#[allow(unused)]
pub fn get_entropy_from_cpu() {
    let Some(raw_value) = gen_rdseed(20) else {
        return;
    };
    println!("{}",raw_value);
}

/// Loop to gather entropy from "try_rdseed()". Returns None if attempt is blank
pub fn gen_rdseed(loop_amount: u16) -> Option<u64> {
    for _ in 0..loop_amount {
        let attempt = try_rdseed();
        if attempt.is_some() {
            return attempt;
        }
        std::hint::spin_loop();
    }
    None
}

/// Loop to gather entropy from "try_rdrand()". Returns None if blank
pub fn gen_rdrand(loop_amount: u16) -> Option<u64> {
    for _ in 0..loop_amount {
        let attempt = try_rdrand();
        if attempt.is_some() {
            return attempt;
        }
        std::hint::spin_loop();
    }
    None
}

/// Does a query to "rdseed" processor register and returns None if status == 0 or unsupported feature
pub fn try_rdseed() -> Option<u64> {
    if is_x86_feature_detected!("rdseed") {
        unsafe {
            let mut val: u64 = 0;
            let status: i32 = std::arch::x86_64::_rdseed64_step(&mut val);
            if status == 1 {
                Some(val)
            } else {
                None
            }
        }
    } else {
        None
    }
}

/// Does a query to "rdrand" processor register and returns None if status == 0 or unsupported feature
pub fn try_rdrand() -> Option<u64> {
    if is_x86_feature_detected!("rdrand") {
        unsafe {
            let mut val: u64 = 0;
            let status: i32 = std::arch::x86_64::_rdrand64_step(&mut val);
            if status == 1 {
                Some(val)
            } else {
                None
            }
        }
    } else {
        None
    }
}