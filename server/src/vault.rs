use argon2::{self, Argon2, Params};
#[allow(unused)]
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum SecurityProfile {
    Fast = 1,
    Standard = 2,
    /*Paranoid = 3,
    Extreme = 4*/
}

impl SecurityProfile {
    #[allow(unused)]
    pub fn from_u8 (n: u8) -> Option<Self>{
        match n {
            1 => Some(Self::Fast),
            2 => Some(Self::Standard),
            /*3 => Some(Self::Paranoid),
            4 => Some(Self::Extreme),*/
            _ => None
        }
    }
}

pub fn get_master_key(password: &str, entropy: &[u8], profile: SecurityProfile) -> Result<[u8; 32], String>{
    //стоит задавать m_cost (1 параметр) как желаемое МБ * 1024 => (64 (МБ) * 1024)
    let (m,t,p) = match profile {
    SecurityProfile::Fast => (64 * 1024, 4, 1),
    SecurityProfile::Standard => (128 * 1024, 4, 1),
    /*SecurityProfile::Paranoid => (512 * 1024, 8, 4),
    SecurityProfile::Extreme => (1024 * 1024, 12, 4),*/
};
    let params = Params::new(m, t, p, Some(32))
        .expect("Ошибка в параметрах Argon2id");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut output = [0u8; 32];

    argon2.hash_password_into(password.as_bytes(), entropy, &mut output).map_err(|e| e.to_string()).map(|_| output)
}