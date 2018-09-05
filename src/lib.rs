extern crate secp256k1;
extern crate crypto;
pub mod hash;

use hash::hash_into_group;
use secp256k1::curve::{Affine, Jacobian,Field, Scalar, ECMultGenContext, ECMultContext, ECMULT_GEN_CONTEXT, ECMULT_CONTEXT, AFFINE_G};

pub struct VRF {
    hash_input : Jacobian,
    left_scaler : Scalar,
    right_scaler : Scalar
}

pub enum Error {
    HashNotComputable(String),
    UnhandledError()
}

pub struct VRFContext {
    secret_key:Scalar,
    public_key:Jacobian,
    base_point:Jacobian
}

impl VRFContext{
    fn new(secret_key:Scalar) -> VRFContext{
        VRFContext{
            base_point:{
                let mut point = Jacobian::default();
                point.set_ge(&AFFINE_G);
                point
            },
            public_key: {
                let mut point = Jacobian::default();
                ECMULT_GEN_CONTEXT.ecmult_gen(&mut point, &secret_key);
                point
            },
            secret_key: secret_key
        }
    }

    //TODO complete this implementation
    fn generateVRF(&self, data: &[u8]) -> Result<VRF,Error>{
        match hash_into_group(data){
            Ok(h) => {
                let mut i_point = Jacobian::default();
                ECMULT_CONTEXT.ecmult_const(&mut i_point, &h, &self.secret_key);
                Ok(VRF{
                    hash_input:i_point,
                    left_scaler:Scalar::default(),
                    right_scaler:Scalar::default()
                })
            },
            Err(_) => Err(Error::UnhandledError())
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
