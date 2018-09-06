extern crate secp256k1;
extern crate sha2;
extern crate ring;
pub mod hash;

use std::ops::Add;
use std::ops::Mul;
use hash::hash_into_group;
use secp256k1::curve::{Affine, Jacobian, Scalar, ECMULT_GEN_CONTEXT, ECMULT_CONTEXT};
use ring::rand::{SystemRandom, SecureRandom};
use sha2::{Sha256, Digest};

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
}

fn get_random_integer()-> Result<Scalar, Error> {
    let random:SystemRandom = SystemRandom::new();
    let mut bytes:[u8;32] = [0;32];
    let mut value = Scalar::default();
    match random.fill(&mut bytes){
        Ok(_) => {
            value.set_b32(&mut bytes);
            Ok(value)
        },
        Err(_) => Err(Error::UnhandledError())
    }
}
fn copy_elements(to:&mut [u8], from: &[u8]){
    let length = to.len();
    for i in 0..length{
        to[i]=from[i];
    }
}
impl VRFContext{
    pub fn new(secret_key:Scalar) -> VRFContext{
        VRFContext{
            public_key: {
                let mut point = Jacobian::default();
                ECMULT_GEN_CONTEXT.ecmult_gen(&mut point, &secret_key);
                point.x.normalize();
                point.y.normalize();
                point
            },
            secret_key: secret_key,

        }
    }

    pub fn new_from_public_key(public_key:Jacobian) -> VRFContext{
        VRFContext{
            public_key: public_key,
            secret_key: Scalar::default(),

        }
    }



    fn get_sha2_of_values(&self, l:&Jacobian, r:&Jacobian) -> Scalar{
        let mut oracle_input = [0u8;192];
        let mut oracle_output = [0u8;32];

        let mut affine_l = Affine::default();
        affine_l.set_gej(l);
        affine_l.x.normalize();
        affine_l.y.normalize();
        copy_elements(&mut oracle_input[0..32], &affine_l.x.b32());
        copy_elements(&mut oracle_input[32..64], &affine_l.y.b32());

        let mut affine_r = Affine::default();
        affine_r.set_gej(r);
        affine_r.x.normalize();
        affine_r.y.normalize();
        copy_elements(&mut oracle_input[64..96], &affine_r.x.b32());
        copy_elements(&mut oracle_input[96..128], &affine_r.y.b32());

        copy_elements(&mut oracle_input[128..160], &self.public_key.x.b32());
        copy_elements(&mut oracle_input[160..192], &self.public_key.y.b32());

        let mut sha = Sha256::new();

        sha.input(&oracle_input);
        let oracle_outputv = sha.result();
        copy_elements(&mut oracle_output, &oracle_outputv[..]);
        let mut value = Scalar::default();
        value.set_b32(&mut oracle_output);
        return value;
    }

    pub fn generate_vrf(&self, data: &[u8]) -> Result<VRF,Error>{
        let mut public_key = Affine::default();
        public_key.set_gej(&self.public_key);
        match hash_into_group(data){
            Ok(h) => {
                let mut i_point = Jacobian::default();
                ECMULT_CONTEXT.ecmult_const(&mut i_point, &h, &self.secret_key);
                match get_random_integer(){
                    Ok(w)=>{
                        let mut l = Jacobian::default();
                        ECMULT_GEN_CONTEXT.ecmult_gen(&mut l, &w);
                        let mut r = Jacobian::default();
                        ECMULT_CONTEXT.ecmult_const(&mut r, &h, &w);


                        let oracle_output = self.get_sha2_of_values(&l, &r);

                        let d = oracle_output.clone();
                        let xd = oracle_output.mul(self.secret_key.clone());
                        let neg_xd = xd.neg();
                        let c = w.add(neg_xd);
                        Ok(VRF{
                            hash_input:i_point,
                            left_scaler:c,
                            right_scaler:d
                        })
                    },
                    Err(_)=> Err(Error::UnhandledError())
                }

            },
            Err(_) => Err(Error::UnhandledError())
        }
    }

    pub fn verify_vrf(&self, vrf:&VRF, data: &[u8]) -> Result<bool, Error>{
        match hash_into_group(data) {
            Ok(h) => {
                let mut l = Jacobian::default();
                ECMULT_CONTEXT.ecmult(&mut l, &self.public_key, &vrf.right_scaler, &vrf.left_scaler);

                let mut rl = Jacobian::default();
                ECMULT_CONTEXT.ecmult_const(&mut rl, &h, &vrf.left_scaler);

                let mut rra = Jacobian::default();
                let mut i = Affine::default();
                i.set_gej(&vrf.hash_input);
                ECMULT_CONTEXT.ecmult_const(&mut rra, &i, &vrf.right_scaler);
                let mut rr = Affine::default();
                rr.set_gej(&rra);

                let r = rl.add_ge(&rr);
                let oracle_output = self.get_sha2_of_values(&l,&r);

                if oracle_output == vrf.right_scaler {
                    Ok(true)
                }else{
                    Ok(false)
                }

            },
            Err(_) => Err(Error::UnhandledError())
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        match super::get_random_integer(){
            Ok(secret_key) =>{
                match super::get_random_integer(){
                    Ok(data) =>{
                        let mut data_b = [0u8;32];
                        data.fill_b32(&mut data_b);
                        let context = super::VRFContext::new(secret_key);
                        match context.generate_vrf(&data_b){
                            Ok(vrf) =>{
                                match context.verify_vrf(&vrf,&data_b){
                                    Ok(result) => assert!(result),
                                    Err(_) => panic!()
                                }
                            },
                            Err(_) => panic!()
                        }
                    },
                    Err(_) => panic!()
                }
            },
            Err(_) => panic!()
        }
    }

    #[test]
    fn check_fail_public_key(){
        match super::get_random_integer(){
            Ok(secret_key) =>{
                match super::get_random_integer(){
                    Ok(data) =>{
                        let mut data_b = [0u8;32];
                        data.fill_b32(&mut data_b);
                        let context = super::VRFContext::new(secret_key);
                        match context.generate_vrf(&data_b){
                            Ok(vrf) =>{
                                match super::get_random_integer(){
                                    Ok(new_key) =>{
                                        let context = super::VRFContext::new(new_key);
                                        match context.verify_vrf(&vrf,&data_b){
                                            Ok(result) => assert!(!result),
                                            Err(_) => panic!()
                                        }
                                    },
                                    Err(_) => panic!()
                                }

                            },
                            Err(_) => panic!()
                        }
                    },
                    Err(_) => panic!()
                }
            },
            Err(_) => panic!()
        }
    }

    #[test]
    fn check_fail_data(){
        match super::get_random_integer(){
            Ok(secret_key) =>{
                match super::get_random_integer(){
                    Ok(data) =>{
                        let mut data_b = [0u8;32];
                        data.fill_b32(&mut data_b);
                        let context = super::VRFContext::new(secret_key);
                        match context.generate_vrf(&data_b){
                            Ok(vrf) =>{
                                match super::get_random_integer(){
                                    Ok(new_data) =>{
                                        let mut data_b2 = [0u8;32];
                                        new_data.fill_b32(&mut data_b2);
                                        match context.verify_vrf(&vrf,&data_b2){
                                            Ok(result) => assert!(!result),
                                            Err(_) => panic!()
                                        }
                                    },
                                    Err(_) => panic!()
                                }

                            },
                            Err(_) => panic!()
                        }
                    },
                    Err(_) => panic!()
                }
            },
            Err(_) => panic!()
        }
    }


}
