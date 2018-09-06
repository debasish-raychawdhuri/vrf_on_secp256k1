use secp256k1::curve::{Affine,Field};

use super::Error;

use sha2::{Sha256, Digest};


pub fn hash_into_group(data: &[u8])-> Result<Affine, Error>{


    let mut nounce_byte = [0u8];
    let mut nounce:u8 = 0;
    let mut hash:[u8;32] = [0; 32];
    let mut hash2:[u8; 32] = [0; 32];
    loop{
        let mut sha = Sha256::new();
        if nounce>254 {
            break Err(Error::HashNotComputable(String::from("Hash is not computable")));;
        }
        nounce_byte[0]=nounce;
        sha.input(&data);
        sha.input(&nounce_byte);
        let hashv = sha.result();
        super::copy_elements(&mut hash, &hashv[..]);


        let mut x_coord = Field::default();
        if !x_coord.set_b32(&hash) {
            nounce = nounce+1;
            continue;
        }
        let mut affine_point = Affine::default();

        if !affine_point.set_xquad(&x_coord) {
            nounce = nounce+1;
            continue;
        }

        let mut sha2 = Sha256::new();
        sha2.input(&hash);
        let hashv2 = sha2.result();
        super::copy_elements(&mut hash2, &hashv2[..]);
        //Even though all curve points would not be possible,
        //it is better to use both halves of the curve.
        if hash2[0] & 0x01 == 1 {
            affine_point = affine_point.neg();
        }
        //println!("{:?}", &affine_point);
        //The cofactor is 1 meaning all curve points are in the group. So, no more check requried
        break Ok(affine_point);
    }
}
