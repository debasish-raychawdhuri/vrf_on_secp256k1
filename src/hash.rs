use secp256k1::curve::{Affine,Field};

use super::Error;

use crypto::{sha2::Sha256, digest::Digest};


pub fn hash_into_group(data: &[u8])-> Result<Affine, Error>{
    let mut sha = Sha256::new();
    let mut sha2 = Sha256::new();
    let nounce_byte = [0u8];
    let mut ex_data = [data,&nounce_byte].concat();
    let nounce_index = ex_data.len()-1;
    let mut nounce:u8 = 0;
    let mut hash:[u8;32] = [0; 32];
    let mut hash2:[u8; 32] = [0; 32];
    loop{
        if nounce>128 {
            break Err(Error::HashNotComputable(String::from("Hash is not computable")));;
        }
        ex_data[nounce_index] = nounce;
        sha.input(&ex_data[..]);
        sha.result(&mut hash);
        let mut x_coord = Field::new(0,0,0,0,0,0,0,0);
        if !x_coord.set_b32(&hash) {
            nounce = nounce+1;
            continue;
        }
        let mut affine_point = Affine::default();

        if !affine_point.set_xquad(&x_coord) {
            nounce = nounce+1;
            continue;
        }

        sha2.input(&hash);
        sha2.result(&mut hash2);

        //Even though all curve points would not be possible,
        //it is better to use both halves of the curve.
        if hash2[0] & 0x01 == 1 {
            affine_point.neg();
        }
        //The cofactor is 1 meaning all curve points are in the group. So, no more check requried
        break Ok(affine_point);
    }
}
