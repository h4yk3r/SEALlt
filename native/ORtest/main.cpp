#include <iostream>
#include "seal/seal.h"

using namespace std;

int main ()
{
    /*
     * prepare SEAL instance
     */
    // set SEAL parameters
    // encryption scheme: ckks
    seal::EncryptionParameters parms(seal::scheme_type::ckks);
    // set poly_modulus_degree, the degree of polynomial X^N+1
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    // set coefficients_modulus, q_0; RNS modulus p1, p2,...,p_l; P for relinearlize
    // here L = 3
    // q_0 is of 40 bits long, 20 bits integer and 20 bits decimal
    //parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40 }));
    parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40 }));
    // Delta for canonical embedding, secure accuracy, 20 bits decimal
    auto scale = pow(2.0, 50);

    // initial SEAL context instance
    seal::SEALContext context(parms);
    // generate keys from context instance
    seal::KeyGenerator keygen(context);
    seal::SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    seal::GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    // initial utils with keys
    seal::CKKSEncoder ckks_encoder(context);
    seal::Encryptor encryptor(context, public_key);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secret_key);

    vector<double> V;
    for (int i=0; i!=1024; ++i) V.push_back(i + 1.0);
    seal::Plaintext encodedV;
    ckks_encoder.paddingEncode(V, scale, encodedV);
    seal::Ciphertext encV;
    encryptor.encrypt(encodedV, encV);
    seal::Plaintext decV;
    decryptor.decrypt(encV, decV);
    vector<double> evaV;
    ckks_encoder.decode(decV, evaV);

    cout << "[ ";
    for (auto i : evaV) printf("%.3lf ", i);
    cout << "]" << endl;

    return 0;
}