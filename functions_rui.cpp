#include <iostream>
#include <vector>
#include <math.h>
#include <fstream>
#include <sstream>
#include <string>
#include <random>
#include <algorithm>

#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

Ciphertext<DCRTPoly> transpose (CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> &m, unsigned int C, unsigned int R) {
    
    /*  Returns a transpose matrix of input matrix.
     Inputs:
     m: vector, input matrix
     C: int, number of columns in the input matrix
     R: int, number of rows in the input matrix
     Output: vector, transpose matrix mT of input matrix m
     */

    auto cScalar = cc->EvalRotate(m, -2);


    return cScalar;
}

vector <Ciphertext<DCRTPoly>> dot (CryptoContext<DCRTPoly> cc,const vector <Ciphertext<DCRTPoly>> &m1, const vector <float> &m2, const int m1_rows, const int m1_columns, const int m2_columns) {
    /*  Returns the product of two matrices: m1 x m2.
     Inputs:
     m1: vector, left matrix of size m1_rows x m1_columns
     m2: vector, right matrix of size m1_columns x m2_columns (the number of rows in the right matrix
     must be equal to the number of the columns in the left one)
     m1_rows: int, number of rows in the left matrix m1
     m1_columns: int, number of columns in the left matrix m1
     m2_columns: int, number of columns in the right matrix m2
     Output: vector, m1 * m2, product of two vectors m1 and m2, a matrix of size m1_rows x m2_columns
     */
    vector <Ciphertext<DCRTPoly>> output (m1_rows*m2_columns);

    for(int m2_col=0; m2_col<m2_columns; m2_col++) {
        Ciphertext<DCRTPoly> cSum = cc->EvalMult(m1[0], m2[m2_col*m2_columns]);
        for(int m1_col=1; m1_col<m1_columns; m1_col++) {
            Ciphertext<DCRTPoly> cMul = cc->EvalMult(m1[m1_col], m2[m2_col*m2_columns + m1_col]);
            cSum = cc->EvalAdd(cSum, cMul);
        }
        output.push_back(cSum);
    }
    
    return output;
}

int main(){
    // Step 1: Setup CryptoContext
    uint32_t multDepth = 1;

    uint32_t scaleModSize = 50;

    uint32_t batchSize = 8;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;



    // Step 2: Key Generation
    auto keys = cc->KeyGen();

    cc->EvalMultKeyGen(keys.secretKey);

    cc->EvalRotateKeyGen(keys.secretKey, {1, -2});



    // Step 3: Encoding and encryption of inputs
    std::vector<double> x1 = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    std::vector<double> x2 = {5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25};

    // Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    // Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2);

    // std::cout << "Input x1: " << ptxt1 << std::endl;
    // std::cout << "Input x2: " << ptxt2 << std::endl;

    // auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    // auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

    vector <Ciphertext<DCRTPoly>> c1;
    // for(int i=0; i<x1.size(); i++) {
    //     Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1[i]);
    //     c1.push_back()
    // }



    // Step 4: Evaluation
    // Homomorphic addition
    // auto cAdd = cc->EvalAdd(c1, c2);
    // Homomorphic subtraction
    // auto cSub = cc->EvalSub(c1, c2);
    // Homomorphic scalar multiplication
    // auto cScalar = cc->EvalMult(c1, 4.0);
    // Homomorphic multiplication
    // auto cMul = cc->EvalMult(c1, c2);
    // Homomorphic rotations
    // auto cRot1 = cc->EvalRotate(c1, 1);
    // auto cRot2 = cc->EvalRotate(c1, -2);

    // auto cDot = dot(cc, c1, 10, 10);

    

    // Step 5: Decryption and output
    Plaintext result;
    // We set the cout precision to 8 decimal digits for a nicer output.
    // If you want to see the error/noise introduced by CKKS, bump it up
    // to 15 and it should become visible.
    std::cout.precision(8);

    std::cout << std::endl << "Results of homomorphic computations: " << std::endl;
    // cc->Decrypt(keys.secretKey, cDot, &result);
    // result->SetLength(batchSize);
    // std::cout << std::endl << "In rotations, very small outputs (~10^-10 here) correspond to 0's:" << std::endl;
    // std::cout << "x1 rotate by 1 = " << result << std::endl;


    return 0;
}