//
//  nn.cpp
//  
//  To compile: g++ -o nn nn.cpp -std=c++11
//  To run: ./nn
//  Created by Sergei Bugrov on 4/20/18.
//  Copyright © 2017 Sergei Bugrov. All rights reserved.
//  Download dataset from: https://drive.google.com/file/d/1OdtwXHf_-2T0aS9HLBnxU3o-72mklCZY/view?usp=sharing

#include <iostream>
#include <vector>
#include <math.h>
#include <fstream>
#include <sstream>
#include <string>
#include <random>
#include <algorithm>

#include "openfhe.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#define NUM_EPOCHS 10000 // 10000

using namespace std;
using namespace lbcrypto;

#define WEIGHTS_PATH "files/serialized_weights.txt"
#define INPUT_PATH "files/crypted_X_input.txt"

#define ccLocation "files/demoData/cryptocontext.txt"
#define pubKeyLocation "files/demoData/key_pub.txt"   // Pub key
#define multKeyLocation "files/demoData/key_mult.txt"  // relinearization key
#define rotKeyLocation "files/demoData/key_rot.txt"   // automorphism / rotation key

#define BATCH_SIZE 256

pair<CryptoContext<DCRTPoly>, KeyPair<DCRTPoly>> clientProcess() {

    CryptoContext<DCRTPoly> clientCC;
    clientCC->ClearEvalMultKeys();
    clientCC->ClearEvalAutomorphismKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
    if (!Serial::DeserializeFromFile(ccLocation, clientCC, SerType::BINARY)) {
        std::cerr << "I cannot read serialized data from: " << ccLocation << std::endl;
        std::exit(1);
    }
    std::cout << "Client CC deserialized" << '\n' << std::endl;

    KeyPair<DCRTPoly> clientKP;  // We do NOT have a secret key. The client
    // should not have access to this
    PublicKey<DCRTPoly> clientPublicKey;
    if (!Serial::DeserializeFromFile(pubKeyLocation, clientPublicKey, SerType::BINARY)) {
        std::cerr << "I cannot read serialized data from: " pubKeyLocation << std::endl;
        std::exit(1);
    }
    std::cout << "Client KP deserialized" << '\n' << std::endl;

    // std::ifstream multKeyIStream(multKeyLocation, std::ios::in | std::ios::binary);
    // if (!multKeyIStream.is_open()) {
    //     std::cerr << "Cannot read serialization from " multKeyLocation << std::endl;
    //     std::exit(1);
    // }
    // if (!clientCC->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
    //     std::cerr << "Could not deserialize eval mult key file" << std::endl;
    //     std::exit(1);
    // }

    // std::cout << "Deserialized eval mult keys" << '\n' << std::endl;
    // std::ifstream rotKeyIStream(rotKeyLocation, std::ios::in | std::ios::binary);
    // if (!rotKeyIStream.is_open()) {
    //     std::cerr << "Cannot read serialization from " << rotKeyLocation << std::endl;
    //     std::exit(1);
    // }
    // if (!clientCC->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY)) {
    //     std::cerr << "Could not deserialize eval rot key file" << std::endl;
    //     std::exit(1);
    // }
    
    return make_pair(clientCC, clientKP);
}

void print ( const vector <float>& m, int n_rows, int n_columns ) {
    
    /*  "Couts" the input vector as n_rows x n_columns matrix.
     Inputs:
     m: vector, matrix of size n_rows x n_columns
     n_rows: int, number of rows in the left matrix m1
     n_columns: int, number of columns in the left matrix m1
     */
    
    for( int i = 0; i != n_rows; ++i ) {
        for( int j = 0; j != n_columns; ++j ) {
            cout << m[ i * n_columns + j ] << " ";
        }
        cout << '\n';
    }
    cout << endl;
}

int argmax ( const vector <float>& m ) {

    return distance(m.begin(), max_element(m.begin(), m.end()));
}

vector <float> relu(const vector <float>& z){
    int size = z.size();
    vector <float> output;
    for( int i = 0; i < size; ++i ) {
        if (z[i] < 0){
            output.push_back(0.0);
        }
        else output.push_back(z[i]);
    }
    return output;
}

vector <float> reluPrime (const vector <float>& z) {
    int size = z.size();
    vector <float> output;
    for( int i = 0; i < size; ++i ) {
        if (z[i] <= 0){
            output.push_back(0.0);
        }
        else output.push_back(1.0);
    }
    return output;
} 

static vector<float> random_vector(const int size)
{
    random_device rd;
    mt19937 gen(rd());
    uniform_real_distribution<> distribution(0.0, 0.05);
    static default_random_engine generator;

    vector<float> data(size);
    generate(data.begin(), data.end(), [&]() { return distribution(generator); });
    return data;
}

vector <float> softmax (const vector <float>& z, unsigned int dim) {
    
    unsigned int zsize = static_cast<int>(z.size());
    vector <float> out;
    
    for (unsigned i = 0; i != zsize; i += dim) {
        vector <float> foo;
        for (unsigned j = 0; j != dim; ++j) {
            foo.push_back(z[i + j]);
        }
        
        float max_foo = *max_element(foo.begin(), foo.end());

        for (unsigned j = 0; j != dim; ++j) {
            foo[j] = exp(foo[j] - max_foo);
        }      

        float sum_of_elems = 0.0;
        for (unsigned j = 0; j != dim; ++j) {
            sum_of_elems = sum_of_elems + foo[j];
        }
        
        for (unsigned j = 0; j != dim; ++j) {
            out.push_back(foo[j]/sum_of_elems);
        }
    }
    return out;
}

vector <float> sigmoid_d (const vector <float>& m1) {
    
    /*  Returns the value of the sigmoid function derivative f'(x) = f(x)(1 - f(x)),
     where f(x) is sigmoid function.
     Input: m1, a vector.
     Output: x(1 - x) for every element of the input matrix m1.
     */
    
    const unsigned long VECTOR_SIZE = m1.size();
    vector <float> output (VECTOR_SIZE);
    
    
    for( unsigned i = 0; i != VECTOR_SIZE; ++i ) {
        output[ i ] = m1[ i ] * (1 - m1[ i ]);
    }
    
    return output;
}

vector <float> sigmoid (const vector <float>& m1) {
    
    /*  Returns the value of the sigmoid function f(x) = 1/(1 + e^-x).
     Input: m1, a vector.
     Output: 1/(1 + e^-x) for every element of the input matrix m1.
     */
    
    const unsigned long VECTOR_SIZE = m1.size();
    vector <float> output (VECTOR_SIZE);
    
    
    for( unsigned i = 0; i != VECTOR_SIZE; ++i ) {
        output[ i ] = 1 / (1 + exp(-m1[ i ]));
    }
    
    return output;
}

vector <float> operator+(const vector <float>& m1, const vector <float>& m2){
    
    /*  Returns the elementwise sum of two vectors.
     Inputs:
     m1: a vector
     m2: a vector
     Output: a vector, sum of the vectors m1 and m2.
     */
    
    const unsigned long VECTOR_SIZE = m1.size();
    vector <float> sum (VECTOR_SIZE);
    
    for (unsigned i = 0; i != VECTOR_SIZE; ++i){
        sum[i] = m1[i] + m2[i];
    };
    
    return sum;
}

vector <float> operator-(const vector <float>& m1, const vector <float>& m2){
    
    /*  Returns the difference between two vectors.
     Inputs:
     m1: vector
     m2: vector
     Output: vector, m1 - m2, difference between two vectors m1 and m2.
     */
    
    const unsigned long VECTOR_SIZE = m1.size();
    vector <float> difference (VECTOR_SIZE);
    
    for (unsigned i = 0; i != VECTOR_SIZE; ++i){
        difference[i] = m1[i] - m2[i];
    };
    
    return difference;
}

vector <float> operator*(const vector <float>& m1, const vector <float>& m2){
    
    /*  Returns the product of two vectors (elementwise multiplication).
     Inputs:
     m1: vector
     m2: vector
     Output: vector, m1 * m2, product of two vectors m1 and m2
     */
    
    const unsigned long VECTOR_SIZE = m1.size();
    vector <float> product (VECTOR_SIZE);
    
    for (unsigned i = 0; i != VECTOR_SIZE; ++i){
        product[i] = m1[i] * m2[i];
    };
    
    return product;
}

vector <float> operator*(const float m1, const vector <float>& m2){
    
    /*  Returns the product of a float and a vectors (elementwise multiplication).
     Inputs:
     m1: float
     m2: vector
     Output: vector, m1 * m2, product of two vectors m1 and m2
     */
    
    const unsigned long VECTOR_SIZE = m2.size();
    vector <float> product (VECTOR_SIZE);
    
    for (unsigned i = 0; i != VECTOR_SIZE; ++i){
        product[i] = m1 * m2[i];
    };
    
    return product;
}

vector <float> operator/(const vector <float>& m2, const float m1){
    
    /*  Returns the product of a float and a vectors (elementwise multiplication).
     Inputs:
     m1: float
     m2: vector
     Output: vector, m1 * m2, product of two vectors m1 and m2
     */
    
    const unsigned long VECTOR_SIZE = m2.size();
    vector <float> product (VECTOR_SIZE);
    
    for (unsigned i = 0; i != VECTOR_SIZE; ++i){
        product[i] = m2[i] / m1;
    };
    
    return product;
}

vector <float> transpose (float *m, unsigned int C, unsigned int R) {
    
    /*  Returns a transpose matrix of input matrix.
     Inputs:
     m: vector, input matrix
     C: int, number of columns in the input matrix
     R: int, number of rows in the input matrix
     Output: vector, transpose matrix mT of input matrix m
     */
    
    vector <float> mT (C*R);
    
    for(unsigned n = 0; n != C*R; n++) {
        unsigned i = n/C;
        unsigned j = n%C;
        mT[n] = m[R*j + i];
    }
    
    return mT;
}

vector <float> dot (const vector <float>& m1, const vector <float>& m2, const int m1_rows, const int m1_columns, const int m2_columns) {
    
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
    
    vector <float> output (m1_rows*m2_columns);
    
    for( int row = 0; row != m1_rows; ++row ) {
        for( int col = 0; col != m2_columns; ++col ) {
            output[ row * m2_columns + col ] = 0.f;
            for( int k = 0; k != m1_columns; ++k ) {
                output[ row * m2_columns + col ] += m1[ row * m1_columns + k ] * m2[ k * m2_columns + col ];
            }
        }
    }
    
    return output;
}

vector<Ciphertext<DCRTPoly>> crypted_dot (CryptoContext<DCRTPoly> cc, const vector<Ciphertext<DCRTPoly>> &m1, const vector<float> &W, int num_rows, int num_cols) {
    vector<Ciphertext<DCRTPoly>> output;


    for(int j=0; j<num_cols; j++) {
        vector<float> col;
        for(int i=0; i<num_rows; i++) {
            int index = num_rows*i + j;
            col.push_back(W[index]);
        }
        Ciphertext<DCRTPoly> val = cc->EvalLinearWSum(m1, col);
        output.push_back(val);
    }

    return output;
}

vector<string> split(const string &s, char delim) {
    stringstream ss(s);
    string item;
    vector<string> tokens;
    while (getline(ss, item, delim)) {
        tokens.push_back(item);
    }
    return tokens;
}

pair<vector<float>,vector<float>> load_weights(string path) {
    string line;
    vector<string> line_v;

    cout << "Loading data ...\n";
    vector<float> X_train;
    vector<float> y_train;
    ifstream myfile (path);
    if (myfile.is_open())
    {
        while ( getline (myfile,line) )
        {
            line_v = split(line, '\t');
            unsigned int digit = strtof((line_v[0]).c_str(),0);
            for (unsigned i = 0; i < 10; ++i) {
                if (i == digit)
                {
                    y_train.push_back(1.);
                }
                else y_train.push_back(0.);
            }
            
            unsigned int size = static_cast<int>(line_v.size());
            for (unsigned i = 1; i < size; ++i) {
                X_train.push_back(strtof((line_v[i]).c_str(),0));
            }
        }
        X_train = X_train/255.0;
        myfile.close();
    }
    else cout << "Unable to open file" << '\n';

    return make_pair(X_train, y_train);
}

vector<vector<float>> train_model(vector<float> X_train, vector<float> y_train) {
    // Some hyperparameters for the NN
    float lr = .01/BATCH_SIZE;

    // Random initialization of the weights
    vector <float> W1 = random_vector(784*128);
    vector <float> W2 = random_vector(128*64);
    vector <float> W3 = random_vector(64*10);

    // Initialization of best weights and loss
    float best_loss = 1.0;
    vector <float> best_W1 = W1;
    vector <float> best_W2 = W2;
    vector <float> best_W3 = W3;


    cout << "Training the model ...\n";
    for (unsigned i = 0; i < NUM_EPOCHS; ++i) {

        // Building batches of input variables (X) and labels (y)
        unsigned int randindx = rand() % (42000-BATCH_SIZE);
        vector<float> b_X;
        vector<float> b_y;
        for (unsigned j = randindx*784; j < (randindx+BATCH_SIZE)*784; ++j){
            b_X.push_back(X_train[j]);
        }
        for (unsigned k = randindx*10; k < (randindx+BATCH_SIZE)*10; ++k){
            b_y.push_back(y_train[k]);
        }

        // Feed forward
        vector<float> a1 = relu(dot( b_X, W1, BATCH_SIZE, 784, 128 ));
        vector<float> a2 = relu(dot( a1, W2, BATCH_SIZE, 128, 64 ));
        vector<float> yhat = softmax(dot( a2, W3, BATCH_SIZE, 64, 10 ), 10);
        
        // Back propagation
        vector<float> dyhat = (yhat - b_y);
        // dW3 = a2.T * dyhat
        vector<float> dW3 = dot(transpose( &a2[0], BATCH_SIZE, 64 ), dyhat, 64, BATCH_SIZE, 10);
        // dz2 = dyhat * W3.T * relu'(a2)
        vector<float> dz2 = dot(dyhat, transpose( &W3[0], 64, 10 ), BATCH_SIZE, 10, 64) * reluPrime(a2);
        // dW2 = a1.T * dz2
        vector<float> dW2 = dot(transpose( &a1[0], BATCH_SIZE, 128 ), dz2, 128, BATCH_SIZE, 64);
        // dz1 = dz2 * W2.T * relu'(a1)
        vector<float> dz1 = dot(dz2, transpose( &W2[0], 128, 64 ), BATCH_SIZE, 64, 128) * reluPrime(a1);
        // dW1 = X.T * dz1
        vector<float> dW1 = dot(transpose( &b_X[0], BATCH_SIZE, 784 ), dz1, 784, BATCH_SIZE, 128);
        
        // Updating the parameters
        W3 = W3 - lr * dW3;
        W2 = W2 - lr * dW2;
        W1 = W1 - lr * dW1;

        
        if ((i+1) % 100 == 0){
            cout << "-----------------------------------------------Epoch " << i+1 << "--------------------------------------------------" <<"\n";
            cout << "Predictions:" << "\n";
            print ( yhat, 10, 10 );
            cout << "Ground truth:" << "\n";
            print ( b_y, 10, 10 );
            vector<float> loss_m = yhat - b_y;
            float loss = 0.0;
            for (unsigned k = 0; k < BATCH_SIZE*10; ++k){
                loss += loss_m[k]*loss_m[k];
            }
            cout << "                                            Loss " << loss/BATCH_SIZE <<"\n";
            // Upating the best parameters
            if(loss/BATCH_SIZE < best_loss){
                cout << "Updating weights ...\n";
                best_loss = loss/BATCH_SIZE;
                best_W1 = W1;
                best_W2 = W2;
                best_W2 = W2;
            }
            cout << "--------------------------------------------End of Epoch :(------------------------------------------------" <<"\n";
        };
    };

    vector<vector<float>> weights;
    weights.push_back(W1);
    weights.push_back(W2);
    weights.push_back(W3);

    return weights;
}

vector<float> predict(vector<float> X, vector<float> y, vector<vector<float>> weights) {
    vector<float> W1 = weights[0];
    vector<float> W2 = weights[1];
    vector<float> W3 = weights[2];

    cout << "Making the predictions ...\n";

    // Building batches of input variables (X) and labels (y)
    unsigned int randindx = rand() % (42000-BATCH_SIZE);
    vector<float> b_X;
    vector<float> b_y;
    for (unsigned j = randindx*784; j < (randindx+BATCH_SIZE)*784; ++j){
        b_X.push_back(X[j]);
    }
    for (unsigned k = randindx*10; k < (randindx+BATCH_SIZE)*10; ++k){
        b_y.push_back(y[k]);
    }

    // Feed forward
    vector<float> a1 = relu(dot( b_X, W1, BATCH_SIZE, 784, 128 ));
    vector<float> a2 = relu(dot( a1, W2, BATCH_SIZE, 128, 64 ));
    vector<float> yhat = softmax(dot( a2, W3, BATCH_SIZE, 64, 10 ), 10);
        
    vector<float> loss_m = yhat - b_y;
    float loss = 0.0;
    for (unsigned k = 0; k < BATCH_SIZE*10; ++k){
       loss += loss_m[k]*loss_m[k];
    }
    cout << "                                            Loss " << loss/BATCH_SIZE <<"\n";

    return yhat;
}

// vector<Ciphertext<DCRTPoly>> crypted_predict(CryptoContext<DCRTPoly> cc, vector<Ciphertext<DCRTPoly>> X, vector<Ciphertext<DCRTPoly>> y, vector<vector<float>> weights) {
//     cout << "Making the predictions ...\n";

//     // Feed forward
//     vector<Ciphertext<DCRTPoly>> a1 = crypted_relu(crypted_dot(cc, X, weights[0], 784, 128 ));
//     vector<Ciphertext<DCRTPoly>> a2 = crypted_relu(crypted_dot(cc, a1, weights[1], 128, 64 ));
//     vector<Ciphertext<DCRTPoly>> yhat = crypted_softmax(crypted_dot(cc, a2, weights[2], 64, 10 ), 10);

//     return yhat;
// }

int main(int argc, const char * argv[]) {
    vector<vector<float>> weights;
    vector<Ciphertext<DCRTPoly>> input;

    if(argc != 2) {
        std::cerr << "Wrong number of arguments!\nExpecting one argument: train or test.\n" << std::endl;
        std::exit(1);
    }

    string func = argv[1];

    if(func == "train") {
        pair<vector<float>,vector<float>> train_data = load_weights("files/train.txt");

        weights = train_model(train_data.first, train_data.second);

        cout << "Saving weights in file ...\n";

        if (!Serial::SerializeToFile(WEIGHTS_PATH, weights, SerType::BINARY)) {
            std::cerr << "Exception writing weights to serialized_weights.txt" << std::endl;
            std::exit(1);
        }
    }else if(func == "test") {
        cout << "Reading weights from file ...\n";

        if (!Serial::DeserializeFromFile(WEIGHTS_PATH, weights, SerType::BINARY)) {
            std::cerr << "Cannot read weiths from " << WEIGHTS_PATH << std::endl;
            std::exit(1);
        }

        cout << "Reading inputs from file ...\n";

        if (!Serial::DeserializeFromFile(INPUT_PATH, input, SerType::BINARY)) {
            std::cerr << "Cannot read inputs from " << INPUT_PATH << std::endl;
            std::exit(1);
        }

        auto tupleCryptoContext_KeyPair = clientProcess();
        CryptoContext<DCRTPoly> cc = tupleCryptoContext_KeyPair.first;
        
        crypted_dot(cc, input, weights[0], 784, 128);
    }else {
        std::cerr << "Invalid argument!\nExpecting one argument: train or test\n" << std::endl;
        std::exit(1);
    }

    return 0;
}