#include <iomanip>
#include <tuple>
#include <unistd.h>

#include <string>       //ADICIONADAS
#include <sstream>
#include <vector>

#include "openfhe.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
using namespace std;

vector<string> split(const string &s, char delim) {     //ADICIONADO
    stringstream ss(s);
    string item;
    vector<string> tokens;
    while (getline(ss, item, delim)) {
        tokens.push_back(item);
    }
    return tokens;
}

/////////////////////////////////////////////////////////////////
// NOTE:
// If running locally, you may want to replace the "hardcoded" DATAFOLDER with
// the DATAFOLDER location below which gets the current working directory
/////////////////////////////////////////////////////////////////
// char buff[1024];
// std::string DATAFOLDER = std::string(getcwd(buff, 1024));

// Save-Load locations for keys
const std::string DATAFOLDER = "demoData";
std::string ccLocation       = "/cryptocontext.txt";
std::string pubKeyLocation   = "/key_pub.txt";   // Pub key
std::string secKeyLocation   = "/key_sec.txt";   // Sec key
std::string multKeyLocation  = "/key_mult.txt";  // relinearization key
std::string rotKeyLocation   = "/key_rot.txt";   // automorphism / rotation key

// Save-load locations for evaluated ciphertexts
std::string cipherMultLocation   = "/ciphertextMult.txt";
std::string cipherAddLocation    = "/ciphertextAdd.txt";
std::string cipherRotLocation    = "/ciphertextRot.txt";
std::string cipherRotNegLocation = "/ciphertextRotNegLocation.txt";
std::string clientVectorLocation = "/ciphertextVectorFromClient.txt";

/**
 * serverSetupAndWrite
 *  - simulates a server at startup where we generate a cryptocontext and keys.
 *  - then, we generate some data (akin to loading raw data on an enclave)
 * before encrypting the data
 * @param multDepth - multiplication depth
 * @param scaleModSize - number of bits to use in the scale factor (not the
 * scale factor itself)
 * @param batchSize - batch size to use
 * @return Tuple<cryptoContext, keyPair>
 */

std::tuple<CryptoContext<DCRTPoly>, KeyPair<DCRTPoly>> serverSetupAndWrite(int multDepth, int scaleModSize,
                                                                                int batchSize, unsigned int image_number) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> serverCC = GenCryptoContext(parameters);

    serverCC->Enable(PKE);
    serverCC->Enable(KEYSWITCH);
    serverCC->Enable(LEVELEDSHE);

    std::cout << "Cryptocontext generated" << std::endl;

    KeyPair<DCRTPoly> serverKP = serverCC->KeyGen();
    std::cout << "Keypair generated" << std::endl;

    serverCC->EvalMultKeyGen(serverKP.secretKey);
    std::cout << "Eval Mult Keys/ Relinearization keys have been generated" << std::endl;

    serverCC->EvalRotateKeyGen(serverKP.secretKey, {1, 2, -1, -2});
    std::cout << "Rotation keys generated\n" << std::endl;

    //-----------------------------------------------------------------------------------------------------------------

    vector<double> X_train;
    vector<vector<double> > X_train_c(784);
    vector<double> y_train;
    std::ifstream myfile ("train.txt");
    string line;
    vector<string> line_v;
    unsigned int j = 0;

    if (myfile.is_open())
    {
        while ( getline (myfile,line) && j<image_number)
        {
            line_v = split(line, '\t');
            unsigned int digit = strtof((line_v[0]).c_str(),0);

            y_train.push_back(digit);
            // std::cout << "y:" << y_train[j] << std::endl;
                
            unsigned int size = static_cast<int>(line_v.size());
            for (unsigned i = 1; i < size; ++i) {
                X_train_c[i-1].push_back(strtof((line_v[i]).c_str(),0));
            }
            j++;
            // std::cout << "j:" << j << std::endl;
        }
        for(unsigned i = 0; i<X_train.size(); i++){
            X_train[i] = X_train[i]/255.0;
        }
        myfile.close();
    }

    std::cout << "Read from train.txt\n" << std::endl;

    std::cout << "Crypting images matrix" << std::flush;

    vector<Plaintext> serverP_X_train;
    std::vector<Ciphertext<DCRTPoly>> crypted_images_vec;

    for(unsigned j = 0; j<784; j++){
        serverP_X_train.push_back(serverCC->MakeCKKSPackedPlaintext(X_train_c[j]));
        crypted_images_vec.push_back(serverCC->Encrypt(serverKP.publicKey, serverP_X_train[j]));
        if(j % 100 == 0 && j!=0)
            std::cout << "." << std::flush;
    }

    std::cout << "\n\nCrypted images matrix\n" << std::endl;

    /*
   * Part 2:
   * We serialize the following:
   *  Cryptocontext
   *  Public key
   *  relinearization (eval mult keys)
   *  rotation keys
   *  Some of the ciphertext
   *
   *  We serialize all of them to files
   */

    std::cout << "Part 2: Data Serialization\n" << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + ccLocation, serverCC, SerType::BINARY)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
        std::exit(1);
    }

    std::cout << "Cryptocontext serialized" << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + pubKeyLocation, serverKP.publicKey, SerType::BINARY)) {
        std::cerr << "Exception writing public key to pubkey.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Public key serialized" << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + secKeyLocation, serverKP.secretKey, SerType::BINARY)) {
        std::cerr << "Exception writing secret key to seckey.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "SECRET KEY SERIALIZED" << std::endl;

    std::ofstream multKeyFile(DATAFOLDER + multKeyLocation, std::ios::out | std::ios::binary);
    if (multKeyFile.is_open()) {
        if (!serverCC->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
            std::cerr << "Error writing eval mult keys" << std::endl;
            std::exit(1);
        }
        std::cout << "EvalMult/ relinearization keys have been serialized" << std::endl;
        multKeyFile.close();
    }
    else {
        std::cerr << "Error serializing EvalMult keys" << std::endl;
        std::exit(1);
    }

    std::ofstream rotationKeyFile(DATAFOLDER + rotKeyLocation, std::ios::out | std::ios::binary);
    if (rotationKeyFile.is_open()) {
        if (!serverCC->SerializeEvalAutomorphismKey(rotationKeyFile, SerType::BINARY)) {
            std::cerr << "Error writing rotation keys" << std::endl;
            std::exit(1);
        }
        std::cout << "Rotation keys have been serialized" << std::endl;
    }
    else {
        std::cerr << "Error serializing Rotation keys" << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(DATAFOLDER + "/crypted_X_input.txt", crypted_images_vec, SerType::BINARY)) {
        std::cerr << " Error writing cryted_X_Input" << std::endl;
    }
    std::cout << "Input vectors have been serialized" << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + "/Y_truth.txt", y_train, SerType::BINARY)) {
        std::cerr << " Error writing Y_truth" << std::endl;
    }
    std::cout << "Truth vector has been serialized" << std::endl;

    /*std::ofstream file("demoData/TestPath.txt");
    {
        cereal::PortableBinaryOutputArchive Archive(file);
        Archive(crypted_images_vec);
    }*/

    return std::make_tuple(serverCC, serverKP);
}

int main(int argc, char *argv[]) {
    std::cout << "This program requires the subdirectory `" << DATAFOLDER << "' to exist, otherwise you will get "
              << "an error writing serializations.\n" << std::endl;


    // Set main params
    const int multDepth    = 5;
    const int scaleModSize = 40;
    const usint batchSize  = 8192;

    if(argc < 2){
        std::cout << "(ERROR: no arguments given) Specify number of images to encrypt and serialize plz" << std::endl;
        return -1;
    }

    const unsigned int image_number = atoi(argv[1]);

    if(image_number > 8192){
        std::cout << "(ERROR: image amount too big) PLease choose a number between 1 and 8192" << std::endl;
        return -1;
    }

    std::cout << "Number of images to be crypted and serialized: " << image_number << "\n" << std::endl;

    const int cryptoContextIdx = 0;
    const int keyPairIdx       = 1;

    std::cout << "Part 1: Cryptocontext generation, key generation, data encryption\n" << std::endl;

    auto tupleCryptoContext_KeyPair = serverSetupAndWrite(multDepth, scaleModSize, batchSize, image_number);
    auto cc                         = std::get<cryptoContextIdx>(tupleCryptoContext_KeyPair);
    auto kp                         = std::get<keyPairIdx>(tupleCryptoContext_KeyPair);

}