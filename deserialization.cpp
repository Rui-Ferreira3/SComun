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

// Save-load locations for RAW ciphertexts
std::string cipherOneLocation = "/ciphertext1.txt";
std::string cipherTwoLocation = "/ciphertext2.txt";

// Save-load locations for evaluated ciphertexts
std::string cipherMultLocation   = "/ciphertextMult.txt";
std::string cipherAddLocation    = "/ciphertextAdd.txt";
std::string cipherRotLocation    = "/ciphertextRot.txt";
std::string cipherRotNegLocation = "/ciphertextRotNegLocation.txt";
std::string clientVectorLocation = "/ciphertextVectorFromClient.txt";

/**
 * Demarcate - Visual separator between the sections of code
 * @param msg - string message that you want displayed between blocks of
 * characters
 */
void demarcate(const std::string& msg) {
    std::cout << std::setw(50) << std::setfill('*') << '\n' << std::endl;
    std::cout << msg << std::endl;
    std::cout << std::setw(50) << std::setfill('*') << '\n' << std::endl;
}

/**
 * serverVerification
 *  - deserialize data from the client.
 *  - Verify that the results are as we expect
 * @param cc cryptocontext that was previously generated
 * @param kp keypair that was previously generated
 * @param vectorSize vector size of the vectors supplied
 * @return
 *  5-tuple of the plaintexts of various operations
 */

std::tuple<Plaintext> serverVerification() {
    Ciphertext<DCRTPoly> nn_res;

    std::vector<std::complex<double>> vec1 = {1.0, 2.0, 3.0, 4.0};
    int vectorSize = 784;       // tamanho do vetor do resultado

    CryptoContext<DCRTPoly> decoder_CC;
    //KeyPair<DCRTPoly> decoder_KP;  // We DO have a secret key. The client should not have access to this
    PublicKey<DCRTPoly> decoder_PublicKey;
    PrivateKey<DCRTPoly> decoder_SecretKey;

    if (!Serial::DeserializeFromFile(DATAFOLDER + ccLocation, decoder_CC, SerType::BINARY)) {
        std::cerr << "I cannot read serialized data from: " << DATAFOLDER << "/cryptocontext.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Client CC deserialized";

    if (!Serial::DeserializeFromFile(DATAFOLDER + pubKeyLocation, decoder_PublicKey, SerType::BINARY)) {
        std::cerr << "I cannot read serialized data from: " << DATAFOLDER << "/cryptocontext.txt" << std::endl; //não devia ser "pub_key.txt" ?
        std::exit(1);
    }
    std::cout << "Decoder Public KP deserialized" << '\n' << std::endl;

    if (!Serial::DeserializeFromFile(DATAFOLDER + "/key_sec.txt", decoder_SecretKey, SerType::BINARY)) {
        std::cerr << "I cannot read serialized data from: " << DATAFOLDER << "/cryptocontext.txt" << std::endl; //não devia ser "pub_key.txt" ?
        std::exit(1);
    }
    std::cout << "Decoder Secret KP deserialized" << '\n' << std::endl;

    Serial::DeserializeFromFile(DATAFOLDER + "/crypted_X_input.txt", nn_res, SerType::BINARY);

    std::cout << "Deserialized all data from client on server" << '\n' << std::endl;

    demarcate("Part 5: Correctness verification");

    Plaintext nn_res_pt;


    decoder_CC->Decrypt(decoder_SecretKey, nn_res, &nn_res_pt);

    nn_res_pt->SetLength(vectorSize);


    return std::make_tuple(nn_res_pt);
}
int main() {
    std::cout << "This program requres the subdirectory `" << DATAFOLDER << "' to exist, otherwise you will get "
              << "an error writing serializations." << std::endl;

    demarcate("Part 4: Server deserialization of data from client. ");

    auto tupleRes  = serverVerification();
    auto nn_res_pt   = std::get<0>(tupleRes);

    auto nn_res = nn_res_pt->GetRealPackedValue();

    for (int k = 0; k < 784; ++k){
        if(nn_res[k] < 0.1)
            nn_res[k] = 0;
    }

    demarcate("Decrypted NN result:");
    std::cout << nn_res << std::endl;

}