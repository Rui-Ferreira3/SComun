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

//std::tuple<Plaintext> serverVerification() 
int serverVerification() {
    Ciphertext<DCRTPoly> nn_res;

    std::vector<std::complex<double>> vec1 = {1.0, 2.0, 3.0, 4.0};
    int vectorSize = 8192;       // tamanho do vetor do resultado

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

    //-----------------------------------------------
    
    std::vector<Ciphertext<DCRTPoly>> crypted_images_vec;
    Serial::DeserializeFromFile(DATAFOLDER + "/enc_output.txt", crypted_images_vec, SerType::BINARY);

    //Plaintext images_pt;
    std::vector<Plaintext> images_pt(10);

    for(unsigned int i=0; i < 10; i++){
        decoder_CC->Decrypt(decoder_SecretKey, crypted_images_vec[i], &images_pt[i]);
        images_pt[i]->SetLength(vectorSize);
    }

    std::cout << "images decrypted:" << '\n' << std::endl;

    vector<vector<double> > images(10);
    vector <int> best_class (8192);
    vector <double> best_output (8192);

    for(unsigned int i=0; i < 10; i++){
        images[i] = images_pt[i]->GetRealPackedValue();
    }

    // std::cout << images[0] << '\n' << std::endl;

    int i = 0;
    int q = 0;
    while (i!=10){
        q = 0;
        while (q!=8192){
            if (images[i][q]>best_output[q]){
                best_output[q] = images[i][q];
                best_class[q] = i;
            }

            q = q + 1;
        }
        
        i = i + 1;
    }


    std::cout << best_class << '\n' << std::endl;

    vector<double> Y_truth;
    Serial::DeserializeFromFile(DATAFOLDER + "/Y_truth.txt", Y_truth, SerType::BINARY);
    std::cout << Y_truth << '\n' << std::endl;

    q = 0;
    int acertos = 0;
    while (q!= 8192){
        if (best_class[q] == Y_truth[q]){
            acertos = acertos + 1;
        }

        q = q + 1;
    }
    
    //-----------------------------------------------

    std::cout << acertos <<" acertos em 8192" << '\n' << std::endl;



    std::cout << "Deserialized all data from client on server" << '\n' << std::endl;

    return 0;
}
int main() {
    std::cout << "This program requres the subdirectory `" << DATAFOLDER << "' to exist, otherwise you will get "
              << "an error writing serializations." << std::endl;

    demarcate("Part 4: Server deserialization of data from client. ");

    auto value  = serverVerification();

    demarcate("Decrypted NN result:");
    std::cout << value << std::endl;

}