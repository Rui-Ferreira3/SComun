#include <iomanip>
#include <tuple>
#include <unistd.h>

//#include <string>       //ADICIONADAS
//#include <sstream>
//#include <vector>

#include "openfhe.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
using namespace std;

/*
    Basta adicionar a função clientProcess, os includes aqui (se não existirem), e as linhas dos nomes dos ficheiros ao ficheiro nn.cpp para ler as entradas encriptadas das imagens
    E os ficheiros cryptocontext, key_mult, key_pub, key_rot, crypted_X_input na pasta demoData

    É NECESSÁRIO FAZER UMA PASTA demoData DENTRO DO build !! (pode-se escolher outro nome, basta mudar ai em baixo)
    This program requres the subdirectory `" << DATAFOLDER << "' to exist, otherwise you will get an error writing serializations
*/

const std::string DATAFOLDER = "demoData"; // nome da pasta
std::string ccLocation       = "/cryptocontext.txt";
std::string pubKeyLocation   = "/key_pub.txt";   // Pub key
std::string multKeyLocation  = "/key_mult.txt";  // relinearization key
std::string rotKeyLocation   = "/key_rot.txt";   // automorphism / rotation key

/**
 * clientProcess
 *  - deserialize data from a file which simulates receiving data from a server
 * after making a request
 *  - we then process the data by doing operations (multiplication, addition,
 * rotation, etc)
 *  - !! We also create an object and encrypt it in this function before sending
 * it off to the server to be decrypted
 */

std::tuple<CryptoContext<DCRTPoly>, KeyPair<DCRTPoly>> clientProcess() {

//void clientProcess() {
    CryptoContext<DCRTPoly> clientCC;
    clientCC->ClearEvalMultKeys();
    clientCC->ClearEvalAutomorphismKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
    if (!Serial::DeserializeFromFile(DATAFOLDER + ccLocation, clientCC, SerType::BINARY)) {
        std::cerr << "I cannot read serialized data from: " << DATAFOLDER << "/cryptocontext.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Client CC deserialized" << '\n' << std::endl;

    KeyPair<DCRTPoly> clientKP;  // We do NOT have a secret key. The client
    // should not have access to this
    PublicKey<DCRTPoly> clientPublicKey;
    if (!Serial::DeserializeFromFile(DATAFOLDER + pubKeyLocation, clientPublicKey, SerType::BINARY)) {
        std::cerr << "I cannot read serialized data from: " << DATAFOLDER << "/cryptocontext.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Client KP deserialized" << '\n' << std::endl;

    std::ifstream multKeyIStream(DATAFOLDER + multKeyLocation, std::ios::in | std::ios::binary);
    if (!multKeyIStream.is_open()) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + multKeyLocation << std::endl;
        std::exit(1);
    }
    if (!clientCC->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
        std::cerr << "Could not deserialize eval mult key file" << std::endl;
        std::exit(1);
    }

    std::cout << "Deserialized eval mult keys" << '\n' << std::endl;
    std::ifstream rotKeyIStream(DATAFOLDER + rotKeyLocation, std::ios::in | std::ios::binary);
    if (!rotKeyIStream.is_open()) {
        std::cerr << "Cannot read serialization from " << DATAFOLDER + multKeyLocation << std::endl;
        std::exit(1);
    }
    if (!clientCC->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY)) {
        std::cerr << "Could not deserialize eval rot key file" << std::endl;
        std::exit(1);
    }

    // até aqui são chaves para fazer as operações

    Ciphertext<DCRTPoly> client_X_input;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/crypted_X_input.txt", client_X_input, SerType::BINARY)) {       //leitura da entrada (imagem)
        std::cerr << "Cannot read serialization from " << DATAFOLDER + "/crypted_X_input.txt" << std::endl;
        std::exit(1);
    }

    std::cout << "Deserialized cryted_X_Input" << '\n' << std::endl;

    //-----------------------------------------------------------------------------------------------------------------

    auto nn_output   = clientCC->EvalMult(client_X_input, client_X_input);  //aqui pode-se multiplicar os pesos
    //auto add_result    = clientCC->EvalAdd(clientC1, clientC2);             //ex: soma
    //auto rotate_result_positive    = clientCC->EvalRotate(clientC1, 1);     //ex: rotação positiva
    //auto rotate_result_negative = clientCC->EvalRotate(clientC1, -1);       //ex: rotação negativa        ESTÃO EM COMENTÁRIO PQ NÃO SÃO USADAS E DEPOIS DÁ WARNING

    // Now, we want to simulate a client who is encrypting data for the server to
    // decrypt. E.g weights of a machine learning algorithm

    //std::vector<std::complex<double>> clientVector1 = {1.0, 2.0, 3.0, 4.0};                             //ex de ficheiro de saida
    //auto clientPlaintext1                           = clientCC->MakeCKKSPackedPlaintext(clientVector1);
    //auto clientInitiatedEncryption                  = clientCC->Encrypt(clientPublicKey, clientPlaintext1);
    //Serial::SerializeToFile(DATAFOLDER + "/nn_output.txt", clientInitiatedEncryption , SerType::BINARY);

    Serial::SerializeToFile(DATAFOLDER + "/nn_output.txt", nn_output , SerType::BINARY);// ex de escrita do ficheiro de output da nn encriptado, a ser depois lido pelo codigo de desencriptação

    std::cout << "Serialized all ciphertexts from client" << '\n' << std::endl;

    return std::make_tuple(clientCC, clientKP);
}

int main(){

    //clientProcess();

    auto tupleCryptoContext_KeyPair = clientProcess();
    auto cc                         = std::get<0>(tupleCryptoContext_KeyPair);
    //auto kp                         = std::get<1>(tupleCryptoContext_KeyPair);

    Ciphertext<DCRTPoly> client_X_input;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/crypted_X_input.txt", client_X_input, SerType::BINARY)) {       //leitura da entrada (imagem)
        std::cerr << "Cannot read serialization from " << DATAFOLDER + "/crypted_X_input.txt" << std::endl;
        std::exit(1);
    }

    auto nn_output_mult = cc->EvalMult(client_X_input, client_X_input);
    auto rotate_result_positive_nn_output = cc->EvalRotate(client_X_input, 1);     //ex: rotação positiva

    std::cout << "Did math" << '\n' << std::endl;

}