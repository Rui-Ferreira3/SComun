# Test Instructions
## Directory structure
- build
    - files
        - train.txt
    - demoData

The dirctory files contains the train data and will contain the weights and results of the nn. The directory demoData will contain all the encrypted keys and values used in the project.

## Compile the executables
Inside the directory build use the comand: `make`. This will create the executables
 - sc
 - dc
 - nn

## Run the programs:
1. `./nn train 1` to train the model using relu as the activation function.
2. `./nn test 1` to test the model using relu as the activation function.
3. `./sc 8192` to generate the keys necessary and encrypt the input data. Use the second argument to select the number of images to be encrypted.
4. `./nn infer 1` to preform the inference on the private data.
5. `./dc 8192` to deserialize and decrypt the output of the nn. Use the second argument to select the number of images encrypted.

The second argument of the nn selects the activation function to be used. For linear activation use `0`, and for relu use `1`. For training it's also possible to use the activation function sigmoid with the argument `2`.