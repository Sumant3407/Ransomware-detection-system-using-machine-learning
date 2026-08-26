# Ransomware-detection-system-using-machine-learning

This is a detection system which uses machine learning to detect file encryptions and isolates the root cause/file, and eradicate the file and source.

Currently, there is ransomware.py, which will work as a basic simulation for encryption in the project.

We can run this in a virtual machine to start encryption. We can train the model on different types of encryption methods to get a wide range of results to train the machine.

Idea 1:
Create an external device (RP 2040 one) which needs to be physically plugged in to start the decryption and delete the program/fle which is the ransomware.

Reason: It will save resources, and also we can specialise this device in decryption and resolving the problem.

Issues:
    How will the hardware identify the issues ( can work on some special code to help the hardware identify the issue, encryption method, keys, etc ).
Can be misplaced and misused by everyone if they get their hands on the key device of the person ( can allow the user to create a spare USB into the key resolver )

Idea 2:
cCreatethe above mentioned fuction into the program itself and generate a key to identify if it's the right computer, also to prevent this file/folder from being encrypted first/beforehand.

Reason: using any external device is very untrustworthy,y and installing kernel-level programs is a major red flag for any person.

Issues:
    Major drawback is that since there is constant monitoring from the ML program, simultaneous searching and decryption/isolation can consume way more resources,s and the program can have very poor optimisation.

27/08/2026:

Basic ideas are laid out and thought through; will start working on the machine learning project from tomorrow.

    
    Task for Machine learning:
        1: basic ML model 
        2: multiple encryption programs
        3: Simulate the action and record data; also get a dataset if available.
        4: proper dataset
        5: Train the model and test
        6: Run simulations of a ransomware attack to extract more data
        7: application which monitors the whole fileset of the entrie pc and keeps record of all the files that are being installed, etc.

    Task for Resolver:
        1: isolate the device from the network
        2: identify encryption model
        3: decrypt if possible
        4: research the RAM to identify the file which started it; delete the file(s) 
        5: run a basic scan to search for risk elements

    
