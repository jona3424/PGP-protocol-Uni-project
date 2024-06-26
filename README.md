# PGP Email Protection Application

## Project Description

The goal of this project is to gain a better understanding of the PGP (Pretty Good Privacy) scheme for email protection, including its capabilities and usage. This task involves designing and implementing a Python application with a graphical user interface that provides the following functionalities:

1. **RSA Key Pair Management**
   - Generate a new RSA key pair
   - Delete an existing RSA key pair
   - Import and export public key or the entire key pair in `.pem` format

2. **Key Ring Display**
   - Display a list of public and private keys with all necessary information

3. **Message Handling**
   - Send a message with options for encryption and signing
   - Receive a message with options for decryption and verification

## Key Features

- **Key Generation:** Users can generate a new RSA key pair by entering their name, email, and key size (1024 or 2048 bits). They must also set a password to protect the private key.
- **Key Storage:** All generated and imported keys are clearly visible in the user interface. Access to private keys is protected by password prompts.
- **Message Sending:** Users can encrypt messages to ensure confidentiality, sign messages to ensure authenticity, compress messages, and convert data to radix-64 format. Users can select the private key for signing (using SHA-1 hash function) and the public key for encryption using one of the supported symmetric algorithms (TripleDES, AES128, Cast5, or IDEA).
- **Message Receiving:** Users can select a file from the desired location, and the application will recognize the packets, perform decryption, and verification. The interface will display the success of the signature verification and the author's information. In case of failed decryption or verification, an error message will be displayed.

## Implementation Notes

- **Teamwork:** The project should be done in teams of two students. Solo work is possible but not recommended.
- **Submission and Defense:** The project can only be defended in the June or August exam periods. Deadlines for submission and defense dates will be announced later.
- **Project Points:** The project can earn a maximum of 15 or 20 points, which cannot be compensated by other pre-exam or exam obligations.
- **Oral Defense:** During the oral defense, candidates must run their submitted solution, demonstrate knowledge of the task, and address any shortcomings.
- **Documentation:** Before starting the implementation, read the entire task and provided documentation thoroughly. If anything is unclear, make reasonable assumptions.

## Rules and Regulations

- **Standard Compliance:** Students are allowed to use ideas from the RFC 4480 document describing the OpenPGP protocol.
- **Module Usage:** Using modules for parts of the PGP scheme (e.g., `rsa` module, `cryptography` module) is allowed, but using modules that offer complete PGP functionalities (e.g., `py-pgp` module) is prohibited.
- **Work Division:** Responsibilities within the team must be equally divided. One member cannot solely handle the application logic while the other handles the GUI.
- **Plagiarism:** Submitting solutions obtained from the internet or sharing solutions with other teams is prohibited. All submissions will be checked for code similarity, and violations will be reported to the Faculty's disciplinary committee.


