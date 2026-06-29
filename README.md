# Summer Research 2026
## What is Hardware Security  

- Hardware security focuses on protecting physical computing components such as integrated circuits (ICs), processors, and embedded systems from attackers and tampering. 

- We heavily relie on 3rd party resources which can create security risks. This weakens assumptions that attackers cannot access the isolated IC supply chain. For example, 3rd partie resources may insert hardware trojans into chips  
- Hardware Security is basically that we want to make it harder for attackers to hurt our hardware 
#### What do these attackers target? 
 - cryptographic functions 
 - secure architectures 
 - IP (intellectual property) 
 - Machine learning models 
### Sources: 
https://www.mdpi.com/2079-9292/4/4/763 
https://ieeexplore.ieee.org/abstract/document/9310331 
# Hardware Security Goals 
### Secure hardware design has two main Goals: 
- Maintain required performance safely 
- Protect against seasoned attackers who may interfer with the system 

# Integrated Circuits (ICs) and Supply Chain Risks 
- Modern ICs include CPUs, memory, and third-party IP cores. 

-  Due to worldwide manufacturing, they are more vulnerable to attacks. 

### IC Lifecycle Risks 
#### Design stage   
-Relies on trusted CAD tools 
#### Fabrication stage  
- High risk of Trojan insertion 
#### Manufacturing stage  
- Trust depends on testing environment 
### Sources: 
https://ieeexplore.ieee.org/abstract/document/10159361 


# Hardware Trojans 

- A malicious addition to an IC designed to compromise security or leak data. 

#### Where can Hardware Trojans exist? 

- ASICs 
- Microcontrollers 
- 3rd party components 
- Which are usually hidden and triggered under specific conditions 
### Sources: 

https://ieeexplore.ieee.org/abstract/document/5406669 

# Side-Channel Attacks 
### EM side-channels
- Unintentional electromagnetic are for general embedded systems purposes that have been studied to be data recovery and monitoring tools for hardware security. 

- EM side channels have been demonstrated on embedded cryptosystems and microprocessors but there is not much work covering the effectiveness in surveilling wireless communication between connected devices (blue tooth).  

### Timing side-channels
 - Timing side channels can show information about hidden code locations in memory.
- Even little timing differences can help attackers bypass defenses such as Address Space Layout Randomization (ASLR).

- Timing side channels can identify functions, gadgets, and even system call locations inside randomized code.

- Fine grained ASLR gave the strongest defense but was still vulnerable to side-channel leakage.

- Timing attacks remained possible over noisy network environments.

### Sources: 
https://dl.acm.org/doi/10.1145/3649476.3658742 
https://dl.acm.org/doi/abs/10.1145/2660267.2660309


# "FPGA oriented moving target defense against threats from malicious FPGA tools"

### FPGA security 4 main aspects
- secure operations implemented by FPGA devices
- Utilization of FPGAs for system security enhancement
- Secure bitstream delivery to FPGA devices 
- Exploitation of FPGA devices as a attack surface of FPGA based systems 

there is Limited work covering security threats from malicious FPGA design software

At end of introduction in the research paper they explain how they test this. 

### source
https://ieeexplore-ieee-org.ezproxy.lib.ucalgary.ca/document/8383907 

# Hardware noise vs Software noise
 ### Hardware Noise
 - noise created by the PCB and peripherals. (capacitors, resistors, power regulators)
 - Electromagnetic interference from close components on the board
 - Temperature changes affecting resistance and the signal behavior


### Software Noise
- system-level interferences such as other processes, interrupts, and system calls
- Can be reduced with disabling interrupts during the measurement and fixing clock speed


### source
https://arxiv.org/pdf/2410.11563

# categories of hardware security
- Physical security (the hardware itself) 
- Software attacks on hardware 
- Classic hardware attacks (trojans) 
- Cryptographic hardware  

# CPA Side-Channel Attacks - steps
### 1) collect the power traces
- run AES device multiple times
- for each encryption you must record the plaintext and the power consumption over time
- each trace contains thoousands of sample points
### 2) guess a key byte
### 3) compute the s-box output
- for every plaintext
### 4) compute hyp power
- most CPA attacks assume the device will leak Hamming weight 
- the hamming weight will be hypothetical power consumption
### 5) now compare with the real power traces
- use correlation

### 6) repeat this for every key guess and every time sample
- if the graph is wrong you get 0 or near 0.
- if correctthen a spike occurs when a s-box computation happens
### 7) pick best key
- this is the largest correlation peak

# DPA Side-Channel attack - steps
### 1)  