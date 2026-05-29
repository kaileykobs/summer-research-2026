# Summer Research 2026
## What is Hardware Security  

- Hardware security focuses on protecting physical computing components such as integrated circuits (ICs), processors, and embedded systems from attackers and tampering. 

- we heavily relie on 3rd party resources which can create security risks. This weakens assumptions that attackers cannot access the isolated IC supply chain. For example, 3rd partie resources may insert hardware trojans into chips  
- hardware secuirty is basically that we want to make it harder for attackers to hurt our hardware 
#### What do these attackers target? 
 - cryptographic functions 
 - secure architectures 
 - IP (intellectual property) 
 - machine learning models 
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
-relies on trusted CAD tools 
#### Fabrication stage  
- high risk of Trojan insertion 
#### Manufacturing stage  
- trust depends on testing environment 
### Sources: 
https://ieeexplore.ieee.org/abstract/document/10159361 


# Hardware Trojans 

- a malicious addition to an IC designed to compromise security or leak data. 

#### Where can Hardware Trojans exist? 

- ASICs 
- microcontrollers 
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

- timing side channels can identify functions, gadgets, and even system call locations inside randomized code.

- Fine grained ASLR gave the strongest defense but was still vulnerable to side-channel leakage.

- Timing attacks remained possible over noisy network environments.

### Sources: 
https://dl.acm.org/doi/10.1145/3649476.3658742 
https://dl.acm.org/doi/abs/10.1145/2660267.2660309


# "FPGA oriented moving target defense against threats from malicious FPGA tools"

### FPGA security 4 main aspects
- secure operations implemented by FPGA devices
- utilization of FPGAs for system security enhancement
- secure bitstream delivery to FPGA devices 
- exploitation of FPGA devices as a attack surface of FPGA based systems 

there is Limited work covering security threats from malicious FPGA design software

At end of introduction in the research paper they explain how they test this. 

### source
https://ieeexplore-ieee-org.ezproxy.lib.ucalgary.ca/document/8383907 

# categories of hardware security
- Physical security (the hardware itself) 
- Software attacks on hardware 
- Classic hardware attacks (trojans) 
- Cryptographic hardware  
