# DDoS Detection in SDN

Software Defined Networking (SDN) emerged out as an alternative of the traditional network now a days. SDN provides a centralized control of the network. The controller is also a single point of failure in the SDN environment. This project focusses on detecting Distributed Denial of Service (DDoS), identifying the source of the attack and mitigating the attack in the SDN. 

#### Requirements
 - Floodlight controller (https://floodlight.atlassian.net/wiki/display/floodlightcontroller/Installation+Guide)
 - Mininet (For creating network with OpenVSwitch) (http://mininet.org/download/)
 - Hping3 (Tool for creating packet in Linux)
 - Eclipse (IDE for Java) (optional)

#### Description 
The project works with Floodlight acting in 'hub' mode i.e. all the packets are transmitted from the switch to the controller.
The module consists of two classes :
 - **CDM** (Collection,Detection and Mitigation) class for collecting data and running the detection algorithm every 15 sec and finally running the mitigation process if any attack is detected.
 - **Server** class for storing the server IP and the host associated with the server.

##### Collecting data
When any packet arrives at the controller, source and destination IP address are extracted from the packet.If any of the IP address belongs to the server under consideration, then the packet is further processed otherwise it is left.
Then after that information about the TCP flag is extracted from the packet and is updated to the appropriate host associated with server. 

##### Detection Algorithm
A thread is created which runs in every 15 seconds and collect the count of SYN , SYN-ACK and FIN flag of TCP for every host and server pair and calculate the entropy using the following formula:
![equation](http://mathurl.com/render.cgi?-%5Csum_%7Bi%3D1%7D%5E%7Bn%7D%20P_i%20*%20log_2%20P_i%5Cnocache)
where P is the probability of the element i.e. the number of occurences divided by total.
 In the TCP case, the ﬂags SYN, SYN-ACK, and FIN have the same probability of appearing. An attack would decrease entropy. If the entropy is below a fixed value , then an attack is declared and mitigation procedure is started.
##### Mitigation Process
Mitigation is performed using the Static Entry Pusher of the floodlight. The server-host pair for which the attack is detected will be blocked.All the traffic from that host IP to that server IP is dropped at the switch. After 2 minutes that flow rule is deleted from the switch if it is not already removed by IDLE_TIMEOUT.

### How to Run
 - Deactivate the forwarding mode and activate the Hub mode in the floodlight controller.This can be done by editing the **floodlightdefault.properties** file located in *src/resources*. In this file remove the line *net.floodlightcontroller.forwarding.Forwarding* and add the line *net.floodlightcontroller.hub.Hub* 
 - Add a new package in the floodlight and copy the two classes in the same package.
 - Register the module by adding the line *net.floodlightcontroller.<yourpackagename>.CDM* in the **floodlightdefault.properties** file located in *src/resources* and also in *net.floodlightcontroller.core.module.IFloodlightModule* located in src/resources/META-INF/services.
 - Now run the controller and create topology using mininet and detect the attack.

#### References
 - L. V. Morales, A. F. Murillo and S. J. Rueda, "Extending the Floodlight Controller," Network Computing and Applications (NCA), 2015 IEEE 14th International Symposium on, Cambridge, MA, 2015, pp. 126-133.
doi: 10.1109/NCA.2015.11 (http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=7371714&isnumber=7371684)
 - Floodlight Tutorials (https://floodlight.atlassian.net/wiki/display/floodlightcontroller/How+to+Write+a+Module)
 - Mininet Tutorial (http://mininet.org/walkthrough/)

#### Future Work
 - Work with the forwarding mode
 - Adaptive Threshold Determination





```

 
