# **no-services** <img src="https://cdn-icons-png.flaticon.com/512/5229/5229377.png" height="45" width="45"></div>
## About
**no-services** by DalekIRC is a set of software(s) for [UnrealIRCd](https://unrealircd.org/) which provides services-related functionality without having to rely on messaging a bot user.

The main software comes in two parts, the ***UnrealIRCd module*** and the web-hosted [***no-services URL API endpoint***](https://github.com/DalekIRC/no-services-api/) which the module talks to. This is the repository for the ***UnrealIRCd module***.

## Motivation
IRC (Internet Relay Chat) services form the backbone of online communities, facilitating communication, collaboration, and the management of channels and user accounts. However, the current state of IRC services often faces challenges during network splits (netsplits), disrupting crucial functionalities and impeding seamless communication. Integrating IRC services functions directly into the IRC server, allowing them to communicate with URL API endpoints for managing account and channel settings, presents a compelling solution that addresses these shortcomings and offers a myriad of benefits.

Presently, IRC services typically operate as separate entities, independent of the IRC server infrastructure. When netsplits occur, these services lose connectivity and become unable to manage accounts or channels effectively. This disconnection leads to a lack of synchronization across servers, causing inconsistencies in user access, permissions, and channel management. Such disruptions degrade the user experience and hinder effective community management.

By embedding services functionalities within the IRC server itself, connected servers can maintain access to account and channel management capabilities even during netsplits. This integration ensures continuous service availability, enabling users to manage their accounts and channels seamlessly, regardless of network disruptions. The direct communication between the IRC server and the URL API endpoint for managing settings establishes a resilient and robust infrastructure that persists through network partitions.

Furthermore, consolidating services within the IRC server architecture enhances efficiency and reduces latency. Eliminating the need for external service connections streamlines the communication process, leading to quicker responses and smoother interactions for users. The centralized management of account and channel settings simplifies administration for network operators, promoting a more streamlined and cohesive user experience.

Additionally, integrating IRC services functionality into the server infrastructure enhances security and reliability. With a unified system, security protocols and access controls can be implemented more comprehensively, fortifying the network against vulnerabilities and unauthorized access. Moreover, the consolidated structure reduces dependency on external services, mitigating potential points of failure and ensuring a more reliable platform for users.

In conclusion, the integration of IRC services functions directly within the IRC server, communicating with URL API endpoints for managing account and channel settings, presents a transformative solution to the current limitations of IRC services. By enabling uninterrupted account and channel management during netsplits, streamlining operations, improving reliability, and enhancing security, this approach heralds a new era of stability and efficiency for online communities built upon the IRC framework.

## Commands
Below is a list of commands which have been implemented so far and any plans regarding the future.

### REGISTER
Following the Account Registration IRCv3 specification, you can register an account with the following syntax:
```
/REGISTER <account name> <email address> <password>
```
Example:
```
/REGISTER Valware valerie@valware.co.uk FantasticPasswordWhichDefinitelyNobodyWillEverGuessLmao
```
### LOGIN
This logs you into your account based on what nick you are using. Currently authing as an account other than your nick is unsupported. This command will eventually be expanded to allow specifying an account and password, and SASL will be added to be interoperable with existing clients. The syntax is as follows:
```
/LOGIN <password>
```
Example:
```
/LOGIN FantasticPasswordWhichDefinitelyNobodyWillEverGuessLmao
```

### CREGISTER
This will let you register a channel, which sets mode the 'registered mode (`+r`)' on the channel and 'owner status (`+q`)' on you and the syntax is as follows:
```
/CREGISTER <channel name>
```
Example:
```
/CREGISTER #mychannel
```

## The Plan
The plan is to implement as many existing account/channel-related commands into the server, and also many more new things; from `/AJOIN` to manage your auto-join channels list to `/VOTEBAN', a command channel staff can enable or disable for their channel.

At the time of writing this, the no-services project is very early on, and I'm only a few days into coding it enthusiastically.

If this has inspired any ideas in your mind (you, the reader), please open an issue in the github repository and I'll be more than happy to consider it.
