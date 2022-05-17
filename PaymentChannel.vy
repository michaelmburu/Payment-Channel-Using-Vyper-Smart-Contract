# @version ^0.2.0

sender: public(address)
receiver: public(address)

#expire payment channel
DURATION: constant(uint256) = 7 * 24 * 60* 60
expiresAt: public(uint256)

#init
@external
@payable
def __init__(_receiver: address):
    assert _receiver != ZERO_ADDRESS, "Receiver equals zero address"
    self.sender = msg.sender
    self.receiver = _receiver
    self.expiresAt = block.timestamp + DURATION

@internal
@pure
def _getHash(_amount: uint256) -> bytes32:
    #N/B this is prone to signature replay attack
    return keccak256(concat(
        convert(self, bytes32),
        convert(_amount, bytes32)
    )) 

@external
@view
def getHash(_amount: uint256) -> bytes32:
    return self._getHash(_amount)

#compute actual hash that was signed
@internal
@view
def _getEthSignedHash(_amount: uint256) -> bytes32:
    hash: bytes32 = self._getHash(_amount)
    return keccak256(
        concat (
            b'\x19 Ethreum Signed Message: \n32',
            hash
        )
    )

@external
@view
def getEthSignedHash(_amount: uint256) -> bytes32:
    return self._getEthSignedHash(_amount)

@internal
@view
def _verify(_amount: uint256, _sig: Bytes[65]) -> bool:
    ethSignedHash: bytes32 = self._getEthSignedHash(_amount)
    
    r: uint256 = convert(slice(_sig, 0, 32), uint256)
    s: uint256 = convert(slice(_sig, 32, 32), uint256)
    v: uint256 = convert(slice(_sig, 64, 1), uint256)

    return ecrecover(ethSignedHash, v, r, s) == self.sender

@external
@view
def verify(_amount: uint256, _sig: Bytes[65]) -> bool:
    return self._verify(_amount, _sig)

# Receiever to finalize payment
# Submit payment & signature
# Send ETH to receiver
# Delete contract
@nonreentrant("lock")
@external
def close(_amount: uint256, _sig: Bytes[65]):
    assert msg.sender == self.receiver, "not receiver"
    assert self._verify(_amount, _sig), "invalid signature"

    raw_call(self.receiver, b'\x00', value=_amount)
    selfdestruct(self.sender)

#Force close payment channels
@external
def cancel():
    assert msg.sender == self.sender, "not sender"
    assert block.timestamp >= self.expiresAt, "not expired"
    selfdestruct(sel.sender)