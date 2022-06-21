import pandas as pd
from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
from ethereumetl.service.eth_contract_service import EthContractService
from ethereumetl.service.token_transfer_extractor import EthTokenTransferExtractor
from hexbytes.main import HexBytes
import eth_abi
from eth_abi import decode_abi

contract_service = EthContractService()
token_transfer_service = EthTokenTransferExtractor()

# w3 = Web3(WebsocketProvider('ws://127.0.0.1:18546'))

w3=Web3(WebsocketProvider('wss://mainnet.infura.io/ws/v3/786588cde85944e68ae070d5bd14febd'))
a=w3.eth.contract()
print(10**3)
# print(w3.eth.getBlock('latest'))
# print(w3.eth.is_async)
# a=w3.eth.getBlock(4222300)['hash']
# print(a if type(a) is not HexBytes else a.hex())
# print(w3.eth.get_uncle_by_block(4222300,1))
# print(w3.eth.getBlock(4222300))
# print(Web3.toChecksumAddress('0xCb67d2E1fBFACf5dae02B128C6336A1b07B3AeC9'))

eth_block={}

eth_address = {}
eth_block = {}
eth_uncle_block = {}
eth_tx = {}
eth_token_tx = {}
print(eth_block)
#
# print(w3.eth.get_uncle_by_block(4222300,0))
def parse_uncle_block(BlockNumber, index):
    uncle_block = w3.eth.get_uncle_by_block(BlockNumber, index)
    eth_uncle_block['block_number'] = BlockNumber
    eth_uncle_block['uncle_block_number'] = uncle_block.number
    if type(eth_uncle_block['uncle_block_number']) is str and eth_uncle_block[
        'uncle_block_number'].startswith(
            '0x'):
        eth_uncle_block['uncle_block_number'] = int(
            eth_uncle_block['uncle_block_number'][2:], 16)
    eth_uncle_block['uncle_block_miner'] = uncle_block.miner if type(
        uncle_block.miner) is not HexBytes else uncle_block.miner.hex()
    eth_uncle_block['uncle_block_reward_value'] = (eth_uncle_block[
                                                            'uncle_block_number'] + 8 - BlockNumber) * 5 / 8


# def parse_external_transaction(tx_hash):
#     external_tx=w3.eth.getTransaction(tx_hash)
#     eth_tx['bloc']


def parse_block( BlockNumber):
    block = w3.eth.getBlock(BlockNumber)
    print(block)
    eth_block['block_number'] = block.number
    eth_block['block_timestamp'] = block.timestamp
    eth_block['block_hash'] = block.hash if type(block.hash) is not HexBytes else block.hash.hex()
    eth_block['size'] = block.size
    eth_block['gaslimit'] = block.gasLimit
    eth_block['gas_uesed'] = block.gasUsed
    eth_block['transaction'] = [i if type(i) is not HexBytes else i.hex() for i in block.transactions]
    eth_block['transaction_count'] = len(eth_block['transaction'])
    eth_block['uncles'] = [i if type(i) is not HexBytes else i.hex() for i in block.uncles]
    eth_block['miner'] = block.miner if type(block.miner) is not HexBytes else block.miner.hex()
    eth_block['miner_reward_value'] = 5 + len(eth_block['uncles']) * 5 / 32

    if len(eth_block['uncles'])>0:
        for i in range(0,len(eth_block['uncles'])):
            parse_uncle_block(BlockNumber,i)

for x in range(0,6000):
    print(x)
    parse_block(x)

# parse_block(3552)
#
# parse_block(4222300)
# print(eth_block)

# bytecode = w3.eth.getCode(Web3.toChecksumAddress('0xA15C7Ebe1f07CaF6bFF097D8a589fb8AC49Ae5B3'))
# bytecode = bytecode if type(
#     bytecode) is not HexBytes else bytecode.hex()
# print(bytecode)
#
# function_sighashes = contract_service.get_function_sighashes(
#     bytecode)
# print(function_sighashes)
# print(contract_service.is_erc20_contract(function_sighashes))
# print(contract_service.is_erc721_contract(function_sighashes))



# a=w3.eth.getTransaction('0x82936f51301869ad4d1182edd29fa34cb21b2af26ba76c7d4bf89c22b46818c7')
# print(a.blockHash)
# print(a)

# print(w3.eth.getTransaction('0x82936f51301869ad4d1182edd29fa34cb21b2af26ba76c7d4bf89c22b46818c7'))
# print(w3.eth.getTransactionReceipt('0x2f99cfc4ffb31592c808bdfbf75232307c3f67e7732dc90f7696924e5226845b'))
# # print(w3.myContract.getPastEvents())
#
# logs = w3.eth.getTransactionReceipt('0x26784c355b769af7690a74e198c0f56598a5cd2e196e5c183f51d3eec2a28e9f').logs
# for log in logs:
#     transfer = token_transfer_service.extract_transfer_from_log(
#         log)
#     print(transfer.from_address,transfer.to_address,transfer.value,transfer.token_address,transfer.transaction_hash,transfer.value_raw,transfer.block_number)


# logs = w3.eth.getTransactionReceipt('0x26784c355b769af7690a74e198c0f56598a5cd2e196e5c183f51d3eec2a28e9f').logs
# for log in logs:
#     transfer = token_transfer_service.extract_transfer_from_log(
#         log)
#     print(transfer.from_address)
#     print(transfer.value)