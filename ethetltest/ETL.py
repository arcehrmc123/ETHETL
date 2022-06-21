from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
from ethereumetl.service.eth_contract_service import EthContractService
from ethereumetl.service.token_transfer_extractor import EthTokenTransferExtractor
from hexbytes.main import HexBytes
import time
import logging
import os
import requests
from neo4j import GraphDatabase
from neo4j.io import ClientError
from threading import Thread

# eth_address = {}
# eth_block = {}
# eth_tx = {}
# eth_token_tx = {}
#
# def parse_block(BlockNumber):
#     block=



logger = logging.getLogger(__name__)

class EthereumETL:
    contract_service = EthContractService()
    token_transfer_service = EthTokenTransferExtractor()

    eth_address={}
    eth_block={}
    eth_exterbal_tx={}
    eth_token_tx={}
    eth_uncle_block={}
    unit_ex=10**18


    def __init__(self, config):
        self.config = config
        rpc_config = config["daemon"]
        neo4j_config = config["neo4j"]

        # Websocket is not supported under multi thread
        # https://github.com/ethereum/web3.py/issues/2090
        # w3 = Web3(Web3.WebsocketProvider('ws://127.0.0.1:8546'))
        # w3 = Web3(Web3.WebsocketProvider(
        #     'wss://mainnet.infura.io/ws/v3/dc6980e1063b421bbcfef8d7f58ccd43'))
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=2**16, pool_maxsize=2**16)
        session = requests.Session()
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        self.w3 = Web3(Web3.HTTPProvider(rpc_config["address"],
                                         session=session, request_kwargs={'timeout': 20}))
        logger.warning('using web3@'+self.w3.api)

        self.driver = GraphDatabase.driver(
            neo4j_config["address"], auth=(neo4j_config["username"], neo4j_config["password"]))

        self.dbname = neo4j_config.get("database", "eth")

        self.ensure_db_exists()

    def drop_db(self):
        system = self.driver.session()
        system.run(f"DROP DATABASE {self.dbname}")

    def create_db(self):
        system = self.driver.session()
        system.run(f"CREATE DATABASE {self.dbname}")
        system.close()

        with self.driver.session(database=self.dbname) as session:
            session.run(
                "CREATE CONSTRAINT block_hash_uq ON (block:Block) ASSERT block.hash IS UNIQUE")
            session.run(
                "CREATE CONSTRAINT block_number_uq ON (block:Block) ASSERT block.number IS UNIQUE")
            session.run(
                "CREATE CONSTRAINT addr_uq ON (addr:Address) ASSERT addr.address IS UNIQUE")


    def ensure_db_exists(self):
        with self.driver.session(database=self.dbname) as session:
            try:
                session.run("create (placeholder:Block {height: -1})")
                session.run(
                    "MATCH  (placeholder:Block {height: -1}) delete placeholder")
            except ClientError as e:
                if e.code == 'Neo.ClientError.Database.DatabaseNotFound':
                    self.create_db()
                else:
                    raise e

    def parse_Token_Transaction(self, t,transaction_receipt_log):
        for log in transaction_receipt_log:
            transfer = self.token_transfer_service.extract_transfer_from_log(
                log)
            if transfer is not None:
                self.eth_token_tx['block_number'] = transfer.block_number
                if type(self.eth_token_tx['block_number']) is str and self.eth_token_tx['block_number'].startswith(
                        '0x'):
                    self.eth_token_tx['block_number'] = int(
                        self.eth_token_tx['block_number'][2:], 16)
                else:
                    self.eth_token_tx['block_number'] = int(self.eth_token_tx['block_number'])
                self.eth_token_tx['token_address'] = transfer.token_address if type(
                    transfer.token_address) is not HexBytes else transfer.token_address.hex()
                self.eth_token_tx['transaction_hash'] = transfer.transaction_hash if type(
                    transfer.transaction_hash) is not HexBytes else transfer.transaction_hash.hex()
                self.eth_token_tx['value'] = transfer.value/self.unit_ex
                self.eth_token_tx['from_address'] = transfer.from_address
                self.eth_token_tx['to_address'] = transfer.to_address
                #insert address
                self.insert_EOA(t, self.eth_token_tx['from_address'])  # token transfer must be an EOA
                self.insert_EOA(t, self.eth_token_tx['to_address'])  # token transfer must be an EOA

                t.run("""
                MATCH 
                    (from:Address {address: $from_address}),
                    (to:Address {address: $to_address})
                MERGE (from)-[tx:TOKEN_TX {block_number:$block_number,token_address:$token_address,transaction_hash:$transaction_hash,value:$value}]->(to)
                """, {'from_address': self.eth_token_tx['from_address'], 'to_address': self.eth_token_tx['to_address'],
                      'block_number': self.eth_token_tx['block_number'],
                      'token_address':self.eth_token_tx['token_address'],
                      'transaction_hash': self.eth_token_tx['transaction_hash'],
                      'value': self.eth_token_tx['value']})

                # print(self.eth_token_tx)



    def parse_Transaction(self,t,transaction):
        external_tx=self.w3.eth.get_transaction(transaction)
        # print("**************transaction***********", external_tx)
        self.eth_exterbal_tx['block_number']=external_tx.blockNumber
        self.eth_exterbal_tx['from'] = external_tx['from']
        self.eth_exterbal_tx['to'] = external_tx['to']
        self.eth_exterbal_tx['block_number'] = external_tx.blockNumber
        if type(self.eth_exterbal_tx['block_number']) is str and self.eth_exterbal_tx['block_number'].startswith(
                '0x'):
            self.eth_exterbal_tx['block_number'] = int(
                self.eth_exterbal_tx['block_number'][2:], 16)
        else:
            self.eth_exterbal_tx['block_number'] = int( self.eth_exterbal_tx['block_number'])
        self.eth_exterbal_tx['transaction_hash']=external_tx.hash if type(external_tx.hash) is not HexBytes else external_tx.hash.hex()
        self.eth_exterbal_tx['value']=external_tx.value/self.unit_ex
        self.eth_exterbal_tx['gas'] = external_tx.gas
        self.eth_exterbal_tx['gas_price'] = external_tx.gasPrice/self.unit_ex
        receipt=self.w3.eth.get_transaction_receipt(self.eth_exterbal_tx['transaction_hash'])
        self.parse_Token_Transaction(t,receipt.logs)
        self.eth_exterbal_tx['receipt_gas_used'] = receipt.gasUsed
        if receipt.contractAddress is None:
            self.eth_exterbal_tx['receipt_contract_address'] =''
        else:
            self.eth_exterbal_tx['receipt_contract_address'] = receipt.contractAddress
        self.eth_exterbal_tx['tx_fee'] = self.eth_exterbal_tx['receipt_gas_used']*self.eth_exterbal_tx['gas_price']

        if self.eth_exterbal_tx['to']  != None:
            self.insert_Address(t, self.eth_exterbal_tx['to'])  # to is unknown
            self.insert_EOA(t, self.eth_exterbal_tx['from'])  # from must be an EOA
            # insert relationships
            t.run("""
            MATCH
                (from:Address {address: $from}),
                (to:Address {address: $to})
            MERGE (from)-[tx:EXTER_TX {block_number:$block_number,transaction_hash:$transaction_hash,value:$value,gas:$gas,gas_price:$gas_price,receipt_gas_used: $receipt_gas_used,receipt_contract_address:$receipt_contract_address}]->(to)
            """, {'from': self.eth_exterbal_tx['from'], 'to': self.eth_exterbal_tx['to'],'block_number':self.eth_exterbal_tx['block_number'],
                  'transaction_hash':self.eth_exterbal_tx['transaction_hash'],'value':self.eth_exterbal_tx['value'],'gas':self.eth_exterbal_tx['gas'],
                  'gas_price':self.eth_exterbal_tx['gas_price'],'receipt_gas_used':self.eth_exterbal_tx['receipt_gas_used'] ,'receipt_contract_address':self.eth_exterbal_tx['receipt_contract_address']})
        else:
            self.insert_EOA(t, self.eth_exterbal_tx['from'])
            new_contract_address =  self.get_new_contract_address(self.eth_exterbal_tx['transaction_hash'])
            assert type(new_contract_address) == str and len(
                new_contract_address) > 0
            self.insert_Contract(t, new_contract_address,self.eth_exterbal_tx['block_number'])
            logger.info('tx {} created a new contract {}'.format(
                self.eth_exterbal_tx['transaction_hash'], new_contract_address))

            t.run("""
            MATCH
                (from:Address {address: $from}),
                (to:Address {address: $to})
            MERGE (from)-[tx:EXTER_TX {block_number:$block_number,transaction_hash:$transaction_hash,value:$value,gas:$gas,gas_price:$gas_price,receipt_gas_used:$receipt_gas_used,receipt_contract_address:$receipt_contract_address}]->(to)
            """, {'from': self.eth_exterbal_tx['from'], 'to': self.eth_exterbal_tx['to'],'block_number':self.eth_exterbal_tx['block_number'],
                  'transaction_hash':self.eth_exterbal_tx['transaction_hash'],'value':self.eth_exterbal_tx['value'],'gas':self.eth_exterbal_tx['gas'],
                  'gas_price':self.eth_exterbal_tx['gas_price'],'receipt_gas_used':self.eth_exterbal_tx['receipt_gas_used'] ,'receipt_contract_address':self.eth_exterbal_tx['receipt_contract_address']})


        # print(self.eth_exterbal_tx)

    def parse_uncle_block(self,t,BlockNumber, index):
        uncle_block = self.w3.eth.get_uncle_by_block(BlockNumber, index)
        # print("**************uncle_block***********", uncle_block)
        self.eth_uncle_block['block_number'] = BlockNumber
        self.eth_uncle_block['uncle_block_number'] = uncle_block.number
        if type(self.eth_uncle_block['uncle_block_number']) is str and self.eth_uncle_block['uncle_block_number'].startswith(
                '0x'):
            self.eth_uncle_block['uncle_block_number'] = int(
                self.eth_uncle_block['uncle_block_number'][2:], 16)
        self.eth_uncle_block['uncle_block_miner'] = uncle_block.miner if type(uncle_block.miner) is not HexBytes else uncle_block.miner.hex()
        self.eth_uncle_block['uncle_block_reward_value'] = (self.eth_uncle_block['uncle_block_number']+8-BlockNumber)*5/8
        self.insert_EOA(t, self.eth_uncle_block['uncle_block_miner'])

        t.run("""
        MATCH (uncle_miner:Address {address: $uncle_miner}),
            (uncle_block_re:Block {block_number: $uncle_block_number})
        CREATE (uncle_miner)-[reward_uncle_block:Reward{value:$value,reward_type:$reward_type}]->(uncle_block_re)
        """, {'uncle_miner': self.eth_uncle_block['uncle_block_miner'],
              'uncle_block_number': self.eth_uncle_block['block_number'], 'value': self.eth_uncle_block['uncle_block_reward_value'],'reward_type':1})

    def parse_block(self,t,BlockNumber):
        block = self.w3.eth.getBlock(BlockNumber)
        # print("**************block***********",block)
        self.eth_block['block_number'] = block.number
        self.eth_block['block_timestamp'] = block.timestamp
        self.eth_block['block_hash'] = block.hash if type(block.hash) is not HexBytes else block.hash.hex()
        self.eth_block['size'] = block.size
        self.eth_block['gaslimit'] = block.gasLimit
        self.eth_block['gas_uesed'] = block.gasUsed
        self.eth_block['transaction'] = [i if type(i) is not HexBytes else i.hex() for i in block.transactions]
        self.eth_block['transaction_count'] =len(self.eth_block['transaction'])
        self.eth_block['uncles'] = [i if type(i) is not HexBytes else i.hex() for i in block.uncles]
        self.eth_block['miner'] = block.miner if type(block.miner) is not HexBytes else block.miner.hex()
        self.eth_block['miner_reward_value'] = 5+len(self.eth_block['uncles'])*5/32

        self.insert_EOA(t,self.eth_block['miner'])
        self.insert_Block(t,self.eth_block)


        if len(self.eth_block['uncles'])>0:
            for uncle_block_index in range(0, len(self.eth_block['uncles'])):
                self.parse_uncle_block(t,self.eth_block['block_number'], uncle_block_index)

        if len(self.eth_block['transaction']) > 0:
            for tx_hash in self.eth_block['transaction']:
                self.parse_Transaction(t,tx_hash)
                self.eth_block['miner_reward_value']=self.eth_block['miner_reward_value']+self.eth_exterbal_tx['tx_fee']
        t.run("""
        MATCH (miner:Address {address: $miner}),
            (block_re:Block {block_number: $block_number})
        CREATE (miner)-[reward_block:Reward{value:$value,reward_type:$reward_type}]->(block_re)
        """, {'miner': self.eth_block['miner'],
              'block_number': self.eth_block['block_number'], 'value': self.eth_block['miner_reward_value'],'reward_type':0})

    def get_new_contract_address(self, transaction_hash):
        receipt = self.w3.eth.getTransactionReceipt(transaction_hash)
        return receipt.contractAddress  # 0xabcd in str

    def is_ERC20(self, function_sighashes):
        # contains bug here
        # https://github.com/blockchain-etl/ethereum-etl/issues/194
        # https://github.com/blockchain-etl/ethereum-etl/issues/195
        return self.contract_service.is_erc20_contract(function_sighashes)

    def is_ERC721(self, function_sighashes):
        return self.contract_service.is_erc721_contract(function_sighashes)

    def insert_Contract(self, tx, addr,BlockNumber):
        if type(addr) is HexBytes:
            addr = addr.hex()
        query = """
        MERGE (a:Address {address: $address})
        set a:CONTRACT,a.function_sighashes = $function_sighashes, a.is_erc20=$is_erc20, a.is_erc721=$is_erc721 , a.block_number=$block_number
        """
        bytecode = self.w3.eth.getCode(Web3.toChecksumAddress(addr))
        bytecode = bytecode if type(
            bytecode) is not HexBytes else bytecode.hex()
        function_sighashes_con = self.contract_service.get_function_sighashes(
            bytecode)

        tx.run(query, address=addr,function_sighashes=function_sighashes_con,is_erc20=self.is_ERC20(
            function_sighashes_con), is_erc721=self.is_ERC721(function_sighashes_con),block_number=BlockNumber)

    def insert_EOA(self, t, addr):
        if type(addr) is HexBytes:
            addr = addr.hex()
        t.run("""
        MERGE (a:Address {address: $address})
        set a:EOA
        """, address=addr)

    def insert_Address(self, t, addr):
        if type(addr) is HexBytes:
            addr = addr.hex()
        query = "MERGE (a:Address {address: $address})"
        t.run(query, address=addr)

    def insert_Block(self, t, block_dic):
        t.run("""
        MERGE (b:Block {block_number: $block_number, block_timestamp:$block_timestamp,size:$size,gas_limit:$gaslimit,gas_uesed:$gas_uesed,transaction_count:$transaction_count})
        """, block_number=block_dic['block_number'],block_timestamp=block_dic['block_timestamp'],
              size=block_dic['size'],gaslimit=block_dic['gaslimit'],
              gas_uesed=block_dic['gas_uesed'],transaction_count=block_dic['transaction_count'])

    def block_exists(self, t, height):
        results = t.run(
            "MATCH (b:Block {block_number: $height}) RETURN b.block_number;", height=height).value()
        if type(results) is not list:
            logger.error(
                f"failed to inspect Block on {height}: results are {results}")
            os._exit(0)
        if len(results) != 1 or results[0] is None:
            return False
        return True

    def get_local_block_height(self):
        with self.driver.session(database=self.dbname) as session:
            results = session.run(
                "MATCH (b:Block) RETURN max(b.block_number);").value()
            if results[0] is None:
                return -1
            else:
                return results[0]

    def get_local_block_timestamp(self):
        with self.driver.session(database=self.dbname) as session:
            results = session.run(
                "MATCH (b:Block) with max(b.block_number) as top match (b:Block) where b.block_number = top return b.timestamp;").value()
            if results[0] is None:
                return -1
            else:
                return results[0]

    def thread_task(self, height, latest):
        with self.driver.session(database=self.dbname) as session:
            retry = 0
            while True:
                try:
                    block = self.w3.eth.get_block(height, full_transactions=True)
                    break
                except Exception as e:
                    logger.error("failed to fetch block on syncing")
                    logger.error(e)
                    if retry == 3:
                        os._exit(0)
                retry += 1

            retry = 0
            while True:
                try:
                    logger.warning('processing block(with {} txs) {} -> {}'.format(
                        len(block.transactions), block.number, latest
                    ))
                    session.write_transaction(self.parse_block, height)
                    break
                except Exception as e:
                    logger.error("failed to parse block on syncing")
                    logger.error(e)
                    if retry == 3:
                        os._exit(0)
                retry += 1
    def check_task(self, height):
        with self.driver.session(database=self.dbname) as session:
            if session.read_transaction(self.block_exists, height):
                # logger.warning(f'Block {height} exists')
                pass
            else:
                logger.warning(f'Missing block {height}')
                while True:
                    retry = 0
                    try:
                        session.write_transaction(self.parse_block, height)
                        logger.warning(f"supplemented block {height}")
                        return
                    except Exception as e:
                        logger.error(f'parsing {height} failed')
                        logger.error(e)
                        if retry == 3:
                            os._exit(0)
                    time.sleep(2)
                    retry += 1

    def check_missing(self, local_height, co=1, safe_height=1000):
        logger.warning(
            f'check missing blocks from {safe_height} to {local_height}')

        height = safe_height
        while height < local_height:
            next_height = height + co
            if next_height > local_height:
                next_height = local_height
            tasks = [Thread(target=self.check_task, args=(i,))
                     for i in range(height, next_height)]
            for t in tasks:
                t.start()
            for t in tasks:
                t.join()
            height = next_height

    def work_flow(self):
        latest = self.w3.eth.get_block(
            'latest', full_transactions=False).number
        local_height = self.get_local_block_height()
        co = self.config["checker"].get("thread", 1000)
        # co=None
        # if self.config.get("checker") is not None and local_height > 0:
        #     co = self.config["checker"].get("thread", 1000)

        logger.warning(f'running on check missing mode, thread {co}')
        safe_height = self.config["checker"].get("safe-height")
        if safe_height is None or safe_height < 0:
            safe_height = local_height - 1000 if local_height > 1000 else 0

        if co is not None:
            self.check_missing(local_height, co=co,
                               safe_height=safe_height)
        else:
            self.check_missing(local_height, safe_height=safe_height)

        if self.config.get("syncer") is not None and local_height < latest - 1000:
            co = self.config["syncer"].get("thread", 100)
            logger.warning(f'running on slow sync mode, thread {co}.')
            logger.warning('suggest export csv and manually import in neo4j')

            # while local_height < latest - 1000:
                # self.thread_task(local_height ,latest)
                # local_height=local_height+1

            while local_height < latest - 1000:
                tasks = [Thread(target=self.thread_task, args=(
                    local_height + i + 1, latest)) for i in range(co)]

                # start all
                for t in tasks:
                    t.start()
                for t in tasks:
                    t.join()
                local_height += co

            logger.warning("entering daily sync mode")
            while True:
                latest = self.w3.eth.get_block(
                    'latest', full_transactions=False).number
                local_timestamp = self.get_local_block_timestamp()
                print(latest)
                print(local_timestamp)
                while True:
                    local_height += 1
                    block = self.w3.eth.getBlock(
                        local_height, full_transactions=True)
                    if block.timestamp - local_timestamp < 60 * 60 * 24:
                        break
                    logger.warning('processing block(with {} txs) {} -> {}'.format(
                        len(block.transactions), local_height, latest
                    ))
                    with self.driver.session(database=self.dbname) as session:
                        session.write_transaction(self.parse_block, local_height)

                time.sleep(60 * 60 * 24)  # sleep one day


    def test(self):
        with self.driver.session(database=self.dbname) as session:
            session.write_transaction(self.parse_block, 4222300)



