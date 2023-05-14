import os

import solcx
from eth_hash.backends.pycryptodome import keccak256
from solcx import set_solc_version, compile_source
from web3 import Web3
from werkzeug.utils import secure_filename


class FileContract:
    def __init__(self):
        self.__contract_code = None
        self.__compiled_contract = None
        self.__interface = None
        self.__bin = None
        self.__abi = None
        self.__compile_contract()

    def __compile_contract(self):
        solcx.install_solc('0.8.0')
        set_solc_version("0.8.0")

        with open("contracts/FileUpload.sol", "r") as contract_file:
            self.__contract_code = contract_file.read()
            self.__compiled_contract = compile_source(self.__contract_code)
            self.__interface = self.__compiled_contract['<stdin>:FileUpload']
            self.__bin = self.__interface['bin']
            self.__abi = self.__interface['abi']

    def upload_file_via_shredding(self, uploaded_file, w3, record, upload_folder):
        filename = secure_filename(uploaded_file.filename)
        # ADDING BLOCKCHAIN TRANSACTION AND SQLITE DATABASE RECORD FOR FILE UPLOAD
        receipt = self.__create_block_transaction(uploaded_file=uploaded_file, filename=filename, w3=w3, record=record,
                                                  upload_folder=upload_folder)

        with open(os.path.join(upload_folder, filename), "rb") as file:
            file_bytes = file.read()
        chunk_size = 4096  # in bytes
        file_upload_contract_2 = w3.eth.contract(address=receipt['contractAddress'],
                                                 abi=self.__abi)
        details = file_upload_contract_2.functions.uploadFileViaShredding(file_bytes, chunk_size).call()
        return details

    def upload_file_simple(self, uploaded_file, w3, record, upload_folder):
        filename = secure_filename(uploaded_file.filename)
        receipt = self.__create_block_transaction(uploaded_file=uploaded_file, w3=w3, record=record,
                                                  upload_folder=upload_folder, filename=filename)

        with open(os.path.join(upload_folder, filename), "rb") as file:
            # Read the file as bytes
            file_bytes = file.read()
            file_upload_contract_2 = w3.eth.contract(address=receipt['contractAddress'],
                                                     abi=self.__abi)
            details = file_upload_contract_2.functions.uploadFileSimple(file_bytes).call()
            return details

    def __create_block_transaction(self, uploaded_file, filename, w3, record, upload_folder):
        uploaded_file.save(os.path.join(upload_folder, filename))
        file_upload_gas_estimate = w3.eth.estimateGas({'data': self.__bin})
        deploy_file_upload_tx = {
            'from': record[4],
            'data': self.__bin,
            'gas': file_upload_gas_estimate,
            'gasPrice': w3.toWei('1', 'gwei'),
            'nonce': w3.eth.getTransactionCount(record[4])
        }
        file_upload_signed_tx = w3.eth.account.signTransaction(deploy_file_upload_tx, private_key=record[3])
        file_upload_tx_hash = w3.eth.sendRawTransaction(file_upload_signed_tx.rawTransaction)
        file_upload_tx_receipt = w3.eth.waitForTransactionReceipt(file_upload_tx_hash)
        return file_upload_tx_receipt

    def check_file(self, w3, record, file_address, file_owner, upload_folder):
        contract = w3.eth.contract(address=file_address, abi=self.__abi)
        with open(os.path.join(upload_folder, record[1]), "rb") as file:
            file_bytes = file.read()
        file_hash = keccak256(file_bytes).hex()

        stored_hash = contract.functions.getHash().call({'from': file_owner})
        return file_hash != stored_hash
